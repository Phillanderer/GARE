# Variable slicing for data flow analysis (GB-3)
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript get_variable_slice.py <function_name> <variable_name> <direction>
# Book Reference: Ch. 19 (The Ghidra Decompiler, pp. 670-691)
#   - Forward slice: all statements affected by a variable
#   - Backward slice: all statements that affect a variable
#   - Uses decompiler's HighFunction and p-code Def-Use chains

import json
import sys

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

script_args = getScriptArgs()
if len(script_args) < 3:
    print(json.dumps({"error": "Usage: get_variable_slice.py <function_name_or_address> <variable_name> <forward|backward>"}))
    sys.exit(1)

target = script_args[0]
var_name = script_args[1]
direction = script_args[2]  # "forward" or "backward"

if direction not in ("forward", "backward"):
    print(json.dumps({"error": "Direction must be 'forward' or 'backward'"}))
    sys.exit(1)

function_manager = program.getFunctionManager()

# Find function by name or address
function = None
try:
    addr = program.getAddressFactory().getAddress(target)
    function = function_manager.getFunctionAt(addr)
except:
    pass

if function is None:
    for func in function_manager.getFunctions(True):
        if str(func.getName()) == target:
            function = func
            break

if function is None:
    print(json.dumps({"error": "Function not found: " + target}))
    sys.exit(1)

try:
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.model.pcode import PcodeOp

    decompiler = DecompInterface()
    options = DecompileOptions()
    options.grabFromProgram(program)
    decompiler.setOptions(options)
    decompiler.openProgram(program)
    decompiler.setSimplificationStyle("decompile")
    decomp_monitor = ConsoleTaskMonitor()

    result = decompiler.decompileFunction(function, 30, decomp_monitor)

    slice_results = []
    target_varnode = None

    if result.decompileCompleted():
        high_func = result.getHighFunction()
        if high_func is not None:
            # Find the target variable in the symbol map
            local_symbol_map = high_func.getLocalSymbolMap()
            target_symbol = None
            for symbol in local_symbol_map.getSymbols():
                if str(symbol.getName()) == var_name:
                    target_symbol = symbol
                    break

            if target_symbol is None:
                print(json.dumps({"error": "Variable not found: " + var_name,
                                  "available_variables": [str(s.getName()) for s in local_symbol_map.getSymbols()]}))
                decompiler.dispose()
                sys.exit(0)

            # Get the high variable for this symbol
            high_var = target_symbol.getHighVariable()

            if high_var is None:
                print(json.dumps({"error": "No high variable for: " + var_name}))
                decompiler.dispose()
                sys.exit(0)

            # Collect all varnodes representing this variable
            var_instances = high_var.getInstances()
            visited_ops = set()

            def get_op_info(op):
                """Extract info from a p-code operation"""
                if op is None:
                    return None
                op_addr = op.getSeqnum().getTarget()
                mnemonic = str(op.getMnemonic())
                return {
                    "address": str(op_addr),
                    "opcode": mnemonic,
                    "seq": op.getSeqnum().getOrder()
                }

            def forward_slice(varnode, depth=0):
                """Trace forward: what operations USE this varnode's value"""
                if depth > 20:  # Prevent infinite recursion
                    return
                desc_iter = varnode.getDescendants()
                while desc_iter.hasNext():
                    op = desc_iter.next()
                    op_key = (str(op.getSeqnum().getTarget()), op.getSeqnum().getOrder())
                    if op_key in visited_ops:
                        continue
                    visited_ops.add(op_key)

                    info = get_op_info(op)
                    if info:
                        # Get output variable name if available
                        output = op.getOutput()
                        if output and output.getHigh():
                            info["output_var"] = str(output.getHigh().getName())
                        info["depth"] = depth
                        slice_results.append(info)

                        # Continue tracing through the output
                        if output:
                            forward_slice(output, depth + 1)

            def backward_slice(varnode, depth=0):
                """Trace backward: what operations DEFINE this varnode's value"""
                if depth > 20:
                    return
                def_op = varnode.getDef()
                if def_op is None:
                    return
                op_key = (str(def_op.getSeqnum().getTarget()), def_op.getSeqnum().getOrder())
                if op_key in visited_ops:
                    return
                visited_ops.add(op_key)

                info = get_op_info(def_op)
                if info:
                    info["depth"] = depth
                    # Get input variable names
                    input_vars = []
                    for inp in def_op.getInputs():
                        if inp.getHigh():
                            input_vars.append(str(inp.getHigh().getName()))
                    if input_vars:
                        info["input_vars"] = input_vars
                    slice_results.append(info)

                    # Continue tracing through each input
                    for inp in def_op.getInputs():
                        if inp.getHigh() and not inp.isConstant():
                            backward_slice(inp, depth + 1)

            # Execute the slice in the requested direction
            for varnode in var_instances:
                if direction == "forward":
                    forward_slice(varnode)
                else:
                    backward_slice(varnode)

    # Sort by address for readability
    slice_results.sort(key=lambda x: (x.get("address", ""), x.get("seq", 0)))

    # Deduplicate by address+seq
    seen = set()
    unique_results = []
    for r in slice_results:
        key = (r.get("address"), r.get("seq"))
        if key not in seen:
            seen.add(key)
            unique_results.append(r)

    output = {
        "function": str(function.getName()),
        "variable": var_name,
        "direction": direction,
        "is_parameter": target_symbol.isParameter() if target_symbol else False,
        "variable_type": str(target_symbol.getDataType()) if target_symbol else "unknown",
        "slice_size": len(unique_results),
        "slice": unique_results
    }
    print(json.dumps(output, indent=2))

    decompiler.dispose()

except Exception as e:
    print(json.dumps({"error": str(e)}))
