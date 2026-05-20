# Get rich function signature with parameters, locals, pointer info, and xrefs
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript get_function_signature.py <function_name_or_address>

import json
import sys

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

script_args = getScriptArgs()
if len(script_args) < 1:
    print(json.dumps({"error": "Usage: get_function_signature.py <function_name_or_address>"}))
    sys.exit(1)

target = script_args[0]
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
    from ghidra.program.model.data import Pointer

    decompiler = DecompInterface()
    # GB-1: Configure decompiler options for consistent output
    options = DecompileOptions()
    options.grabFromProgram(program)
    decompiler.setOptions(options)
    decompiler.openProgram(program)
    decompiler.setSimplificationStyle("decompile")
    decomp_monitor = ConsoleTaskMonitor()

    result = decompiler.decompileFunction(function, 30, decomp_monitor)

    parameters = []
    local_variables = []
    pointer_param_indices = []

    if result.decompileCompleted():
        high_func = result.getHighFunction()
        if high_func is not None:
            local_symbol_map = high_func.getLocalSymbolMap()
            for symbol in local_symbol_map.getSymbols():
                name = str(symbol.getName())
                data_type = str(symbol.getDataType())
                storage = str(symbol.getStorage())
                is_param = symbol.isParameter()

                if is_param:
                    idx = symbol.getCategoryIndex()
                    is_pointer = isinstance(symbol.getDataType(), Pointer)
                    parameters.append({
                        "index": idx,
                        "name": name,
                        "type": data_type,
                        "storage": storage
                    })
                    if is_pointer:
                        pointer_param_indices.append(idx)
                else:
                    local_variables.append({
                        "name": name,
                        "type": data_type,
                        "storage": storage
                    })

    # Sort parameters by index
    parameters.sort(key=lambda p: p["index"])

    # Get return type
    return_type = str(function.getReturnType())

    # Get calling convention
    calling_convention = str(function.getCallingConventionName())

    # Get signature string
    signature = str(function.getSignature())

    # Get callers
    ref_manager = program.getReferenceManager()
    entry_point = function.getEntryPoint()
    callers = []
    seen_callers = set()
    for ref in ref_manager.getReferencesTo(entry_point):
        from_addr = ref.getFromAddress()
        caller_func = function_manager.getFunctionContaining(from_addr)
        if caller_func is not None:
            caller_name = str(caller_func.getName())
            if caller_name not in seen_callers:
                seen_callers.add(caller_name)
                callers.append(caller_name)

    # Get callees
    callees = []
    for called in function.getCalledFunctions(monitor):
        callees.append(str(called.getName()))

    output = {
        "function": str(function.getName()),
        "address": str(entry_point),
        "calling_convention": calling_convention,
        "signature": signature,
        "parameters": parameters,
        "local_variables": local_variables,
        "return_type": return_type,
        "pointer_parameters": pointer_param_indices,
        "xref_callers": callers,
        "xref_callees": callees
    }
    print(json.dumps(output, indent=2))

    decompiler.dispose()

except Exception as e:
    print(json.dumps({"error": str(e)}))
