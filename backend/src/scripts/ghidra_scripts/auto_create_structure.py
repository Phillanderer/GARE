# Auto-create structure from pointer offset patterns (GB-2)
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript auto_create_structure.py <function_name_or_address>
# Book Reference: Ch. 19 (The Ghidra Decompiler, pp. 437-441)
#   - Detects pointer arithmetic patterns in decompiled output
#   - Auto-creates structure definitions from offset usage
#   - Applies created structure to improve decompiler readability

import json
import sys

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

script_args = getScriptArgs()
if len(script_args) < 1:
    print(json.dumps({"error": "Usage: auto_create_structure.py <function_name_or_address>"}))
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
    from ghidra.program.model.data import Pointer, StructureDataType, CategoryPath

    decompiler = DecompInterface()
    options = DecompileOptions()
    options.grabFromProgram(program)
    decompiler.setOptions(options)
    decompiler.openProgram(program)
    decompiler.setSimplificationStyle("decompile")
    decomp_monitor = ConsoleTaskMonitor()

    result = decompiler.decompileFunction(function, 30, decomp_monitor)

    structures_created = []
    offset_patterns = {}  # param_name -> list of offsets used

    if result.decompileCompleted():
        high_func = result.getHighFunction()
        if high_func is not None:
            local_symbol_map = high_func.getLocalSymbolMap()

            # Scan parameters for pointer types that access offsets
            for symbol in local_symbol_map.getSymbols():
                if symbol.isParameter():
                    data_type = symbol.getDataType()
                    if isinstance(data_type, Pointer):
                        param_name = str(symbol.getName())
                        param_idx = symbol.getCategoryIndex()
                        pointed_type = data_type.getDataType()
                        pointed_type_name = str(pointed_type.getName()) if pointed_type else "undefined"

                        # If the pointed-to type is undefined/generic, it's a candidate
                        # for structure creation
                        if pointed_type_name in ("undefined", "undefined1", "undefined2",
                                                  "undefined4", "undefined8", "void",
                                                  "byte", "int", "long"):
                            offset_patterns[param_name] = {
                                "param_index": param_idx,
                                "base_type": pointed_type_name,
                                "storage": str(symbol.getStorage())
                            }

            # Analyze the high p-code to find offset access patterns
            # Walk through all p-code ops in the function
            func_proto = high_func.getFunctionPrototype()
            if func_proto is not None:
                num_params = func_proto.getNumParams()
            else:
                num_params = 0

            # Collect offset information from variable references
            # Look at all high-level variables for structure access patterns
            varnodes = []
            pcode_iter = high_func.getPcodeOps()
            offsets_by_param = {}  # param_name -> set of (offset, size)

            while pcode_iter.hasNext():
                op = pcode_iter.next()
                opcode = op.getOpcode()

                # PTRSUB and PTRADD operations indicate structure/array access
                # Opcode 18 = PTRSUB (structure field access)
                # Opcode 19 = PTRADD (array element access)
                from ghidra.program.model.pcode import PcodeOp
                if opcode == PcodeOp.PTRSUB or opcode == PcodeOp.PTRADD:
                    inputs = op.getInputs()
                    if len(inputs) >= 2:
                        base = inputs[0]
                        offset_node = inputs[1]

                        # Check if base is a parameter we're tracking
                        base_high = base.getHigh()
                        if base_high is not None:
                            base_name = str(base_high.getName())
                            if base_name in offset_patterns:
                                # Get the offset value
                                if offset_node.isConstant():
                                    offset_val = offset_node.getOffset()
                                    # Get the size of the access
                                    output = op.getOutput()
                                    access_size = output.getSize() if output else 4

                                    if base_name not in offsets_by_param:
                                        offsets_by_param[base_name] = set()
                                    offsets_by_param[base_name].add((int(offset_val), int(access_size)))

            # Create structures for parameters with detected offsets
            dtm = program.getDataTypeManager()

            for param_name, offsets in offsets_by_param.items():
                if not offsets:
                    continue

                sorted_offsets = sorted(offsets, key=lambda x: x[0])
                max_offset = max(o[0] + o[1] for o in sorted_offsets)

                # Create a structure large enough to hold all accessed fields
                struct_name = "struct_%s_%s" % (str(function.getName()), param_name)
                struct_size = max(max_offset, 4)  # Minimum 4 bytes

                # Check if structure already exists
                existing = dtm.getDataType("/" + struct_name)
                if existing is not None:
                    structures_created.append({
                        "name": struct_name,
                        "status": "already_exists",
                        "fields": len(sorted_offsets)
                    })
                    continue

                # Create new structure
                from ghidra.program.model.data import StructureDataType, CategoryPath
                struct = StructureDataType(CategoryPath("/"), struct_name, struct_size)

                fields_added = 0
                for offset_val, access_size in sorted_offsets:
                    field_name = "field_0x%x" % offset_val
                    try:
                        # Map size to appropriate base type
                        if access_size == 1:
                            field_type = dtm.getDataType("/byte")
                        elif access_size == 2:
                            field_type = dtm.getDataType("/short")
                        elif access_size == 4:
                            field_type = dtm.getDataType("/int")
                        elif access_size == 8:
                            field_type = dtm.getDataType("/long")
                        else:
                            field_type = dtm.getDataType("/undefined" + str(access_size))

                        if field_type is not None and offset_val < struct_size:
                            struct.replaceAtOffset(int(offset_val), field_type, access_size, field_name, "")
                            fields_added += 1
                    except:
                        pass

                if fields_added > 0:
                    # Add to data type manager
                    txn = program.startTransaction("Add auto-created structure")
                    try:
                        dtm.addDataType(struct, None)
                        program.endTransaction(txn, True)
                        structures_created.append({
                            "name": struct_name,
                            "status": "created",
                            "size": struct_size,
                            "fields": fields_added,
                            "offsets": [{"offset": "0x%x" % o, "size": s} for o, s in sorted_offsets]
                        })
                    except Exception as e:
                        program.endTransaction(txn, False)
                        structures_created.append({
                            "name": struct_name,
                            "status": "error",
                            "error": str(e)
                        })

    output = {
        "function": str(function.getName()),
        "address": str(function.getEntryPoint()),
        "pointer_parameters_analyzed": len(offset_patterns),
        "structures_created": structures_created,
        "parameter_details": offset_patterns
    }
    print(json.dumps(output, indent=2))

    decompiler.dispose()

except Exception as e:
    print(json.dumps({"error": str(e)}))
