# Apply a data type to a function parameter or return type
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript apply_data_type.py <function_address> <param_index> <type_name>
# param_index: 0-based parameter index, or "return" for return type

import json
import sys

from ghidra.program.model.symbol import SourceType

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

script_args = getScriptArgs()
if len(script_args) < 3:
    print(json.dumps({"error": "Usage: apply_data_type.py <function_address> <param_index_or_return> <type_name>"}))
    sys.exit(1)

func_address = script_args[0]
param_target = script_args[1]  # integer index or "return"
type_name = script_args[2]

try:
    # Find the function
    addr = program.getAddressFactory().getAddress(func_address)
    func_manager = program.getFunctionManager()
    func = func_manager.getFunctionAt(addr)

    if func is None:
        print(json.dumps({"error": f"No function at address: {func_address}"}))
        sys.exit(1)

    # Find the data type by name
    dtm = program.getDataTypeManager()
    matched_type = None
    for dt in dtm.getAllDataTypes():
        if str(dt.getName()) == type_name:
            matched_type = dt
            break

    if matched_type is None:
        print(json.dumps({"error": f"Data type not found: {type_name}"}))
        sys.exit(1)

    if param_target == "return":
        # Apply to return type
        func.setReturnType(matched_type, SourceType.USER_DEFINED)
        print(json.dumps({
            "success": True,
            "function": str(func.getName()),
            "target": "return_type",
            "applied_type": type_name
        }))
    else:
        # Apply to parameter by index
        param_idx = int(param_target)
        params = func.getParameters()
        if param_idx < 0 or param_idx >= len(params):
            print(json.dumps({"error": f"Parameter index {param_idx} out of range (function has {len(params)} params)"}))
            sys.exit(1)

        param = params[param_idx]
        param.setDataType(matched_type, SourceType.USER_DEFINED)
        print(json.dumps({
            "success": True,
            "function": str(func.getName()),
            "target": f"param[{param_idx}] ({str(param.getName())})",
            "applied_type": type_name
        }))

except Exception as e:
    print(json.dumps({"error": str(e)}))
