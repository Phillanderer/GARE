# Rename script for functions and data
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript rename.py <type> <old_or_address> <new_name>
# Types: function, function_by_address, data

import json
import sys
from ghidra.program.model.symbol import SourceType

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

script_args = getScriptArgs()
if len(script_args) < 3:
    print(json.dumps({"error": "Usage: rename.py <type> <old_or_address> <new_name>"}))
    sys.exit(1)

rename_type = script_args[0]
target = script_args[1]
new_name = script_args[2]

function_manager = program.getFunctionManager()
success = False

try:
    if rename_type == "function":
        # Find function by name
        for func in function_manager.getFunctions(True):
            if str(func.getName()) == target:
                func.setName(new_name, SourceType.USER_DEFINED)
                success = True
                print(json.dumps({"success": True, "message": f"Renamed {target} to {new_name}"}))
                break

        if not success:
            print(json.dumps({"error": f"Function not found: {target}"}))

    elif rename_type == "function_by_address":
        # Find function by address
        addr = program.getAddressFactory().getAddress(target)
        func = function_manager.getFunctionAt(addr)
        if func:
            func.setName(new_name, SourceType.USER_DEFINED)
            print(json.dumps({"success": True, "message": f"Renamed function at {target} to {new_name}"}))
        else:
            print(json.dumps({"error": f"No function at address: {target}"}))

    elif rename_type == "data":
        # Rename data at address
        addr = program.getAddressFactory().getAddress(target)
        symbol_table = program.getSymbolTable()

        # Remove existing symbol if any
        symbols = symbol_table.getSymbols(addr)
        for symbol in symbols:
            if not symbol.isExternal():
                symbol_table.removeSymbolSpecial(symbol)

        # Create new symbol
        symbol_table.createLabel(addr, new_name, SourceType.USER_DEFINED)
        print(json.dumps({"success": True, "message": f"Renamed data at {target} to {new_name}"}))

    else:
        print(json.dumps({"error": f"Unknown rename type: {rename_type}"}))

except Exception as e:
    print(json.dumps({"error": str(e)}))
