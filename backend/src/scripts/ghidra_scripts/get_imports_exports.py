# Get imports and exports
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript get_imports_exports.py <type> <offset> <limit>
# Types: imports, exports

import json
import sys

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

script_args = getScriptArgs()
if len(script_args) < 1:
    print(json.dumps({"error": "Type required: imports or exports"}))
    sys.exit(1)

query_type = script_args[0]
offset = int(script_args[1]) if len(script_args) > 1 else 0
limit = int(script_args[2]) if len(script_args) > 2 else 100

symbol_table = program.getSymbolTable()
result_list = []

if query_type == "imports":
    # Get external symbols (imports)
    idx = 0
    for symbol in symbol_table.getExternalSymbols():
        if idx >= offset + limit:
            break
        if idx >= offset:
            result_list.append({
                "name": str(symbol.getName()),
                "address": str(symbol.getAddress()),
                "namespace": str(symbol.getParentNamespace().getName(True))
            })
        idx += 1

    result = {"imports": result_list, "offset": offset, "limit": limit, "count": len(result_list)}

elif query_type == "exports":
    # Get global symbols (exports)
    idx = 0
    for symbol in symbol_table.getPrimarySymbolIterator():
        if idx >= offset + limit:
            break
        if not symbol.isExternal() and symbol.isGlobal():
            if idx >= offset:
                result_list.append({
                    "name": str(symbol.getName()),
                    "address": str(symbol.getAddress()),
                    "type": str(symbol.getSymbolType())
                })
            idx += 1

    result = {"exports": result_list, "offset": offset, "limit": limit, "count": len(result_list)}

else:
    result = {"error": f"Unknown type: {query_type}"}

print(json.dumps(result, indent=2))
