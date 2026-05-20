# List namespaces
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript list_namespaces.py <offset> <limit>

import json
import sys

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

script_args = getScriptArgs()
offset = int(script_args[0]) if len(script_args) > 0 else 0
limit = int(script_args[1]) if len(script_args) > 1 else 100

symbol_table = program.getSymbolTable()
namespaces = []

idx = 0
for namespace in symbol_table.getNamespaceIterator():
    if idx >= offset + limit:
        break

    # Skip global namespace
    if not namespace.isGlobal():
        if idx >= offset:
            namespaces.append({
                "name": str(namespace.getName(True)),
                "type": str(namespace.getSymbol().getSymbolType())
            })
        idx += 1

result = {
    "namespaces": namespaces,
    "offset": offset,
    "limit": limit,
    "count": len(namespaces)
}

print(json.dumps(result, indent=2))
