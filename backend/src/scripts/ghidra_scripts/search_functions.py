# Search functions by name substring
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript search_functions.py <query> <offset> <limit>

import json
import sys

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

script_args = getScriptArgs()
if len(script_args) < 1:
    print(json.dumps({"error": "Query string required"}))
    sys.exit(1)

query = script_args[0].lower()
offset = int(script_args[1]) if len(script_args) > 1 else 0
limit = int(script_args[2]) if len(script_args) > 2 else 100

function_manager = program.getFunctionManager()
functions = []
idx = 0

for func in function_manager.getFunctions(True):
    func_name = str(func.getName()).lower()

    if query in func_name:
        if idx >= offset + limit:
            break
        if idx >= offset:
            functions.append({
                "name": str(func.getName()),
                "address": str(func.getEntryPoint()),
                "signature": str(func.getSignature())
            })
        idx += 1

result = {
    "functions": functions,
    "offset": offset,
    "limit": limit,
    "count": len(functions)
}

print(json.dumps(result, indent=2))
