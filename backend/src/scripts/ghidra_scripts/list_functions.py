# List functions script
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript list_functions.py <offset> <limit>

import json
import sys

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

# Get offset and limit from args
script_args = getScriptArgs()
offset = int(script_args[0]) if len(script_args) > 0 else 0
limit = int(script_args[1]) if len(script_args) > 1 else 100

function_manager = program.getFunctionManager()
functions = []

for idx, func in enumerate(function_manager.getFunctions(True)):
    if idx < offset:
        continue
    if len(functions) >= limit:
        break

    functions.append({
        "name": str(func.getName()),
        "address": str(func.getEntryPoint()),
        "size": func.getBody().getNumAddresses(),
        "signature": str(func.getSignature()),
        "is_thunk": func.isThunk(),
        "calling_convention": str(func.getCallingConventionName())
    })

result = {
    "total": function_manager.getFunctionCount(),
    "offset": offset,
    "limit": limit,
    "functions": functions
}

print(json.dumps(result, indent=2))
