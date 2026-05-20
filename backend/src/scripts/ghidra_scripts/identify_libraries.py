# Identify library functions using Ghidra's analysis metadata
# Returns functions tagged as library/thunk vs user-defined code
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript identify_libraries.py [offset] [limit]

import json
import sys

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

script_args = getScriptArgs()
offset = int(script_args[0]) if len(script_args) > 0 else 0
limit = int(script_args[1]) if len(script_args) > 1 else 200

function_manager = program.getFunctionManager()

library_funcs = []
thunk_funcs = []
user_funcs = []
idx = 0

try:
    for func in function_manager.getFunctions(True):
        if idx >= offset + limit:
            break

        if idx >= offset:
            name = str(func.getName())
            address = str(func.getEntryPoint())
            is_thunk = func.isThunk()
            is_external = func.isExternal()
            is_library = func.isLibrary() if hasattr(func, 'isLibrary') else False

            # Heuristic: functions in external namespace or marked as thunks
            # are library code the agent can skip
            source_type = str(func.getSymbol().getSource()) if func.getSymbol() else "UNKNOWN"

            entry = {
                "name": name,
                "address": address,
                "source": source_type
            }

            if is_thunk or is_external:
                entry["type"] = "thunk" if is_thunk else "external"
                thunk_funcs.append(entry)
            elif source_type in ("IMPORTED", "ANALYSIS") and (
                name.startswith("_") or name.startswith("__") or
                "::" in name or name.startswith("std::")
            ):
                entry["type"] = "library"
                library_funcs.append(entry)
            else:
                entry["type"] = "user"
                user_funcs.append(entry)

        idx += 1

    result = {
        "library_functions": library_funcs,
        "thunk_functions": thunk_funcs,
        "user_functions": user_funcs,
        "counts": {
            "library": len(library_funcs),
            "thunk": len(thunk_funcs),
            "user": len(user_funcs),
            "total": len(library_funcs) + len(thunk_funcs) + len(user_funcs)
        },
        "recommendation": "Focus analysis on 'user' functions. Library and thunk functions are known code."
    }
    print(json.dumps(result, indent=2))

except Exception as e:
    print(json.dumps({"error": str(e)}))
