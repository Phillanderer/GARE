# List available data types in the program
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript list_data_types.py [filter] [offset] [limit]

import json
import sys

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

script_args = getScriptArgs()
type_filter = script_args[0] if len(script_args) > 0 else ""
offset = int(script_args[1]) if len(script_args) > 1 else 0
limit = int(script_args[2]) if len(script_args) > 2 else 100

try:
    dtm = program.getDataTypeManager()
    all_types = []
    idx = 0

    # Iterate all data types
    for dt in dtm.getAllDataTypes():
        name = str(dt.getName())
        path = str(dt.getCategoryPath())
        length = dt.getLength()
        dt_class = dt.__class__.__name__

        # Apply filter if specified
        if type_filter and type_filter.lower() not in name.lower():
            continue

        if idx >= offset + limit:
            break

        if idx >= offset:
            entry = {
                "name": name,
                "category": path,
                "size": length,
                "kind": dt_class
            }
            all_types.append(entry)

        idx += 1

    result = {
        "data_types": all_types,
        "count": len(all_types),
        "offset": offset,
        "limit": limit,
        "filter": type_filter or None
    }
    print(json.dumps(result, indent=2))

except Exception as e:
    print(json.dumps({"error": str(e)}))
