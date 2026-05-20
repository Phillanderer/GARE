# Get strings from binary
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript get_strings.py <offset> <limit> [filter]

import json
import sys

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

script_args = getScriptArgs()
offset = int(script_args[0]) if len(script_args) > 0 else 0
limit = int(script_args[1]) if len(script_args) > 1 else 2000
filter_str = script_args[2] if len(script_args) > 2 else None

listing = program.getListing()
memory = program.getMemory()
strings = []

# Get defined strings from listing
data_iterator = listing.getDefinedData(True)
idx = 0

for data in data_iterator:
    if idx >= offset + limit:
        break

    if data.hasStringValue():
        string_value = str(data.getValue())

        # Apply filter if provided
        if filter_str and filter_str not in string_value:
            continue

        if idx >= offset:
            strings.append({
                "address": str(data.getAddress()),
                "value": string_value,
                "length": len(string_value)
            })

        idx += 1

result = {
    "offset": offset,
    "limit": limit,
    "count": len(strings),
    "strings": strings
}

print(json.dumps(result, indent=2))
