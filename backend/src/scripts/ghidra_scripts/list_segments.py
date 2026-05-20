# List memory segments
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript list_segments.py <offset> <limit>

import json
import sys

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

script_args = getScriptArgs()
offset = int(script_args[0]) if len(script_args) > 0 else 0
limit = int(script_args[1]) if len(script_args) > 1 else 100

memory = program.getMemory()
segments = []

idx = 0
for block in memory.getBlocks():
    if idx >= offset + limit:
        break
    if idx >= offset:
        segments.append({
            "name": str(block.getName()),
            "start": str(block.getStart()),
            "end": str(block.getEnd()),
            "size": block.getSize(),
            "read": block.isRead(),
            "write": block.isWrite(),
            "execute": block.isExecute(),
            "initialized": block.isInitialized()
        })
    idx += 1

result = {
    "segments": segments,
    "offset": offset,
    "limit": limit,
    "total": memory.getBlocks().length
}

print(json.dumps(result, indent=2))
