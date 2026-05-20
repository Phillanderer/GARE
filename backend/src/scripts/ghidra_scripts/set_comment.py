# Set a comment at a specific address
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript set_comment.py <address> <base64_comment>

import json
import sys
import base64

from ghidra.program.model.listing import CodeUnit

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

script_args = getScriptArgs()
if len(script_args) < 2:
    print(json.dumps({"error": "Usage: set_comment.py <address> <base64_comment>"}))
    sys.exit(1)

address_str = script_args[0]
b64_comment = script_args[1]

try:
    # Decode URL-safe base64 comment (padding may have been stripped)
    padded = b64_comment + "=" * (-len(b64_comment) % 4)
    comment = base64.urlsafe_b64decode(padded).decode("utf-8")

    # Resolve address
    addr = program.getAddressFactory().getAddress(address_str)
    if addr is None:
        print(json.dumps({"error": f"Invalid address: {address_str}"}))
        sys.exit(1)

    # Set PLATE comment (visible in decompiler view)
    listing = program.getListing()
    listing.setComment(addr, CodeUnit.PLATE_COMMENT, comment)

    print(json.dumps({
        "success": True,
        "address": str(addr),
        "comment": comment
    }))

except Exception as e:
    print(json.dumps({"error": str(e)}))
