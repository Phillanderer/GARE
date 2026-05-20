# Set repeatable comment at an address (GB-13)
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript set_repeatable_comment.py <address> <comment>
# Book Reference: Ch. 7 (Disassembly Manipulation, pp. 131-132)
#   - Repeatable comments propagate to all cross-reference sources
#   - A comment at a function entry echoes at every call site
#   - Ideal for documenting API behavior, security-critical functions, arch patterns

import json
import sys

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

script_args = getScriptArgs()
if len(script_args) < 2:
    print(json.dumps({"error": "Usage: set_repeatable_comment.py <address_or_function_name> <comment_text>"}))
    sys.exit(1)

target = script_args[0]
comment_text = script_args[1]

# Allow additional args to be part of comment (in case comment has spaces that survived sanitization)
if len(script_args) > 2:
    comment_text = " ".join(script_args[1:])

try:
    from ghidra.program.model.listing import CodeUnit

    listing = program.getListing()
    function_manager = program.getFunctionManager()

    # Resolve target to address — try as address first, then as function name
    addr = None
    resolved_via = None

    try:
        addr = program.getAddressFactory().getAddress(target)
        resolved_via = "address"
    except:
        pass

    if addr is None:
        # Try as function name
        for func in function_manager.getFunctions(True):
            if str(func.getName()) == target:
                addr = func.getEntryPoint()
                resolved_via = "function_name"
                break

    if addr is None:
        print(json.dumps({"error": "Could not resolve target: " + target}))
        sys.exit(1)

    # Get the code unit at the address
    code_unit = listing.getCodeUnitAt(addr)
    if code_unit is None:
        print(json.dumps({"error": "No code unit at address: " + str(addr)}))
        sys.exit(1)

    # Get previous comment if any
    previous_comment = code_unit.getComment(CodeUnit.REPEATABLE_COMMENT)

    # Set the repeatable comment
    tx_id = program.startTransaction("Set repeatable comment")
    try:
        code_unit.setComment(CodeUnit.REPEATABLE_COMMENT, comment_text)
        program.endTransaction(tx_id, True)
    except Exception as e:
        program.endTransaction(tx_id, False)
        raise e

    # Count how many references will see this comment
    ref_manager = program.getReferenceManager()
    xref_count = 0
    refs = ref_manager.getReferencesTo(addr)
    for ref in refs:
        xref_count += 1

    result = {
        "success": True,
        "address": str(addr),
        "resolved_via": resolved_via,
        "comment": comment_text,
        "previous_comment": previous_comment,
        "comment_type": "REPEATABLE",
        "xref_propagation_count": xref_count,
        "note": "This comment will appear at all " + str(xref_count) + " cross-reference source locations"
    }

    # If it's a function entry, include function name
    func_at = function_manager.getFunctionAt(addr)
    if func_at:
        result["function"] = str(func_at.getName())

    print(json.dumps(result, indent=2))

except Exception as e:
    print(json.dumps({"error": str(e)}))
