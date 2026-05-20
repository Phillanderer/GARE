# Get cross-references with R/W/Pointer classification (GB-8)
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript get_xrefs.py <type> <target> <offset> <limit>
# Types: to, from, function
# Book Reference: Ch. 9 (Cross-References, pp. 183-196)
#   - Read (R): data location contents are read
#   - Write (W): data location is written to
#   - Pointer (*): address of location is taken (e.g., LEA, string reference)

import json
import sys

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

script_args = getScriptArgs()
if len(script_args) < 2:
    print(json.dumps({"error": "Type and target required"}))
    sys.exit(1)

xref_type = script_args[0]
target = script_args[1]
offset = int(script_args[2]) if len(script_args) > 2 else 0
limit = int(script_args[3]) if len(script_args) > 3 else 100


def classify_ref(ref):
    """Classify a reference as Read/Write/Pointer/Code per Ch. 9 taxonomy"""
    ref_type = ref.getReferenceType()
    ref_type_str = str(ref_type)

    # Check data access classification
    if ref_type.isRead() and ref_type.isWrite():
        return "RW"
    elif ref_type.isRead():
        return "R"
    elif ref_type.isWrite():
        return "W"
    elif ref_type.isData():
        # Data reference that isn't explicitly read/write = pointer (address-of)
        return "*"
    elif ref_type.isFlow():
        # Code flow references (calls, jumps)
        if ref_type.isCall():
            return "CALL"
        elif ref_type.isJump():
            return "JUMP"
        else:
            return "FLOW"
    elif ref_type.isIndirect():
        return "INDIRECT"
    else:
        return ref_type_str


def get_containing_function(addr):
    """Get the name of the function containing an address"""
    func = program.getFunctionManager().getFunctionContaining(addr)
    if func:
        return str(func.getName())
    return None


def build_xref_entry(ref):
    """Build a detailed xref entry with classification and function context"""
    from_addr = ref.getFromAddress()
    to_addr = ref.getToAddress()

    entry = {
        "from": str(from_addr),
        "to": str(to_addr),
        "type": str(ref.getReferenceType()),
        "classification": classify_ref(ref)
    }

    # Add function context
    from_func = get_containing_function(from_addr)
    if from_func:
        entry["from_function"] = from_func

    to_func = get_containing_function(to_addr)
    if to_func:
        entry["to_function"] = to_func

    return entry


xrefs = []
ref_manager = program.getReferenceManager()

try:
    if xref_type == "to":
        # Get references TO an address
        addr = program.getAddressFactory().getAddress(target)
        refs = ref_manager.getReferencesTo(addr)

        idx = 0
        for ref in refs:
            if idx >= offset + limit:
                break
            if idx >= offset:
                xrefs.append(build_xref_entry(ref))
            idx += 1

    elif xref_type == "from":
        # Get references FROM an address
        addr = program.getAddressFactory().getAddress(target)
        refs = ref_manager.getReferencesFrom(addr)

        idx = 0
        for ref in refs:
            if idx >= offset + limit:
                break
            if idx >= offset:
                xrefs.append(build_xref_entry(ref))
            idx += 1

    elif xref_type == "function":
        # Get references to a function by name
        function_manager = program.getFunctionManager()
        function = None

        for func in function_manager.getFunctions(True):
            if str(func.getName()) == target:
                function = func
                break

        if function:
            entry_point = function.getEntryPoint()
            refs = ref_manager.getReferencesTo(entry_point)

            idx = 0
            for ref in refs:
                if idx >= offset + limit:
                    break
                if idx >= offset:
                    xrefs.append(build_xref_entry(ref))
                idx += 1
        else:
            print(json.dumps({"error": "Function not found: " + target}))
            sys.exit(1)

    # Build summary statistics
    classification_counts = {}
    for x in xrefs:
        c = x.get("classification", "unknown")
        classification_counts[c] = classification_counts.get(c, 0) + 1

    result = {
        "xrefs": xrefs,
        "offset": offset,
        "limit": limit,
        "count": len(xrefs),
        "classification_summary": classification_counts
    }
    print(json.dumps(result, indent=2))

except Exception as e:
    print(json.dumps({"error": str(e)}))
