# Detect array patterns from scaling operations in instructions (GB-9)
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript detect_arrays.py <function_name_or_address>
# Book Reference: Ch. 8 (Data Types and Data Structures, pp. 147-182)
#   - Array indexing uses scale factors: RAX*4 = int[], RAX*8 = pointer[], RAX*24 = struct[24]
#   - Global arrays appear as sequences of same-typed data at regular intervals
#   - Stack arrays: negative EBP offsets with scale-factor indexing
#   - Heap arrays: malloc return value + scaled index

import json
import sys

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

script_args = getScriptArgs()
if len(script_args) < 1:
    print(json.dumps({"error": "Usage: detect_arrays.py <function_name_or_address>"}))
    sys.exit(1)

target = script_args[0]
function_manager = program.getFunctionManager()

# Find function by name or address
function = None
try:
    addr = program.getAddressFactory().getAddress(target)
    function = function_manager.getFunctionAt(addr)
except:
    pass

if function is None:
    for func in function_manager.getFunctions(True):
        if str(func.getName()) == target:
            function = func
            break

if function is None:
    print(json.dumps({"error": "Function not found: " + target}))
    sys.exit(1)

try:
    listing = program.getListing()
    func_body = function.getBody()

    # Common element sizes and their likely types
    SIZE_TYPE_MAP = {
        1: "byte/char",
        2: "short/wchar_t",
        4: "int/float/pointer(32-bit)",
        8: "long/double/pointer(64-bit)",
        16: "struct(16)/SSE vector"
    }

    arrays_detected = []
    scale_instructions = []

    # Pass 1: Find scaling operations in instructions
    # These indicate array element size via index * element_size
    instr_iter = listing.getInstructions(func_body, True)

    while instr_iter.hasNext():
        instr = instr_iter.next()
        mnemonic = str(instr.getMnemonicString()).upper()
        addr = instr.getAddress()
        instr_str = str(instr)

        # Method 1: Detect explicit scale factors in addressing modes
        # x86 SIB byte: [base + index*scale + disp]
        # Scales: 1, 2, 4, 8
        num_ops = instr.getNumOperands()
        for i in range(num_ops):
            op_str = str(instr.getDefaultOperandRepresentation(i))

            # Look for patterns like [REG*4 + ...], [REG*8 + ...], etc.
            import re
            scale_match = re.search(r'\*\s*([248])', op_str)
            if scale_match:
                scale = int(scale_match.group(1))
                scale_instructions.append({
                    "address": str(addr),
                    "instruction": instr_str,
                    "scale_factor": scale,
                    "element_size": scale,
                    "likely_type": SIZE_TYPE_MAP.get(scale, "struct(" + str(scale) + ")")
                })

        # Method 2: Detect SHL (shift left) used as multiplication for indexing
        # SHL REG, 2 = multiply by 4 (int array)
        # SHL REG, 3 = multiply by 8 (pointer/long array)
        if mnemonic in ("SHL", "SAL"):
            try:
                scalar = instr.getScalar(1)
                if scalar is not None:
                    shift = int(scalar.getValue())
                    if 1 <= shift <= 4:  # Reasonable array element sizes
                        element_size = 1 << shift
                        scale_instructions.append({
                            "address": str(addr),
                            "instruction": instr_str,
                            "scale_factor": element_size,
                            "element_size": element_size,
                            "likely_type": SIZE_TYPE_MAP.get(element_size, "struct(" + str(element_size) + ")"),
                            "method": "shift_left"
                        })
            except:
                pass

        # Method 3: Detect IMUL/MUL with constant for larger struct arrays
        # IMUL REG, REG, 24 = struct[24] array indexing
        if mnemonic in ("IMUL", "MUL"):
            for i in range(num_ops):
                try:
                    scalar = instr.getScalar(i)
                    if scalar is not None:
                        val = int(scalar.getValue())
                        if 3 <= val <= 256 and val not in (0x66666667, 0x55555556, 0x2AAAAAAB):
                            # Exclude magic multiplicative inverse constants (those are modulo ops)
                            scale_instructions.append({
                                "address": str(addr),
                                "instruction": instr_str,
                                "scale_factor": val,
                                "element_size": val,
                                "likely_type": "struct(" + str(val) + ")",
                                "method": "multiply"
                            })
                except:
                    pass

        # Method 4: LEA with scaling — LEA REG, [REG + REG*scale]
        if mnemonic == "LEA":
            op_str = str(instr.getDefaultOperandRepresentation(1)) if num_ops > 1 else ""
            scale_match = re.search(r'\*\s*([0-9]+)', op_str)
            if scale_match:
                scale = int(scale_match.group(1))
                if scale in (2, 4, 8, 16):
                    scale_instructions.append({
                        "address": str(addr),
                        "instruction": instr_str,
                        "scale_factor": scale,
                        "element_size": scale,
                        "likely_type": SIZE_TYPE_MAP.get(scale, "struct(" + str(scale) + ")"),
                        "method": "lea_scale"
                    })

    # Pass 2: Check for global data sequences (consecutive same-type data at regular offsets)
    # Look at data references from this function
    ref_manager = program.getReferenceManager()
    data_refs = {}

    instr_iter2 = listing.getInstructions(func_body, True)
    while instr_iter2.hasNext():
        instr = instr_iter2.next()
        for ref in instr.getReferencesFrom():
            if ref.getReferenceType().isData():
                to_addr = ref.getToAddress()
                data = listing.getDefinedDataAt(to_addr)
                if data:
                    dt = data.getDataType()
                    key = str(dt.getName())
                    if key not in data_refs:
                        data_refs[key] = []
                    data_refs[key].append(int(to_addr.getOffset()))

    # Check for consecutive addresses with same type (global array pattern)
    for type_name, addrs in data_refs.items():
        if len(addrs) >= 3:
            addrs_sorted = sorted(addrs)
            # Check if addresses are evenly spaced
            diffs = [addrs_sorted[i+1] - addrs_sorted[i] for i in range(len(addrs_sorted)-1)]
            if len(set(diffs)) == 1 and diffs[0] > 0:
                arrays_detected.append({
                    "type": "global_array",
                    "base_address": hex(addrs_sorted[0]),
                    "element_type": type_name,
                    "element_size": diffs[0],
                    "element_count": len(addrs_sorted),
                    "total_size": diffs[0] * len(addrs_sorted),
                    "addresses": [hex(a) for a in addrs_sorted[:20]]
                })

    # Aggregate scaling patterns into array candidates
    scale_sizes = {}
    for si in scale_instructions:
        sz = si["element_size"]
        if sz not in scale_sizes:
            scale_sizes[sz] = []
        scale_sizes[sz].append(si)

    for sz, instructions in scale_sizes.items():
        if len(instructions) >= 1:
            arrays_detected.append({
                "type": "indexed_access",
                "element_size": sz,
                "likely_type": SIZE_TYPE_MAP.get(sz, "struct(" + str(sz) + ")"),
                "access_count": len(instructions),
                "access_points": instructions[:10]
            })

    output = {
        "function": str(function.getName()),
        "address": str(function.getEntryPoint()),
        "arrays_detected": len(arrays_detected),
        "arrays": arrays_detected,
        "scale_instructions_found": len(scale_instructions)
    }
    print(json.dumps(output, indent=2))

except Exception as e:
    print(json.dumps({"error": str(e)}))
