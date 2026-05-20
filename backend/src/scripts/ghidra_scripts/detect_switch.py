# Detect switch statement implementation patterns (GB-6)
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript detect_switch.py <function_name_or_address>
# Book Reference: Ch. 20 (Compiler Variations, pp. 444-451)
#   - Jump table switches: dense cases -> lookup table in .rodata (gcc) or .text (MSVC)
#   - Binary search switches: sparse cases -> nested if/else, log(n) depth
#   - Hybrid: jump table for dense range + binary search for outliers

import json
import sys

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

script_args = getScriptArgs()
if len(script_args) < 1:
    print(json.dumps({"error": "Usage: detect_switch.py <function_name_or_address>"}))
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
    from ghidra.util.task import ConsoleTaskMonitor

    listing = program.getListing()
    func_body = function.getBody()
    ref_manager = program.getReferenceManager()

    switches = []

    # Scan instructions in the function for switch-like patterns
    instr_iter = listing.getInstructions(func_body, True)

    while instr_iter.hasNext():
        instr = instr_iter.next()
        mnemonic = str(instr.getMnemonicString()).upper()
        addr = instr.getAddress()

        # Method 1: Look for Ghidra-detected switch tables
        # Ghidra marks computed jumps with COMPUTED_JUMP flow type
        flow_type = instr.getFlowType()
        if flow_type.isComputed() and flow_type.isJump():
            # This is a computed jump — likely a switch jump table
            refs_from = instr.getReferencesFrom()
            jump_targets = []
            for ref in refs_from:
                if ref.getReferenceType().isJump():
                    target_addr = ref.getToAddress()
                    target_func = function_manager.getFunctionContaining(target_addr)
                    # Only count targets within this function
                    if target_func and target_func.getEntryPoint().equals(function.getEntryPoint()):
                        jump_targets.append(str(target_addr))

            if len(jump_targets) >= 2:
                # Determine if jump table is in .rodata or .text
                table_location = "unknown"
                memory = program.getMemory()
                for ref in refs_from:
                    if ref.getReferenceType().isData():
                        block = memory.getBlock(ref.getToAddress())
                        if block:
                            table_location = str(block.getName())
                            break

                switches.append({
                    "type": "jump_table",
                    "address": str(addr),
                    "instruction": str(instr),
                    "case_count": len(jump_targets),
                    "targets": jump_targets[:20],  # Cap output
                    "table_location": table_location,
                    "density": "dense"
                })

        # Method 2: Detect binary search switch patterns
        # Look for CMP + JG/JL/JE chains (compare-and-branch trees)
        if mnemonic in ("CMP", "CMPL", "CMPQ", "CMPI"):
            # Check if this CMP is followed by conditional jumps forming a tree
            next_instr = instr.getNext()
            if next_instr:
                next_mnemonic = str(next_instr.getMnemonicString()).upper()
                # Conditional branches after CMP suggest binary search node
                if next_mnemonic.startswith("J") and next_mnemonic not in ("JMP", "JMPQ"):
                    # Count the depth of CMP chains in this function
                    # (we'll aggregate these at the end)
                    pass

    # Method 3: Scan for Ghidra's switch table annotations
    # Ghidra stores switch table info in the program's data
    from ghidra.program.model.symbol import FlowType
    from ghidra.program.model.block import BasicBlockModel

    monitor = ConsoleTaskMonitor()
    block_model = BasicBlockModel(program)

    # Count conditional branches to estimate binary search switches
    cmp_count = 0
    conditional_branch_count = 0
    instr_iter2 = listing.getInstructions(func_body, True)
    cmp_values = []

    while instr_iter2.hasNext():
        instr = instr_iter2.next()
        mnemonic = str(instr.getMnemonicString()).upper()

        if mnemonic in ("CMP", "CMPL", "CMPQ"):
            cmp_count += 1
            # Try to extract the comparison constant
            num_ops = instr.getNumOperands()
            for i in range(num_ops):
                try:
                    scalar = instr.getScalar(i)
                    if scalar is not None:
                        cmp_values.append(int(scalar.getValue()))
                except:
                    pass

        if mnemonic.startswith("J") and mnemonic not in ("JMP", "JMPQ", "CALL"):
            conditional_branch_count += 1

    # Heuristic: if many CMP instructions with distinct constants followed by
    # conditional branches, likely a binary search switch
    if cmp_count >= 3 and len(set(cmp_values)) >= 3:
        unique_values = sorted(set(cmp_values))
        # Calculate density: cases / (max - min + 1)
        if len(unique_values) >= 2:
            value_range = unique_values[-1] - unique_values[0] + 1
            density = len(unique_values) / float(value_range) if value_range > 0 else 0

            if density < 0.5:  # Sparse = likely binary search
                switches.append({
                    "type": "binary_search",
                    "case_values": unique_values[:30],  # Cap output
                    "case_count": len(unique_values),
                    "value_range": [unique_values[0], unique_values[-1]],
                    "density": round(density, 3),
                    "cmp_instructions": cmp_count,
                    "conditional_branches": conditional_branch_count,
                    "note": "Sparse case values suggest compiler used binary search tree instead of jump table"
                })

    output = {
        "function": str(function.getName()),
        "address": str(function.getEntryPoint()),
        "switches_detected": len(switches),
        "switches": switches,
        "stats": {
            "cmp_instructions": cmp_count,
            "conditional_branches": conditional_branch_count,
            "distinct_cmp_constants": len(set(cmp_values))
        }
    }
    print(json.dumps(output, indent=2))

except Exception as e:
    print(json.dumps({"error": str(e)}))
