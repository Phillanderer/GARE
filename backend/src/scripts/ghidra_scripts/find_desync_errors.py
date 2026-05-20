# Detect disassembly desynchronization errors (GB-17)
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript find_desync_errors.py
# Book Reference: Ch. 21 (Obfuscated Code Analysis, pp. 470-473)
#   - Desync: jumps land mid-instruction (e.g., JMP LAB+1)
#   - Causes Ghidra's linear sweep to generate error bookmarks
#   - "Conflicting instruction" messages indicate overlap
#   - Detection is the first step toward automated repair

import json
import sys

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

try:
    from ghidra.util.task import ConsoleTaskMonitor

    listing = program.getListing()
    bookmark_manager = program.getBookmarkManager()
    function_manager = program.getFunctionManager()
    memory = program.getMemory()

    errors = []
    warnings = []
    desync_candidates = []

    # Method 1: Scan Ghidra's error bookmarks
    # Ghidra creates bookmarks of type "Error" for conflicting instructions
    error_bookmarks = bookmark_manager.getBookmarksIterator("Error")
    for bm in error_bookmarks:
        addr = bm.getAddress()
        category = str(bm.getCategory())
        comment = str(bm.getComment())

        entry = {
            "address": str(addr),
            "category": category,
            "comment": comment,
            "type": "error_bookmark"
        }

        # Check if this is in a function
        func = function_manager.getFunctionContaining(addr)
        if func:
            entry["function"] = str(func.getName())

        errors.append(entry)

        # Check if it's specifically a conflicting instruction
        if "conflict" in comment.lower() or "overlap" in comment.lower():
            desync_candidates.append(entry)

    # Method 2: Scan analysis bookmarks for warnings
    analysis_bookmarks = bookmark_manager.getBookmarksIterator("Analysis")
    for bm in analysis_bookmarks:
        addr = bm.getAddress()
        category = str(bm.getCategory())
        comment = str(bm.getComment())

        if any(kw in comment.lower() for kw in ("conflict", "overlap", "bad instruction", "failed")):
            entry = {
                "address": str(addr),
                "category": category,
                "comment": comment,
                "type": "analysis_warning"
            }
            func = function_manager.getFunctionContaining(addr)
            if func:
                entry["function"] = str(func.getName())
            warnings.append(entry)

    # Method 3: Detect mid-instruction jumps
    # Scan for jump targets that land inside another instruction
    mid_instruction_jumps = []
    ref_manager = program.getReferenceManager()

    # Build set of valid instruction start addresses for executable segments
    exec_blocks = []
    for block in memory.getBlocks():
        if block.isExecute():
            exec_blocks.append(block)

    # Scan code references for targets that don't align with instruction boundaries
    for block in exec_blocks:
        instr_iter = listing.getInstructions(block.getStart(), True)
        checked = 0
        while instr_iter.hasNext() and checked < 10000:
            instr = instr_iter.next()
            checked += 1

            # Check if the instruction's address is inside the current block
            if not block.contains(instr.getAddress()):
                break

            flow_type = instr.getFlowType()
            if flow_type.isJump() or flow_type.isCall():
                refs = instr.getReferencesFrom()
                for ref in refs:
                    target = ref.getToAddress()
                    if not memory.contains(target):
                        continue

                    # Check if target is at a valid instruction start
                    target_instr = listing.getInstructionAt(target)
                    if target_instr is None:
                        # Target is not at an instruction start
                        # Check if it's inside an existing instruction
                        containing_instr = listing.getInstructionContaining(target)
                        if containing_instr is not None and not containing_instr.getAddress().equals(target):
                            mid_instruction_jumps.append({
                                "jump_from": str(instr.getAddress()),
                                "jump_instruction": str(instr),
                                "target": str(target),
                                "lands_inside": str(containing_instr),
                                "containing_instr_addr": str(containing_instr.getAddress()),
                                "offset_into_instr": int(target.getOffset() - containing_instr.getAddress().getOffset()),
                                "type": "mid_instruction_jump"
                            })

                            # Add function context
                            func = function_manager.getFunctionContaining(instr.getAddress())
                            if func:
                                mid_instruction_jumps[-1]["function"] = str(func.getName())

    # Method 4: Detect undefined bytes in executable sections (potential hidden code)
    undefined_regions = []
    for block in exec_blocks:
        # Sample undefined regions (don't scan the entire binary)
        addr = block.getStart()
        end = block.getEnd()
        undef_start = None
        undef_count = 0
        checked = 0

        while addr.compareTo(end) <= 0 and checked < 50000:
            checked += 1
            cu = listing.getCodeUnitAt(addr)
            if cu is None:
                if undef_start is None:
                    undef_start = addr
                undef_count += 1
                try:
                    addr = addr.add(1)
                except:
                    break
            else:
                if undef_start is not None and undef_count >= 4:
                    undefined_regions.append({
                        "start": str(undef_start),
                        "size": undef_count,
                        "section": str(block.getName()),
                        "note": "Undefined bytes in executable section — may be hidden/obfuscated code"
                    })
                undef_start = None
                undef_count = 0
                try:
                    addr = addr.add(cu.getLength())
                except:
                    break

        # Final region
        if undef_start is not None and undef_count >= 4:
            undefined_regions.append({
                "start": str(undef_start),
                "size": undef_count,
                "section": str(block.getName())
            })

    output = {
        "error_bookmarks": len(errors),
        "analysis_warnings": len(warnings),
        "desync_candidates": len(desync_candidates),
        "mid_instruction_jumps": len(mid_instruction_jumps),
        "undefined_exec_regions": len(undefined_regions),
        "errors": errors[:30],
        "warnings": warnings[:20],
        "desync": desync_candidates[:20],
        "mid_jumps": mid_instruction_jumps[:20],
        "undefined_regions": undefined_regions[:20],
        "remediation": {
            "for_desync": "Use convert_to_code on the jump target address to re-disassemble from the correct boundary",
            "for_mid_jumps": "Undefine the containing instruction, then disassemble from the jump target",
            "for_undefined": "Use convert_to_code to attempt disassembly of undefined executable regions"
        }
    }
    print(json.dumps(output, indent=2))

except Exception as e:
    print(json.dumps({"error": str(e)}))
