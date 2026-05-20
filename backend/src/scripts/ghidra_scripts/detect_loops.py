# Detect and classify loops via CFG back-edge analysis (GB-16)
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript detect_loops.py <function_name_or_address>
# Book Reference: Ch. 10 (Graphs, pp. 197-214)
#   - Back edges in a CFG indicate loops
#   - Natural loops: single entry (header), one or more back edges
#   - Loop type inference: for (counter), while (condition-first), do-while (condition-last)
#   - Nesting depth from dominator tree relationships

import json
import sys

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

script_args = getScriptArgs()
if len(script_args) < 1:
    print(json.dumps({"error": "Usage: detect_loops.py <function_name_or_address>"}))
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
    from ghidra.program.model.block import BasicBlockModel

    monitor = ConsoleTaskMonitor()
    block_model = BasicBlockModel(program)
    listing = program.getListing()
    func_body = function.getBody()

    # Step 1: Build the CFG — blocks and edges
    blocks = {}  # addr_str -> {id, start, end, successors, predecessors}
    block_order = []  # Ordered list of block addresses
    block_iter = block_model.getCodeBlocksContaining(func_body, monitor)

    while block_iter.hasNext():
        block = block_iter.next()
        start = block.getFirstStartAddress()
        start_str = str(start)

        blocks[start_str] = {
            "id": len(block_order),
            "start": start_str,
            "end": str(block.getMaxAddress()),
            "successors": [],
            "predecessors": [],
            "instruction_count": 0
        }
        block_order.append(start_str)

        # Count instructions
        instr_iter = listing.getInstructions(block, True)
        count = 0
        while instr_iter.hasNext():
            instr_iter.next()
            count += 1
        blocks[start_str]["instruction_count"] = count

    # Step 2: Build edges
    for addr_str in block_order:
        block_iter2 = block_model.getCodeBlocksContaining(func_body, monitor)
        while block_iter2.hasNext():
            block = block_iter2.next()
            if str(block.getFirstStartAddress()) == addr_str:
                dest_iter = block.getDestinations(monitor)
                while dest_iter.hasNext():
                    dest_ref = dest_iter.next()
                    dest_block = dest_ref.getDestinationBlock()
                    dest_str = str(dest_block.getFirstStartAddress())
                    if dest_str in blocks:
                        blocks[addr_str]["successors"].append(dest_str)
                        blocks[dest_str]["predecessors"].append(addr_str)
                break

    # Step 3: Compute dominators using iterative algorithm
    # dom[n] = {n} union (intersection of dom[p] for all predecessors p)
    entry_str = str(function.getEntryPoint())
    dom = {}
    all_nodes = set(block_order)

    for n in block_order:
        if n == entry_str:
            dom[n] = {n}
        else:
            dom[n] = set(all_nodes)

    changed = True
    iterations = 0
    while changed and iterations < 100:
        changed = False
        iterations += 1
        for n in block_order:
            if n == entry_str:
                continue
            preds = blocks[n]["predecessors"]
            if preds:
                new_dom = set(all_nodes)
                for p in preds:
                    if p in dom:
                        new_dom = new_dom.intersection(dom[p])
                new_dom.add(n)
                if new_dom != dom[n]:
                    dom[n] = new_dom
                    changed = True

    # Step 4: Find back edges (edge n->h where h dominates n)
    back_edges = []
    for n in block_order:
        for succ in blocks[n]["successors"]:
            if succ in dom.get(n, set()):
                back_edges.append({"from": n, "to": succ})

    # Step 5: For each back edge, compute the natural loop
    loops = []
    for be in back_edges:
        header = be["to"]
        tail = be["from"]

        # Natural loop = all nodes that can reach tail without going through header
        loop_body = {header, tail}
        worklist = [tail] if tail != header else []

        while worklist:
            node = worklist.pop()
            for pred in blocks[node]["predecessors"]:
                if pred not in loop_body:
                    loop_body.add(pred)
                    worklist.append(pred)

        # Count total instructions in loop
        total_instrs = sum(blocks[b]["instruction_count"] for b in loop_body if b in blocks)

        # Classify loop type based on structure
        loop_type = classify_loop(blocks, header, tail, loop_body)

        # Detect loop-carried variables (variables modified in loop body)
        loop_vars = detect_loop_variables(listing, blocks, loop_body, program)

        loop_info = {
            "header": header,
            "back_edge_from": tail,
            "body_blocks": sorted(list(loop_body)),
            "block_count": len(loop_body),
            "instruction_count": total_instrs,
            "type": loop_type,
            "loop_variables": loop_vars[:10]  # Cap output
        }

        loops.append(loop_info)

    # Step 6: Compute nesting depth
    # A loop L1 is nested inside L2 if L1's body is a proper subset of L2's body
    for i, l1 in enumerate(loops):
        body1 = set(l1["body_blocks"])
        nesting_depth = 0
        parent_header = None
        for j, l2 in enumerate(loops):
            if i == j:
                continue
            body2 = set(l2["body_blocks"])
            if body1.issubset(body2) and body1 != body2:
                nesting_depth += 1
                if parent_header is None or len(body2) < len(set(loops[k]["body_blocks"] if loops[k].get("_parent_size", 999) > len(body2) else [] for k in range(len(loops)))):
                    parent_header = l2["header"]
        l1["nesting_depth"] = nesting_depth
        if parent_header:
            l1["parent_loop_header"] = parent_header

    output = {
        "function": str(function.getName()),
        "address": str(function.getEntryPoint()),
        "total_blocks": len(blocks),
        "back_edges_found": len(back_edges),
        "loops_detected": len(loops),
        "loops": loops,
        "dominator_iterations": iterations,
        "max_nesting_depth": max((l.get("nesting_depth", 0) for l in loops), default=0)
    }
    print(json.dumps(output, indent=2))

except Exception as e:
    print(json.dumps({"error": str(e)}))


def classify_loop(blocks, header, tail, loop_body):
    """Classify loop as for/while/do-while based on structure"""
    # do-while: header has no conditional branch (condition is at the tail)
    # while: header has a conditional branch with one exit outside loop
    # for: while-like but with an increment operation before the back edge

    header_succs = blocks[header]["successors"]
    exits_from_header = [s for s in header_succs if s not in loop_body]

    if header == tail:
        return "self_loop"

    if exits_from_header:
        # Header can exit the loop — condition checked at top = while or for
        # Heuristic: if tail block has an increment-like pattern, it's a for-loop
        return "while_or_for"
    else:
        # Header doesn't exit — condition must be at the tail = do-while
        tail_succs = blocks[tail]["successors"]
        exits_from_tail = [s for s in tail_succs if s not in loop_body]
        if exits_from_tail:
            return "do_while"
        else:
            return "infinite_or_complex"


def detect_loop_variables(listing, blocks, loop_body, program):
    """Detect variables that are modified within the loop body"""
    modified_regs = set()
    loop_vars = []

    for block_addr in loop_body:
        if block_addr not in blocks:
            continue
        start = program.getAddressFactory().getAddress(blocks[block_addr]["start"])
        end = program.getAddressFactory().getAddress(blocks[block_addr]["end"])
        addr_set = program.getAddressFactory().getAddressSet(start, end)

        instr_iter = listing.getInstructions(addr_set, True)
        while instr_iter.hasNext():
            instr = instr_iter.next()
            mnemonic = str(instr.getMnemonicString()).upper()

            # Track register writes (destinations of arithmetic/move ops)
            if mnemonic in ("ADD", "SUB", "INC", "DEC", "MOV", "LEA", "IMUL", "SHL", "SHR", "XOR", "AND", "OR"):
                try:
                    result_objs = instr.getResultObjects()
                    for obj in result_objs:
                        obj_str = str(obj)
                        if obj_str not in modified_regs:
                            modified_regs.add(obj_str)
                            # Only report if it's a register or stack variable
                            if not obj_str.startswith("0x"):
                                loop_vars.append({
                                    "name": obj_str,
                                    "modified_by": mnemonic,
                                    "at": str(instr.getAddress())
                                })
                except:
                    pass

    return loop_vars
