# Basic block and control flow graph analysis (GB-4)
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript analyze_basic_blocks.py <function_name_or_address>
# Book Reference: Ch. 10 (Graphs, pp. 8708-8728)
#   - Basic blocks: sequences with single entry/exit, guaranteed to complete
#   - Back edges indicate loops
#   - Edge types: sequential, jump-true, jump-false, fallthrough

import json
import sys

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

script_args = getScriptArgs()
if len(script_args) < 1:
    print(json.dumps({"error": "Usage: analyze_basic_blocks.py <function_name_or_address>"}))
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
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.task import ConsoleTaskMonitor

    monitor = ConsoleTaskMonitor()
    block_model = BasicBlockModel(program)

    # Get all basic blocks within this function's body
    func_body = function.getBody()
    block_iter = block_model.getCodeBlocksContaining(func_body, monitor)

    blocks = []
    block_map = {}  # address -> block_id
    block_id = 0

    # First pass: collect all blocks
    while block_iter.hasNext():
        block = block_iter.next()
        start = block.getMinAddress()
        end = block.getMaxAddress()

        # Count instructions in this block
        listing = program.getListing()
        instr_count = 0
        instr_iter = listing.getInstructions(block, True)
        last_instr = None
        while instr_iter.hasNext():
            last_instr = instr_iter.next()
            instr_count += 1

        # Determine if this is the entry block
        is_entry = start.equals(function.getEntryPoint())

        block_info = {
            "id": block_id,
            "start": str(start),
            "end": str(end),
            "instruction_count": instr_count,
            "is_entry": is_entry,
            "successors": [],
            "predecessors": []
        }

        # Get last instruction mnemonic for edge type determination
        if last_instr:
            block_info["last_instruction"] = str(last_instr.getMnemonicString())

        blocks.append(block_info)
        block_map[str(start)] = block_id
        block_id += 1

    # Second pass: build edges (successors/predecessors)
    block_iter = block_model.getCodeBlocksContaining(func_body, monitor)
    idx = 0
    back_edges = []
    all_edges = []

    while block_iter.hasNext():
        block = block_iter.next()
        src_addr = str(block.getMinAddress())
        src_id = block_map.get(src_addr, idx)

        # Get successors (destinations)
        dest_iter = block.getDestinations(monitor)
        while dest_iter.hasNext():
            dest_ref = dest_iter.next()
            dest_block = dest_ref.getDestinationBlock()
            if dest_block is not None:
                dest_addr = str(dest_block.getMinAddress())
                dest_id = block_map.get(dest_addr)
                if dest_id is not None:
                    flow_type = str(dest_ref.getFlowType())
                    edge_info = {
                        "target_id": dest_id,
                        "target_addr": dest_addr,
                        "flow_type": flow_type
                    }
                    blocks[src_id]["successors"].append(edge_info)

                    # Track edge for back-edge detection
                    all_edges.append((src_id, dest_id, flow_type))

                    # Detect back edges (target block_id <= source block_id in DFS order)
                    # Simple heuristic: if target address <= source address, likely a back edge (loop)
                    if dest_id <= src_id:
                        back_edges.append({
                            "from_block": src_id,
                            "to_block": dest_id,
                            "from_addr": src_addr,
                            "to_addr": dest_addr,
                            "flow_type": flow_type
                        })

        # Get predecessors (sources)
        src_iter = block.getSources(monitor)
        while src_iter.hasNext():
            src_ref = src_iter.next()
            src_block = src_ref.getSourceBlock()
            if src_block is not None:
                pred_addr = str(src_block.getMinAddress())
                pred_id = block_map.get(pred_addr)
                if pred_id is not None:
                    blocks[src_id]["predecessors"].append({
                        "source_id": pred_id,
                        "source_addr": pred_addr
                    })

        idx += 1

    # Identify loops from back edges
    loops = []
    for be in back_edges:
        loop_header = be["to_block"]
        loop_body = set()

        # Simple loop body detection: all blocks reachable from header
        # that can reach the back edge source
        loop_body.add(be["from_block"])
        loop_body.add(loop_header)

        # Walk backwards from back edge source to find loop body blocks
        worklist = [be["from_block"]]
        while worklist:
            current = worklist.pop()
            for pred in blocks[current]["predecessors"]:
                pid = pred["source_id"]
                if pid not in loop_body and pid != loop_header:
                    loop_body.add(pid)
                    worklist.append(pid)

        loops.append({
            "header_block": loop_header,
            "header_addr": blocks[loop_header]["start"],
            "back_edge_from": be["from_block"],
            "body_blocks": sorted(list(loop_body)),
            "body_size": len(loop_body)
        })

    output = {
        "function": str(function.getName()),
        "address": str(function.getEntryPoint()),
        "total_blocks": len(blocks),
        "total_edges": len(all_edges),
        "loops_detected": len(loops),
        "blocks": blocks,
        "back_edges": back_edges,
        "loops": loops
    }
    print(json.dumps(output, indent=2))

except Exception as e:
    print(json.dumps({"error": str(e)}))
