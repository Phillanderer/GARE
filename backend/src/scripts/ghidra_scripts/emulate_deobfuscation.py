# Emulation-based static deobfuscation (GB-19)
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript emulate_deobfuscation.py <start_address> <end_address> [write_back]
# Book Reference: Ch. 21 (Obfuscated Code Analysis, pp. 491-501)
#   - EmulatorHelper with enableMemoryWriteTracking(true)
#   - Emulates instructions in specified range
#   - Tracks all memory writes (decoded/unpacked bytes)
#   - Optional: writes modified bytes back to the program via writeBackMemory()
#   - Triggers re-analysis so disassembler parses decoded instructions

import json
import sys

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

script_args = getScriptArgs()
if len(script_args) < 2:
    print(json.dumps({"error": "Usage: emulate_deobfuscation.py <start_address> <end_address> [write_back=false]"}))
    sys.exit(1)

start_addr_str = script_args[0]
end_addr_str = script_args[1]
write_back = script_args[2].lower() in ("true", "1", "yes") if len(script_args) > 2 else False

try:
    from ghidra.app.emulator import EmulatorHelper
    from ghidra.util.task import ConsoleTaskMonitor

    addr_factory = program.getAddressFactory()
    memory = program.getMemory()
    listing = program.getListing()
    space = addr_factory.getDefaultAddressSpace()
    pointer_size = program.getDefaultPointerSize()

    start_addr = addr_factory.getAddress(start_addr_str)
    end_addr = addr_factory.getAddress(end_addr_str)

    if start_addr is None or end_addr is None:
        print(json.dumps({"error": "Invalid address range"}))
        sys.exit(1)

    # Calculate range size
    range_size = int(end_addr.getOffset()) - int(start_addr.getOffset())
    if range_size <= 0:
        print(json.dumps({"error": "End address must be after start address"}))
        sys.exit(1)
    if range_size > 1048576:  # 1MB limit
        print(json.dumps({"error": "Range too large (max 1MB). Specify a smaller region."}))
        sys.exit(1)

    monitor = ConsoleTaskMonitor()

    # Set up emulator
    emu = EmulatorHelper(program)
    emu.enableMemoryWriteTracking(True)

    # Set up a reasonable stack
    stack_base = 0x7FFF0000 if pointer_size == 4 else 0x7FFFFFFFE000
    stack_addr = space.getAddress(stack_base)
    sp_reg = program.getCompilerSpec().getStackPointer()
    if sp_reg:
        emu.writeRegister(sp_reg, stack_base)

    # Set PC to start address
    emu.writeRegister(emu.getPCRegister(), int(start_addr.getOffset()))

    # Emulate
    max_steps = 100000
    step_count = 0
    memory_writes = []
    errors = []

    results = {
        "start_address": start_addr_str,
        "end_address": end_addr_str,
        "range_size": range_size,
        "write_back_enabled": write_back,
        "steps_executed": 0,
        "memory_writes": [],
        "unique_write_regions": [],
        "bytes_modified": 0,
        "success": False
    }

    try:
        while step_count < max_steps:
            current_pc = emu.getExecutionAddress()

            # Check if we've passed the end address
            if current_pc.getOffset() > end_addr.getOffset():
                break

            # Check if we've looped back before start (error)
            if current_pc.getOffset() < start_addr.getOffset() and step_count > 0:
                # Allow jumps within the range but stop if we escape entirely
                break

            # Execute one step
            try:
                success = emu.step(monitor)
                if not success:
                    errors.append("Step failed at " + str(current_pc))
                    break
            except Exception as step_err:
                errors.append("Exception at " + str(current_pc) + ": " + str(step_err))
                break

            step_count += 1

        # Collect memory write tracking results
        write_set = emu.getTrackedMemoryWriteSet()
        if write_set is not None:
            write_ranges = write_set.getAddressRanges()
            total_bytes = 0

            for addr_range in write_ranges:
                range_start = addr_range.getMinAddress()
                range_end = addr_range.getMaxAddress()
                range_len = int(range_end.getOffset()) - int(range_start.getOffset()) + 1
                total_bytes += range_len

                region_info = {
                    "start": str(range_start),
                    "end": str(range_end),
                    "size": range_len
                }

                # Read the first few bytes of modified data
                preview_bytes = []
                preview_addr = range_start
                for i in range(min(32, range_len)):
                    try:
                        b = emu.readMemoryByte(preview_addr)
                        preview_bytes.append(format(b & 0xFF, '02x'))
                        preview_addr = preview_addr.add(1)
                    except:
                        break
                region_info["preview_hex"] = " ".join(preview_bytes)

                # Check if the modified region is in an executable section
                block = memory.getBlock(range_start)
                if block:
                    region_info["section"] = str(block.getName())
                    region_info["executable"] = block.isExecute()

                memory_writes.append(region_info)

            results["memory_writes"] = memory_writes[:50]  # Cap output
            results["bytes_modified"] = total_bytes
            results["unique_write_regions"] = len(memory_writes)

        results["steps_executed"] = step_count
        results["success"] = step_count > 0

        if errors:
            results["errors"] = errors[:10]

        # Write back if requested
        if write_back and total_bytes > 0:
            tx_id = program.startTransaction("Emulation deobfuscation writeback")
            try:
                bytes_written = 0
                for region in memory_writes:
                    region_start = addr_factory.getAddress(region["start"])
                    region_size = region["size"]

                    # Read emulated memory and write to program
                    write_addr = region_start
                    for i in range(region_size):
                        try:
                            b = emu.readMemoryByte(write_addr)
                            memory.setByte(write_addr, b & 0xFF)
                            bytes_written += 1
                            write_addr = write_addr.add(1)
                        except:
                            break

                program.endTransaction(tx_id, True)
                results["writeback_bytes"] = bytes_written
                results["writeback_success"] = True
                results["note"] = "Modified bytes written back to program. Re-analyze affected regions with convert_to_code."

            except Exception as wb_err:
                program.endTransaction(tx_id, False)
                results["writeback_success"] = False
                results["writeback_error"] = str(wb_err)

    except Exception as emu_err:
        results["error"] = str(emu_err)
        results["steps_executed"] = step_count
    finally:
        emu.dispose()

    print(json.dumps(results, indent=2))

except Exception as e:
    print(json.dumps({"error": str(e)}))
