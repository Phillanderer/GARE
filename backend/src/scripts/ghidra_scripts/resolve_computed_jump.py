# Resolve computed/indirect jumps via p-code emulation (GB-18)
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript resolve_computed_jump.py <address>
# Book Reference: Ch. 21 (Obfuscated Code Analysis, pp. 474-476, 496-501)
#   - Computed jumps (JMP EAX, JMP [reg+offset]) break static analysis
#   - EmulatorHelper provides architecture-independent p-code emulation
#   - Trace register values through CALL/POP/LEA chains to resolve targets
#   - Works across x86, ARM, MIPS via Ghidra's p-code intermediate representation

import json
import sys

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

script_args = getScriptArgs()
if len(script_args) < 1:
    print(json.dumps({"error": "Usage: resolve_computed_jump.py <address_of_indirect_jump>"}))
    sys.exit(1)

target_addr_str = script_args[0]

try:
    from ghidra.app.emulator import EmulatorHelper
    from ghidra.util.task import ConsoleTaskMonitor

    listing = program.getListing()
    addr_factory = program.getAddressFactory()
    memory = program.getMemory()
    function_manager = program.getFunctionManager()

    addr = addr_factory.getAddress(target_addr_str)
    if addr is None:
        print(json.dumps({"error": "Invalid address: " + target_addr_str}))
        sys.exit(1)

    # Get the instruction at the target address
    instr = listing.getInstructionAt(addr)
    if instr is None:
        print(json.dumps({"error": "No instruction at address: " + target_addr_str}))
        sys.exit(1)

    # Verify it's a computed jump or call
    flow_type = instr.getFlowType()
    if not flow_type.isComputed():
        print(json.dumps({
            "address": target_addr_str,
            "instruction": str(instr),
            "flow_type": str(flow_type),
            "warning": "Instruction is not a computed jump/call — emulation may not be needed",
            "is_computed": False
        }))
        sys.exit(0)

    # Find the containing function to get the entry point for emulation
    func = function_manager.getFunctionContaining(addr)
    if func is None:
        print(json.dumps({"error": "No function contains address " + target_addr_str + ". Cannot determine emulation start point."}))
        sys.exit(1)

    entry = func.getEntryPoint()

    # Set up the emulator
    emu = EmulatorHelper(program)
    monitor = ConsoleTaskMonitor()

    # Configure emulation
    emu.enableMemoryWriteTracking(True)

    # Set initial register state (stack pointer, etc.)
    lang = program.getLanguage()
    space = addr_factory.getDefaultAddressSpace()
    pointer_size = program.getDefaultPointerSize()

    # Set up a reasonable stack
    stack_addr = space.getAddress(0x7FFF0000) if pointer_size == 4 else space.getAddress(0x7FFFFFFFE000)
    sp_reg = program.getCompilerSpec().getStackPointer()
    if sp_reg:
        emu.writeRegister(sp_reg, int(stack_addr.getOffset()))

    # Start emulation from the function entry
    emu.setBreakpoint(addr)  # Break at the computed jump

    # Emulate with a step limit to prevent infinite loops
    max_steps = 10000
    step_count = 0
    reached_target = False

    emu.writeRegister(emu.getPCRegister(), int(entry.getOffset()))

    results = {
        "address": target_addr_str,
        "instruction": str(instr),
        "flow_type": str(flow_type),
        "is_computed": True,
        "function": str(func.getName()),
        "function_entry": str(entry),
        "emulation_start": str(entry),
        "resolved_targets": [],
        "register_state_at_jump": {},
        "steps_executed": 0,
        "success": False
    }

    try:
        while step_count < max_steps:
            current_pc = emu.getExecutionAddress()

            # Check if we've reached the target instruction
            if current_pc.equals(addr):
                reached_target = True

                # Read all general-purpose registers at the jump point
                reg_state = {}
                for reg in lang.getRegisters():
                    if reg.isBaseRegister() and not reg.isProcessorContext():
                        try:
                            val = emu.readRegister(reg)
                            if val != 0:
                                reg_state[str(reg.getName())] = hex(int(val))
                        except:
                            pass

                results["register_state_at_jump"] = reg_state
                results["steps_executed"] = step_count

                # Try to determine the jump target from the instruction's semantics
                # For JMP reg or JMP [mem], the target is in the operand
                num_ops = instr.getNumOperands()
                for i in range(num_ops):
                    op_refs = instr.getOperandReferences(i)
                    for ref in op_refs:
                        if ref.getReferenceType().isFlow():
                            target = ref.getToAddress()
                            target_func = function_manager.getFunctionAt(target)
                            resolved = {
                                "target_address": str(target),
                                "source": "operand_reference"
                            }
                            if target_func:
                                resolved["target_function"] = str(target_func.getName())
                            results["resolved_targets"].append(resolved)

                # Also check register values as potential targets
                for reg_name, reg_val_hex in reg_state.items():
                    try:
                        reg_val = int(reg_val_hex, 16)
                        potential_target = space.getAddress(reg_val)
                        if memory.contains(potential_target):
                            target_instr = listing.getInstructionAt(potential_target)
                            target_func = function_manager.getFunctionAt(potential_target)
                            if target_instr or target_func:
                                resolved = {
                                    "target_address": str(potential_target),
                                    "source": "register_" + reg_name
                                }
                                if target_func:
                                    resolved["target_function"] = str(target_func.getName())
                                # Avoid duplicates
                                if resolved["target_address"] not in [r["target_address"] for r in results["resolved_targets"]]:
                                    results["resolved_targets"].append(resolved)
                    except:
                        pass

                results["success"] = len(results["resolved_targets"]) > 0
                break

            # Execute one step
            success = emu.step(monitor)
            if not success:
                results["error"] = "Emulation step failed at " + str(current_pc)
                break

            step_count += 1

        if not reached_target:
            results["error"] = "Did not reach target instruction within " + str(max_steps) + " steps"
            results["steps_executed"] = step_count

    except Exception as emu_err:
        results["error"] = "Emulation error: " + str(emu_err)
        results["steps_executed"] = step_count
    finally:
        emu.dispose()

    print(json.dumps(results, indent=2))

except Exception as e:
    print(json.dumps({"error": str(e)}))
