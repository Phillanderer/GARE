# Disassemble function
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript disassemble.py <address>

import json
import sys

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

script_args = getScriptArgs()
if len(script_args) < 1:
    print(json.dumps({"error": "Address required"}))
    sys.exit(1)

target_addr = script_args[0]

try:
    addr = program.getAddressFactory().getAddress(target_addr)
    function_manager = program.getFunctionManager()
    function = function_manager.getFunctionAt(addr)

    if function is None:
        print(json.dumps({"error": f"No function at address {target_addr}"}))
        sys.exit(1)

    listing = program.getListing()
    disassembly = []

    # Get instructions in function
    instruction_iter = listing.getInstructions(function.getBody(), True)

    for instruction in instruction_iter:
        instr_addr = instruction.getAddress()
        mnemonic = instruction.getMnemonicString()
        operands = instruction.getDefaultOperandRepresentation()

        # Get comment if any
        comment = listing.getComment(ghidra.program.model.listing.CodeUnit.EOL_COMMENT, instr_addr)
        if comment is None:
            comment = ""

        disassembly.append({
            "address": str(instr_addr),
            "instruction": f"{mnemonic} {operands}",
            "comment": str(comment)
        })

    result = {
        "function": str(function.getName()),
        "address": str(function.getEntryPoint()),
        "disassembly": disassembly
    }

    print(json.dumps(result, indent=2))

except Exception as e:
    print(json.dumps({"error": str(e)}))
