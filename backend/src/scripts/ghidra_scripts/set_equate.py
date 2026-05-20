# Apply named constants (equates) to instruction operands (GB-14)
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript set_equate.py <address> <operand_index> <equate_name>
# Book Reference: Ch. 7 (Disassembly Manipulation, pp. 135-136)
#   - Equates replace opaque hex values with meaningful identifiers
#   - Example: 0xa at a socket call becomes AF_INET; 0x2 becomes SOCK_STREAM
#   - Ghidra has built-in named constant catalog from common libraries

import json
import sys

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

script_args = getScriptArgs()

# Support two modes:
# 1. set_equate.py <address> <operand_index> <equate_name>  — apply equate
# 2. set_equate.py <address> suggest                         — suggest equates for all operands
if len(script_args) < 2:
    print(json.dumps({"error": "Usage: set_equate.py <address> <operand_index> <equate_name> | set_equate.py <address> suggest"}))
    sys.exit(1)

target_addr_str = script_args[0]
mode = script_args[1]

try:
    from ghidra.program.model.scalar import Scalar

    listing = program.getListing()
    equate_table = program.getEquateTable()

    addr = program.getAddressFactory().getAddress(target_addr_str)
    instr = listing.getInstructionAt(addr)

    if instr is None:
        print(json.dumps({"error": "No instruction at address: " + target_addr_str}))
        sys.exit(1)

    if mode == "suggest":
        # Suggest mode: list all scalar operands and any existing equates
        operands = []
        for i in range(instr.getNumOperands()):
            op_info = {
                "index": i,
                "representation": str(instr.getDefaultOperandRepresentation(i)),
                "scalar_value": None,
                "existing_equates": []
            }

            # Check for scalar value
            try:
                scalar = instr.getScalar(i)
                if scalar is not None:
                    val = int(scalar.getValue())
                    op_info["scalar_value"] = val
                    op_info["hex_value"] = hex(val)

                    # Look up existing equates for this value
                    equates = equate_table.getEquates(val)
                    for eq in equates:
                        op_info["existing_equates"].append(str(eq.getName()))

                    # Suggest common constants
                    suggestions = suggest_common_constants(val)
                    if suggestions:
                        op_info["suggestions"] = suggestions
            except:
                pass

            operands.append(op_info)

        result = {
            "address": str(addr),
            "instruction": str(instr),
            "mnemonic": str(instr.getMnemonicString()),
            "operands": operands
        }
        print(json.dumps(result, indent=2))

    else:
        # Apply mode: set equate on specific operand
        operand_index = int(mode)
        equate_name = script_args[2] if len(script_args) > 2 else None

        if equate_name is None:
            print(json.dumps({"error": "Equate name required for apply mode"}))
            sys.exit(1)

        # Get the scalar value at the operand
        scalar = instr.getScalar(operand_index)
        if scalar is None:
            print(json.dumps({"error": "No scalar value at operand index " + str(operand_index)}))
            sys.exit(1)

        scalar_value = int(scalar.getValue())

        # Check if equate already exists
        existing = equate_table.getEquate(equate_name)

        tx_id = program.startTransaction("Set equate: " + equate_name)
        try:
            if existing is None:
                # Create new equate
                equate = equate_table.createEquate(equate_name, scalar_value)
            else:
                equate = existing

            # Apply equate to the instruction operand
            equate.addReference(addr, operand_index)

            program.endTransaction(tx_id, True)

            result = {
                "success": True,
                "address": str(addr),
                "instruction": str(instr),
                "operand_index": operand_index,
                "original_value": scalar_value,
                "hex_value": hex(scalar_value),
                "equate_name": equate_name,
                "created_new": existing is None,
                "reference_count": equate.getReferenceCount()
            }
            print(json.dumps(result, indent=2))

        except Exception as e:
            program.endTransaction(tx_id, False)
            raise e

except Exception as e:
    print(json.dumps({"error": str(e)}))


def suggest_common_constants(value):
    """Suggest common named constants for a given integer value"""
    suggestions = []

    # Socket/network constants
    SOCKET_CONSTANTS = {
        0x0: "INADDR_ANY", 0x2: "AF_INET/SOCK_DGRAM", 0x1: "SOCK_STREAM",
        0xa: "AF_INET6", 0x6: "IPPROTO_TCP", 0x11: "IPPROTO_UDP",
        0x17: "AF_INET6_ALT",
        0x50: "HTTP_PORT_80", 0x1BB: "HTTPS_PORT_443",
        0x1F90: "PORT_8080"
    }

    # File/IO constants
    FILE_CONSTANTS = {
        0x0: "SEEK_SET/O_RDONLY", 0x1: "SEEK_CUR/O_WRONLY",
        0x2: "SEEK_END/O_RDWR", 0x40: "O_CREAT",
        0x200: "O_TRUNC", 0x400: "O_APPEND",
        0x1A4: "FILE_MODE_0644", 0x1ED: "FILE_MODE_0755",
        0x1FF: "FILE_MODE_0777"
    }

    # Memory/mmap constants
    MMAP_CONSTANTS = {
        0x1: "PROT_READ/MAP_SHARED", 0x2: "PROT_WRITE/MAP_PRIVATE",
        0x4: "PROT_EXEC", 0x7: "PROT_RWX",
        0x3: "PROT_READ_WRITE", 0x22: "MAP_PRIVATE_ANONYMOUS"
    }

    # Windows API constants
    WIN_CONSTANTS = {
        0x80000000: "GENERIC_READ", 0x40000000: "GENERIC_WRITE",
        0xC0000000: "GENERIC_READ_WRITE",
        0x1: "CREATE_NEW", 0x2: "CREATE_ALWAYS",
        0x3: "OPEN_EXISTING", 0x4: "OPEN_ALWAYS",
        0x80: "FILE_ATTRIBUTE_NORMAL",
        0x8000000: "PROCESS_ALL_ACCESS"
    }

    # Signal constants
    SIGNAL_CONSTANTS = {
        0x1: "SIGHUP", 0x2: "SIGINT", 0x3: "SIGQUIT",
        0x9: "SIGKILL", 0xB: "SIGSEGV", 0xD: "SIGPIPE",
        0xE: "SIGALRM", 0xF: "SIGTERM"
    }

    for table_name, table in [("socket", SOCKET_CONSTANTS), ("file", FILE_CONSTANTS),
                               ("mmap", MMAP_CONSTANTS), ("windows", WIN_CONSTANTS),
                               ("signal", SIGNAL_CONSTANTS)]:
        if value in table:
            suggestions.append({"category": table_name, "name": table[value]})

    return suggestions
