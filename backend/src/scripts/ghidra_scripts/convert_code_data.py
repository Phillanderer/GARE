# Convert between code and data at specified addresses (GB-15)
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript convert_code_data.py <mode> <address> [data_type] [count]
# Modes: to_code, to_data, undefine
# Book Reference: Ch. 7 (Disassembly Manipulation, pp. 139-145)
#   - Auto-analysis sometimes misclassifies code as data (missed functions)
#   - Or data as code (embedded data tables, jump tables)
#   - Clear Code Bytes (hotkey C) + Disassemble is the standard repair workflow
#   - Compilers that embed data in code sections and obfuscated programs are primary causes

import json
import sys

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

script_args = getScriptArgs()
if len(script_args) < 2:
    print(json.dumps({"error": "Usage: convert_code_data.py <mode> <address> [data_type] [count]"}))
    sys.exit(1)

mode = script_args[0]
target_addr_str = script_args[1]
data_type_name = script_args[2] if len(script_args) > 2 else None
count = int(script_args[3]) if len(script_args) > 3 else 1

try:
    from ghidra.program.model.listing import CodeUnit
    from ghidra.util.task import ConsoleTaskMonitor

    listing = program.getListing()
    addr_factory = program.getAddressFactory()
    addr = addr_factory.getAddress(target_addr_str)

    if addr is None:
        print(json.dumps({"error": "Invalid address: " + target_addr_str}))
        sys.exit(1)

    monitor = ConsoleTaskMonitor()

    if mode == "to_code":
        # Convert data/undefined bytes to code (disassemble)
        # First undefine any existing data at the address
        tx_id = program.startTransaction("Convert to code at " + target_addr_str)
        try:
            # Clear existing code unit
            existing = listing.getCodeUnitAt(addr)
            if existing is not None:
                listing.clearCodeUnits(addr, addr, False)

            # Disassemble from the address
            disassembler = program.getLanguage().getDefaultDisassembler()
            from ghidra.app.cmd.disassemble import DisassembleCommand
            cmd = DisassembleCommand(addr, None, True)
            cmd.applyTo(program, monitor)

            # Get result
            instr = listing.getInstructionAt(addr)
            if instr:
                # Count how many instructions were created
                instr_count = 0
                check_addr = addr
                while instr_count < 50:
                    i = listing.getInstructionAt(check_addr)
                    if i is None:
                        break
                    instr_count += 1
                    check_addr = i.getAddress().add(i.getLength())

                result = {
                    "success": True,
                    "mode": "to_code",
                    "address": str(addr),
                    "first_instruction": str(instr),
                    "instructions_created": instr_count
                }

                # Check if this created a new function candidate
                func = program.getFunctionManager().getFunctionContaining(addr)
                if func:
                    result["in_function"] = str(func.getName())
                else:
                    result["note"] = "No function contains this address. Consider creating a function here."
            else:
                result = {
                    "success": False,
                    "mode": "to_code",
                    "address": str(addr),
                    "error": "Disassembly failed — bytes may not be valid instructions"
                }

            program.endTransaction(tx_id, True)
            print(json.dumps(result, indent=2))

        except Exception as e:
            program.endTransaction(tx_id, False)
            raise e

    elif mode == "to_data":
        # Convert code/undefined bytes to data
        tx_id = program.startTransaction("Convert to data at " + target_addr_str)
        try:
            # Clear existing code unit first
            existing = listing.getCodeUnitAt(addr)
            if existing is not None:
                end_addr = addr.add(existing.getLength() - 1) if existing.getLength() > 0 else addr
                listing.clearCodeUnits(addr, end_addr, False)

            # Determine data type to apply
            if data_type_name:
                # Look up the data type
                dtm = program.getDataTypeManager()
                data_type = None

                # Search all data types
                for dt in dtm.getAllDataTypes():
                    if str(dt.getName()) == data_type_name:
                        data_type = dt
                        break

                if data_type is None:
                    # Try built-in types
                    from ghidra.program.model.data import (
                        ByteDataType, WordDataType, DWordDataType, QWordDataType,
                        FloatDataType, DoubleDataType, PointerDataType,
                        StringDataType, TerminatedStringDataType
                    )
                    BUILTIN_TYPES = {
                        "byte": ByteDataType.dataType,
                        "word": WordDataType.dataType,
                        "dword": DWordDataType.dataType,
                        "qword": QWordDataType.dataType,
                        "float": FloatDataType.dataType,
                        "double": DoubleDataType.dataType,
                        "pointer": PointerDataType.dataType,
                        "string": TerminatedStringDataType.dataType
                    }
                    data_type = BUILTIN_TYPES.get(data_type_name.lower())

                if data_type is None:
                    program.endTransaction(tx_id, False)
                    print(json.dumps({"error": "Data type not found: " + data_type_name}))
                    sys.exit(1)

                # Create data at the address
                if count > 1:
                    # Create array
                    from ghidra.program.model.data import ArrayDataType
                    array_type = ArrayDataType(data_type, count, data_type.getLength())
                    listing.createData(addr, array_type)
                    result = {
                        "success": True,
                        "mode": "to_data",
                        "address": str(addr),
                        "data_type": data_type_name + "[" + str(count) + "]",
                        "element_size": data_type.getLength(),
                        "total_size": data_type.getLength() * count
                    }
                else:
                    listing.createData(addr, data_type)
                    result = {
                        "success": True,
                        "mode": "to_data",
                        "address": str(addr),
                        "data_type": data_type_name,
                        "size": data_type.getLength()
                    }
            else:
                # Default: define as undefined bytes (just clear)
                result = {
                    "success": True,
                    "mode": "to_data",
                    "address": str(addr),
                    "data_type": "undefined",
                    "note": "Cleared code units. Specify data_type to define as specific type."
                }

            program.endTransaction(tx_id, True)
            print(json.dumps(result, indent=2))

        except Exception as e:
            program.endTransaction(tx_id, False)
            raise e

    elif mode == "undefine":
        # Undefine bytes at address (clear both code and data definitions)
        tx_id = program.startTransaction("Undefine at " + target_addr_str)
        try:
            existing = listing.getCodeUnitAt(addr)
            size = 1
            if existing:
                size = existing.getLength()
                end_addr = addr.add(size - 1) if size > 0 else addr
                listing.clearCodeUnits(addr, end_addr, False)

            program.endTransaction(tx_id, True)

            result = {
                "success": True,
                "mode": "undefine",
                "address": str(addr),
                "bytes_cleared": size,
                "note": "Bytes are now undefined. Use to_code or to_data to redefine."
            }
            print(json.dumps(result, indent=2))

        except Exception as e:
            program.endTransaction(tx_id, False)
            raise e

    else:
        print(json.dumps({"error": "Unknown mode: " + mode + ". Valid: to_code, to_data, undefine"}))

except Exception as e:
    print(json.dumps({"error": str(e)}))
