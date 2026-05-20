# Export complete binary analysis package
# Includes: original binary + all annotations in readable format
# @category: Export

import sys
import json
import os
import shutil
from zipfile import ZipFile

try:
    from ghidra.program.model.listing import CodeUnit
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.util.task import TaskMonitor

    # Get output path from command line
    output_zip = sys.argv[1] if len(sys.argv) > 1 else "/tmp/binary_export.zip"

    # Get current program
    program = currentProgram
    if program is None:
        print(json.dumps({"error": "No program is currently open"}))
        sys.exit(1)

    # Get the original binary path from program
    executable_path = program.getExecutablePath()
    binary_name = program.getName()

    # Create temporary directory for export
    temp_dir = "/tmp/ghidra_export_" + str(os.getpid())
    os.makedirs(temp_dir, exist_ok=True)

    try:
        # 1. Copy original binary
        if os.path.exists(executable_path):
            shutil.copy(executable_path, os.path.join(temp_dir, binary_name))

        # 2. Export function list with renames
        listing = program.getListing()
        function_manager = program.getFunctionManager()
        decompiler = DecompInterface()
        options = DecompileOptions()
        decompiler.setOptions(options)
        decompiler.openProgram(program)

        functions_file = os.path.join(temp_dir, "functions.txt")
        with open(functions_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("FUNCTION MAPPINGS - Renamed Functions\n")
            f.write("=" * 80 + "\n\n")

            for function in function_manager.getFunctions(True):
                func_name = function.getName()
                func_addr = function.getEntryPoint().toString()

                # Only include renamed functions
                if not func_name.startswith("FUN_"):
                    f.write(f"{func_addr}: {func_name}\n")

        # 3. Export decompiled code for renamed functions
        decomp_file = os.path.join(temp_dir, "decompiled_code.c")
        with open(decomp_file, 'w') as f:
            f.write("/* Decompiled Code - Renamed Functions Only */\n\n")

            for function in function_manager.getFunctions(True):
                func_name = function.getName()

                if not func_name.startswith("FUN_"):
                    try:
                        result = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY)
                        if result and result.decompileCompleted():
                            decomp_code = result.getDecompiledFunction().getC()
                            f.write(f"\n{'=' * 80}\n")
                            f.write(f"// Function: {func_name}\n")
                            f.write(f"// Address: {function.getEntryPoint()}\n")
                            f.write(f"{'=' * 80}\n\n")
                            f.write(decomp_code)
                            f.write("\n\n")
                    except:
                        pass

        # 4. Export memory map
        memory_file = os.path.join(temp_dir, "memory_layout.txt")
        with open(memory_file, 'w') as f:
            f.write("MEMORY LAYOUT\n")
            f.write("=" * 80 + "\n\n")

            memory = program.getMemory()
            for block in memory.getBlocks():
                f.write(f"Segment: {block.getName()}\n")
                f.write(f"  Start: {block.getStart()}\n")
                f.write(f"  End: {block.getEnd()}\n")
                f.write(f"  Size: {block.getSize()} bytes\n")
                f.write(f"  Permissions: {'R' if block.isRead() else '-'}")
                f.write(f"{'W' if block.isWrite() else '-'}")
                f.write(f"{'X' if block.isExecute() else '-'}\n\n")

        # 5. Create README
        readme_file = os.path.join(temp_dir, "README.txt")
        with open(readme_file, 'w') as f:
            f.write(f"BINARY ANALYSIS EXPORT PACKAGE\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Binary: {binary_name}\n")
            f.write(f"Architecture: {program.getLanguage().getProcessor()}\n")
            f.write(f"Format: {program.getExecutableFormat()}\n\n")
            f.write("CONTENTS:\n\n")
            f.write(f"1. {binary_name} - Original unmodified binary\n")
            f.write("2. functions.txt - List of renamed functions with addresses\n")
            f.write("3. decompiled_code.c - C pseudocode for all renamed functions\n")
            f.write("4. memory_layout.txt - Memory segment information\n\n")
            f.write("NOTES:\n\n")
            f.write("- The binary file is UNCHANGED (Ghidra doesn't modify binaries)\n")
            f.write("- Function renames are Ghidra annotations, not binary modifications\n")
            f.write("- To apply renames, open the Ghidra project, not this binary\n")
            f.write("- The decompiled code shows how functions work with readable names\n")

        # 6. Create ZIP archive
        with ZipFile(output_zip, 'w') as zipf:
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zipf.write(file_path, arcname)

        # Cleanup
        shutil.rmtree(temp_dir)

        print(json.dumps({
            "success": True,
            "path": output_zip,
            "binary": binary_name
        }))

    except Exception as inner_e:
        # Cleanup on error
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        raise inner_e

except Exception as e:
    import traceback
    print(json.dumps({
        "error": str(e),
        "traceback": traceback.format_exc()
    }))
    sys.exit(1)
