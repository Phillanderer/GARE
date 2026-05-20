# Export function annotations (renamed functions, comments, decompiled code)
# Creates a human-readable text file with all annotations
# @category: Export

import sys
import json

try:
    from ghidra.program.model.listing import CodeUnit
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.util.task import TaskMonitor

    # Get output path from command line
    output_path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/annotations.txt"

    # Get current program
    program = currentProgram
    if program is None:
        print("ERROR: No program is currently open")
        sys.exit(1)

    listing = program.getListing()
    function_manager = program.getFunctionManager()

    # Initialize decompiler
    decompiler = DecompInterface()
    options = DecompileOptions()
    decompiler.setOptions(options)
    decompiler.openProgram(program)

    output_lines = []
    output_lines.append("=" * 80)
    output_lines.append("GHIDRA ANNOTATION EXPORT")
    output_lines.append(f"Binary: {program.getName()}")
    output_lines.append(f"Executable Format: {program.getExecutableFormat()}")
    output_lines.append(f"Processor: {program.getLanguage().getProcessor()}")
    output_lines.append("=" * 80)
    output_lines.append("")

    # Track statistics
    total_functions = 0
    renamed_functions = 0
    functions_with_comments = 0

    # Iterate through all functions
    for function in function_manager.getFunctions(True):
        total_functions += 1
        func_name = function.getName()
        func_addr = function.getEntryPoint().toString()

        # Check if function was renamed (doesn't start with FUN_)
        is_renamed = not func_name.startswith("FUN_")
        if is_renamed:
            renamed_functions += 1

        # Get function comments
        comment = function.getComment()
        plate_comment = listing.getComment(CodeUnit.PLATE_COMMENT, function.getEntryPoint())
        pre_comment = listing.getComment(CodeUnit.PRE_COMMENT, function.getEntryPoint())

        has_comments = comment or plate_comment or pre_comment
        if has_comments:
            functions_with_comments += 1

        # Only export if renamed or has comments
        if is_renamed or has_comments:
            output_lines.append("-" * 80)
            output_lines.append(f"Function: {func_name}")
            output_lines.append(f"Address: {func_addr}")

            if is_renamed:
                output_lines.append(f"[RENAMED]")

            if comment:
                output_lines.append(f"Comment: {comment}")
            if plate_comment:
                output_lines.append(f"Plate Comment: {plate_comment}")
            if pre_comment:
                output_lines.append(f"Pre Comment: {pre_comment}")

            # Decompile function
            try:
                result = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY)
                if result and result.decompileCompleted():
                    decomp_code = result.getDecompiledFunction().getC()
                    output_lines.append("")
                    output_lines.append("Decompiled Code:")
                    output_lines.append(decomp_code)
                else:
                    output_lines.append("[Decompilation failed]")
            except:
                output_lines.append("[Decompilation error]")

            output_lines.append("")

    # Add summary
    output_lines.append("=" * 80)
    output_lines.append("SUMMARY")
    output_lines.append(f"Total Functions: {total_functions}")
    output_lines.append(f"Renamed Functions: {renamed_functions}")
    output_lines.append(f"Functions with Comments: {functions_with_comments}")
    output_lines.append("=" * 80)

    # Write to file
    with open(output_path, 'w') as f:
        f.write('\n'.join(output_lines))

    print(json.dumps({
        "success": True,
        "path": output_path,
        "total_functions": total_functions,
        "renamed_functions": renamed_functions,
        "functions_with_comments": functions_with_comments
    }))

except Exception as e:
    import traceback
    print(json.dumps({
        "error": str(e),
        "traceback": traceback.format_exc()
    }))
    sys.exit(1)
