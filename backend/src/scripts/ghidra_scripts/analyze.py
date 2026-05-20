# Ghidra analysis script - outputs JSON metadata
# Run with: analyzeHeadless <project> <name> -process <binary> -postScript analyze.py

import json
import sys

# Get current program
program = getCurrentProgram()

if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

# Extract metadata
metadata = {
    "name": program.getName(),
    "executable_path": program.getExecutablePath(),
    "language": str(program.getLanguage()),
    "compiler": str(program.getCompilerSpec()),
    "executable_format": program.getExecutableFormat(),
    "executable_sha256": program.getExecutableSHA256(),
    "creation_date": str(program.getCreationDate()),
    "image_base": str(program.getImageBase()),
    "min_address": str(program.getMinAddress()),
    "max_address": str(program.getMaxAddress())
}

# Get entry points
entry_points = []
for addr in program.getSymbolTable().getExternalEntryPointIterator():
    # Iterator yields Address objects directly
    symbol = program.getSymbolTable().getPrimarySymbol(addr)
    entry_points.append({
        "address": str(addr),
        "name": str(symbol.getName()) if symbol else str(addr)
    })

metadata["entry_points"] = entry_points

# Count functions
function_manager = program.getFunctionManager()
metadata["function_count"] = function_manager.getFunctionCount()

# Get imports
imports = []
symbol_table = program.getSymbolTable()
for symbol in symbol_table.getExternalSymbols():
    imports.append({
        "name": str(symbol.getName()),
        "address": str(symbol.getAddress())
    })
metadata["imports_count"] = len(imports)

# Get exports (limited to 100)
exports = []
for symbol in symbol_table.getPrimarySymbolIterator(True):
    if symbol.isExternal() == False and symbol.isGlobal():
        exports.append({
            "name": str(symbol.getName()),
            "address": str(symbol.getAddress())
        })
        if len(exports) >= 100:
            break

metadata["exports_sample"] = exports

# Output JSON
output_json = json.dumps(metadata, indent=2)
print(output_json)

# Write to output file if path provided via script args
# PyGhidra sets sys.argv = [script_path] + script_args with Python strings
if len(sys.argv) > 1:
    output_path = sys.argv[1]
    try:
        with open(output_path, 'w') as out_f:
            out_f.write(output_json)
    except Exception as e:
        print("Warning: Could not write output file: " + str(e))
