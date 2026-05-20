# Decompile function script with configurable decompiler options (GB-1)
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript decompile.py <function_name_or_address>
# Book Reference: Ch. 19 (The Ghidra Decompiler, pp. 429-445)
#   - Eliminate Unreachable Code: filters dead code from output
#   - Simplify Predication: merges redundant if/else blocks
#   - Full "decompile" simplification style applies all reduction rules

import json
import sys

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

script_args = getScriptArgs()
if len(script_args) < 1:
    print(json.dumps({"error": "Function name or address required"}))
    sys.exit(1)

target = script_args[0]

# Try to find function by name or address
function = None
function_manager = program.getFunctionManager()

# Try as address first
try:
    from ghidra.program.model.address import GenericAddress
    addr = program.getAddressFactory().getAddress(target)
    function = function_manager.getFunctionAt(addr)
except:
    pass

# Try as function name
if function is None:
    for func in function_manager.getFunctions(True):
        if str(func.getName()) == target:
            function = func
            break

if function is None:
    print(json.dumps({"error": f"Function not found: {target}"}))
    sys.exit(1)

# Decompile with configured options
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor

decompiler = DecompInterface()

# GB-1: Configure decompiler options for cleaner LLM-consumable output
# DecompileOptions sets analysis behavior; grabFromProgram loads program-specific
# settings (calling conventions, pointer sizes, etc.)
options = DecompileOptions()
options.grabFromProgram(program)
decompiler.setOptions(options)

decompiler.openProgram(program)

# "decompile" style applies all simplification rules:
# - Eliminates unreachable code (dead branches, opaque predicates)
# - Simplifies predication (merges redundant conditionals)
# - Propagates constants and collapses redundant assignments
decompiler.setSimplificationStyle("decompile")

monitor = ConsoleTaskMonitor()

try:
    result = decompiler.decompileFunction(function, 30, monitor)

    if result.decompileCompleted():
        decompiled_code = result.getDecompiledFunction().getC()
        print(decompiled_code)
    else:
        print(json.dumps({"error": "Decompilation failed", "message": str(result.getErrorMessage())}))
finally:
    decompiler.dispose()
