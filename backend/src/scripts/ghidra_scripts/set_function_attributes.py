# Set function attributes: NoReturn, Varargs, calling convention (GB-12)
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript set_function_attributes.py <function_name> <attribute> [value]
# Book Reference: Ch. 7 (Disassembly Manipulation, pp. 137-139)
#   - NoReturn: prevents fallthrough analysis for exit(), abort(), longjmp()
#   - Varargs: marks variable-argument functions (printf, scanf family)
#   - Calling convention: override mis-detected conventions (cdecl, stdcall, fastcall, thiscall)

import json
import sys

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

script_args = getScriptArgs()
if len(script_args) < 2:
    print(json.dumps({"error": "Usage: set_function_attributes.py <function_name> <attribute> [value]"}))
    sys.exit(1)

target = script_args[0]
attribute = script_args[1]
value = script_args[2] if len(script_args) > 2 else "true"

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
    from ghidra.program.model.symbol import SourceType

    result = {
        "function": str(function.getName()),
        "address": str(function.getEntryPoint()),
        "attribute": attribute,
        "previous_value": None,
        "new_value": None,
        "success": False
    }

    tx_id = program.startTransaction("Set function attribute: " + attribute)
    try:
        if attribute == "noreturn":
            result["previous_value"] = function.hasNoReturn()
            set_val = value.lower() in ("true", "1", "yes")
            function.setNoReturn(set_val)
            result["new_value"] = set_val
            result["success"] = True

        elif attribute == "varargs":
            result["previous_value"] = function.hasVarArgs()
            set_val = value.lower() in ("true", "1", "yes")
            function.setVarArgs(set_val)
            result["new_value"] = set_val
            result["success"] = True

        elif attribute == "calling_convention":
            result["previous_value"] = str(function.getCallingConventionName())
            # Validate calling convention name
            valid_conventions = ["__cdecl", "__stdcall", "__fastcall", "__thiscall",
                                 "__vectorcall", "default", "unknown"]
            if value in valid_conventions or value.startswith("__"):
                function.setCallingConvention(value)
                result["new_value"] = value
                result["success"] = True
            else:
                result["error"] = "Invalid calling convention: " + value + ". Valid: " + ", ".join(valid_conventions)

        elif attribute == "inline":
            result["previous_value"] = function.isInline()
            set_val = value.lower() in ("true", "1", "yes")
            function.setInline(set_val)
            result["new_value"] = set_val
            result["success"] = True

        elif attribute == "custom_storage":
            result["previous_value"] = function.hasCustomVariableStorage()
            set_val = value.lower() in ("true", "1", "yes")
            function.setCustomVariableStorage(set_val)
            result["new_value"] = set_val
            result["success"] = True

        elif attribute == "get":
            # Read-only: return current attribute values
            result = {
                "function": str(function.getName()),
                "address": str(function.getEntryPoint()),
                "attributes": {
                    "noreturn": function.hasNoReturn(),
                    "varargs": function.hasVarArgs(),
                    "calling_convention": str(function.getCallingConventionName()),
                    "inline": function.isInline(),
                    "custom_storage": function.hasCustomVariableStorage(),
                    "thunk": function.isThunk(),
                    "external": function.isExternal(),
                    "parameter_count": function.getParameterCount(),
                    "stack_frame_size": function.getStackFrame().getFrameSize(),
                    "signature": str(function.getSignature())
                },
                "success": True
            }
        else:
            result["error"] = "Unknown attribute: " + attribute + ". Valid: noreturn, varargs, calling_convention, inline, custom_storage, get"

        program.endTransaction(tx_id, True)
    except Exception as e:
        program.endTransaction(tx_id, False)
        raise e

    print(json.dumps(result, indent=2))

except Exception as e:
    print(json.dumps({"error": str(e)}))
