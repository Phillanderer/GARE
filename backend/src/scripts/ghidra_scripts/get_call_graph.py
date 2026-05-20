# Enhanced call graph with bidirectional depth queries (GB-5)
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript get_call_graph.py <function_name> [depth]
# Book Reference: Ch. 10 (Graphs, pp. 9102-9242)
#   - Bidirectional queries: callers AND callees at configurable depth
#   - Thunk resolution to actual external function names
#   - Call cycle detection (mutual recursion)

import json
import sys

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

script_args = getScriptArgs()
if len(script_args) < 1:
    print(json.dumps({"error": "Usage: get_call_graph.py <function_name> [depth]"}))
    sys.exit(1)

function_name = script_args[0]
max_depth = 1  # Default: immediate callers/callees only (backward compatible)
if len(script_args) >= 2:
    try:
        max_depth = int(script_args[1])
        max_depth = min(max_depth, 5)  # Cap at 5 to prevent runaway
    except:
        max_depth = 1

function_manager = program.getFunctionManager()
ref_manager = program.getReferenceManager()

# Find function by name or address
target_func = None
try:
    addr = program.getAddressFactory().getAddress(function_name)
    target_func = function_manager.getFunctionAt(addr)
except:
    pass

if target_func is None:
    for func in function_manager.getFunctions(True):
        if str(func.getName()) == function_name:
            target_func = func
            break

if target_func is None:
    print(json.dumps({"error": "Function not found: " + function_name}))
    sys.exit(1)

try:
    entry_point = target_func.getEntryPoint()

    def resolve_thunk(func):
        """Resolve thunk functions to their actual target"""
        resolved = func
        depth = 0
        while resolved.isThunk() and depth < 5:
            thunked = resolved.getThunkedFunction(False)
            if thunked is None:
                break
            resolved = thunked
            depth += 1
        return resolved

    def get_func_info(func):
        """Get info dict for a function, resolving thunks"""
        is_thunk = func.isThunk()
        resolved = resolve_thunk(func) if is_thunk else func
        info = {
            "name": str(func.getName()),
            "address": str(func.getEntryPoint()),
            "is_thunk": is_thunk
        }
        if is_thunk and resolved != func:
            info["resolved_name"] = str(resolved.getName())
            info["resolved_address"] = str(resolved.getEntryPoint())
            # Check if it's an external function
            if resolved.isExternal():
                info["is_external"] = True
                parent_ns = resolved.getParentNamespace()
                if parent_ns and not parent_ns.isGlobal():
                    info["library"] = str(parent_ns.getName())
        return info

    def get_callees_recursive(func, depth, visited):
        """Get callees recursively up to max_depth"""
        func_key = str(func.getEntryPoint())
        if depth > max_depth or func_key in visited:
            return []
        visited.add(func_key)

        callees = []
        for called in func.getCalledFunctions(monitor):
            info = get_func_info(called)
            info["depth"] = depth
            if depth < max_depth:
                info["callees"] = get_callees_recursive(called, depth + 1, visited)
            callees.append(info)
        return callees

    def get_callers_recursive(func, depth, visited):
        """Get callers recursively up to max_depth"""
        func_key = str(func.getEntryPoint())
        if depth > max_depth or func_key in visited:
            return []
        visited.add(func_key)

        callers = []
        refs = ref_manager.getReferencesTo(func.getEntryPoint())
        seen = set()
        for ref in refs:
            from_addr = ref.getFromAddress()
            caller_func = function_manager.getFunctionContaining(from_addr)
            if caller_func is not None:
                caller_name = str(caller_func.getName())
                if caller_name not in seen:
                    seen.add(caller_name)
                    info = get_func_info(caller_func)
                    info["depth"] = depth
                    if depth < max_depth:
                        info["callers"] = get_callers_recursive(caller_func, depth + 1, visited)
                    callers.append(info)
        return callers

    # Build the call graph
    callee_visited = set()
    caller_visited = set()
    callees = get_callees_recursive(target_func, 1, callee_visited)
    callers = get_callers_recursive(target_func, 1, caller_visited)

    # Detect call cycles: functions that appear in both callers and callees
    callee_names = set()
    caller_names = set()

    def collect_names(items, name_set):
        for item in items:
            name_set.add(item["name"])
            if "callees" in item:
                collect_names(item["callees"], name_set)
            if "callers" in item:
                collect_names(item["callers"], name_set)

    collect_names(callees, callee_names)
    collect_names(callers, caller_names)
    cycles = sorted(list(callee_names & caller_names))

    # Count thunks
    thunk_count = sum(1 for c in callees if c.get("is_thunk"))

    result = {
        "function": str(target_func.getName()),
        "address": str(entry_point),
        "depth": max_depth,
        "callers": callers,
        "callees": callees,
        "caller_count": len(callers),
        "callee_count": len(callees),
        "thunk_callees": thunk_count,
        "call_cycles": cycles,
        "cycle_count": len(cycles)
    }
    print(json.dumps(result, indent=2))

except Exception as e:
    print(json.dumps({"error": str(e)}))
