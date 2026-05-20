# Reconstruct import table from obfuscated binaries (GB-20)
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript reconstruct_imports.py
# Book Reference: Ch. 21 (Obfuscated Code Analysis, pp. 482-486)
#   - Packers hide the import table and reconstruct it at runtime
#   - Windows: LoadLibrary/GetProcAddress patterns
#   - Linux: dlopen/dlsym patterns
#   - Hash-based lookup: 4-byte hash comparison against API name database
#   - tElock packer: character-by-character comparison
#   - skape hash: ROR13+ADD rolling hash of API names

import json
import sys

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

try:
    listing = program.getListing()
    function_manager = program.getFunctionManager()
    ref_manager = program.getReferenceManager()
    memory = program.getMemory()

    results = {
        "dynamic_import_patterns": [],
        "hash_based_lookups": [],
        "string_based_lookups": [],
        "reconstructed_imports": [],
        "summary": {}
    }

    # --- Method 1: Find LoadLibrary/GetProcAddress call pairs (Windows) ---
    # Pattern: PUSH "kernel32.dll" / CALL LoadLibraryA / PUSH "FunctionName" / CALL GetProcAddress
    win_loader_funcs = ["LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
                        "GetModuleHandleA", "GetModuleHandleW"]
    win_resolver_funcs = ["GetProcAddress"]

    # --- Method 2: Find dlopen/dlsym call pairs (Linux) ---
    linux_loader_funcs = ["dlopen"]
    linux_resolver_funcs = ["dlsym"]

    all_loaders = win_loader_funcs + linux_loader_funcs
    all_resolvers = win_resolver_funcs + linux_resolver_funcs

    # Search for loader and resolver function references
    loader_calls = []
    resolver_calls = []

    for func in function_manager.getFunctions(True):
        func_name = str(func.getName())
        if func_name in all_loaders:
            refs = ref_manager.getReferencesTo(func.getEntryPoint())
            for ref in refs:
                if ref.getReferenceType().isCall():
                    caller_addr = ref.getFromAddress()
                    caller_func = function_manager.getFunctionContaining(caller_addr)
                    loader_calls.append({
                        "loader_function": func_name,
                        "called_from": str(caller_addr),
                        "caller_function": str(caller_func.getName()) if caller_func else None,
                        "platform": "windows" if func_name in win_loader_funcs else "linux"
                    })

        if func_name in all_resolvers:
            refs = ref_manager.getReferencesTo(func.getEntryPoint())
            for ref in refs:
                if ref.getReferenceType().isCall():
                    caller_addr = ref.getFromAddress()
                    caller_func = function_manager.getFunctionContaining(caller_addr)
                    resolver_calls.append({
                        "resolver_function": func_name,
                        "called_from": str(caller_addr),
                        "caller_function": str(caller_func.getName()) if caller_func else None,
                        "platform": "windows" if func_name in win_resolver_funcs else "linux"
                    })

    # Match loader/resolver pairs in the same function
    for resolver in resolver_calls:
        caller = resolver.get("caller_function")
        if caller:
            matching_loaders = [l for l in loader_calls if l.get("caller_function") == caller]
            if matching_loaders:
                results["dynamic_import_patterns"].append({
                    "function": caller,
                    "loader": matching_loaders[0]["loader_function"],
                    "loader_addr": matching_loaders[0]["called_from"],
                    "resolver": resolver["resolver_function"],
                    "resolver_addr": resolver["called_from"],
                    "platform": resolver["platform"],
                    "pattern": "dynamic_import_resolution"
                })

    # --- Method 3: Scan for string-based API lookups ---
    # Look for strings that match known API names near loader/resolver calls
    known_api_prefixes = [
        "Create", "Open", "Close", "Read", "Write", "Delete", "Find",
        "Get", "Set", "Reg", "Virtual", "Heap", "Process", "Thread",
        "Socket", "Connect", "Send", "Recv", "WSA", "Crypt", "Http",
        "Internet", "Shell", "Nt", "Zw", "Rtl"
    ]

    api_strings_found = []
    data_iter = listing.getDefinedData(True)
    for data in data_iter:
        if data.hasStringValue():
            val = str(data.getValue())
            # Check if string looks like an API name
            if (any(val.startswith(p) for p in known_api_prefixes) and
                len(val) > 4 and len(val) < 100 and
                not " " in val and val[0].isupper()):

                # Check if this string is referenced from code
                refs = ref_manager.getReferencesTo(data.getAddress())
                for ref in refs:
                    from_func = function_manager.getFunctionContaining(ref.getFromAddress())
                    if from_func:
                        api_strings_found.append({
                            "api_name": val,
                            "string_address": str(data.getAddress()),
                            "referenced_from": str(ref.getFromAddress()),
                            "in_function": str(from_func.getName())
                        })
                        break

    results["string_based_lookups"] = api_strings_found[:50]

    # --- Method 4: Detect hash-based API resolution ---
    # Common hash algorithms use constants:
    # - ROR13+ADD (skape hash): rotate right 13, add character
    # - CRC32-based: XOR with 0xEDB88320
    # - djb2: multiply by 33, add character
    HASH_CONSTANTS = {
        0xEDB88320: "CRC32",
        0x5D588B65: "skape_hash",
        0x21: "djb2_multiply_33",
        0x1505: "djb2_init_5381",
        0xD: "ROR13_shift"
    }

    hash_patterns = []
    for func in function_manager.getFunctions(True):
        func_body = func.getBody()
        instr_iter = listing.getInstructions(func_body, True)

        func_constants = set()
        has_loop = False
        has_comparison = False
        instr_count = 0

        while instr_iter.hasNext() and instr_count < 500:
            instr = instr_iter.next()
            instr_count += 1
            mnemonic = str(instr.getMnemonicString()).upper()

            # Track constants used
            for i in range(instr.getNumOperands()):
                try:
                    scalar = instr.getScalar(i)
                    if scalar is not None:
                        val = int(scalar.getValue()) & 0xFFFFFFFF
                        if val in HASH_CONSTANTS:
                            func_constants.add(val)
                except:
                    pass

            # Check for loop indicators
            if mnemonic in ("LOOP", "LOOPE", "LOOPNE"):
                has_loop = True
            if mnemonic in ("ROR", "ROL", "SHR", "SHL") and "13" in str(instr):
                func_constants.add(0xD)

            # Check for comparison (hash matching)
            if mnemonic == "CMP":
                has_comparison = True

        if func_constants:
            hash_type = None
            for const in func_constants:
                if const in HASH_CONSTANTS:
                    hash_type = HASH_CONSTANTS[const]
                    break

            hash_patterns.append({
                "function": str(func.getName()),
                "address": str(func.getEntryPoint()),
                "hash_constants": [hex(c) for c in func_constants],
                "suspected_algorithm": hash_type,
                "has_loop": has_loop,
                "has_comparison": has_comparison,
                "confidence": "high" if has_loop and has_comparison else "medium"
            })

    results["hash_based_lookups"] = hash_patterns[:20]

    # --- Build reconstructed import list ---
    for pattern in results["dynamic_import_patterns"]:
        results["reconstructed_imports"].append({
            "source": "dynamic_load",
            "function": pattern["function"],
            "platform": pattern["platform"]
        })

    for api_str in api_strings_found:
        results["reconstructed_imports"].append({
            "source": "string_reference",
            "api_name": api_str["api_name"],
            "referenced_in": api_str["in_function"]
        })

    # Summary
    results["summary"] = {
        "dynamic_import_patterns": len(results["dynamic_import_patterns"]),
        "hash_based_lookups": len(results["hash_based_lookups"]),
        "api_strings_found": len(api_strings_found),
        "total_reconstructed": len(results["reconstructed_imports"]),
        "platforms_detected": list(set(p["platform"] for p in results["dynamic_import_patterns"])) if results["dynamic_import_patterns"] else []
    }

    print(json.dumps(results, indent=2))

except Exception as e:
    print(json.dumps({"error": str(e)}))
