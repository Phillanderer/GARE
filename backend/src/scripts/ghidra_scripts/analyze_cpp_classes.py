# Analyze C++ class hierarchy via vftable and RTTI detection (GB-10)
# Usage: analyzeHeadless <project> <name> -process <binary> -postScript analyze_cpp_classes.py
# Book Reference: Ch. 8 (Data Types, pp. 147-182 — vftable structure)
#   Ch. 20 (Compiler Variations, pp. 443-465 — RTTI differences)
#   - vftable pointer is always at offset 0 in polymorphic C++ objects
#   - Constructors write vftable address into this first field
#   - MSVC: RTTICompleteObjectLocator auto-detected by Ghidra
#   - g++/clang: type_info structures; stripped binaries need string-based RTTI hunting

import json
import sys

program = getCurrentProgram()
if program is None:
    print(json.dumps({"error": "No program loaded"}))
    sys.exit(1)

try:
    from ghidra.util.task import ConsoleTaskMonitor

    listing = program.getListing()
    function_manager = program.getFunctionManager()
    ref_manager = program.getReferenceManager()
    symbol_table = program.getSymbolTable()
    memory = program.getMemory()

    classes = []
    vftables = []
    rtti_strings = []

    # --- Method 1: Find vftable symbols ---
    # Ghidra labels vftables as "vftable", "vtable", or "__vt_" symbols
    symbol_iter = symbol_table.getAllSymbols(True)
    for symbol in symbol_iter:
        name = str(symbol.getName())
        if any(tag in name.lower() for tag in ("vftable", "vtable", "__vt_", "vft_")):
            addr = symbol.getAddress()
            parent_ns = str(symbol.getParentNamespace().getName())

            # Read vftable entries (pointers to virtual functions)
            vtable_entries = []
            entry_addr = addr
            pointer_size = program.getDefaultPointerSize()

            for i in range(50):  # Cap at 50 virtual functions
                try:
                    if pointer_size == 8:
                        ptr_val = memory.getLong(entry_addr)
                    else:
                        ptr_val = memory.getInt(entry_addr) & 0xFFFFFFFF

                    if ptr_val == 0:
                        break

                    target_addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(ptr_val)
                    target_func = function_manager.getFunctionAt(target_addr)

                    entry = {
                        "index": i,
                        "address": str(target_addr)
                    }
                    if target_func:
                        entry["function"] = str(target_func.getName())
                        entry["is_thunk"] = target_func.isThunk()

                    vtable_entries.append(entry)
                    entry_addr = entry_addr.add(pointer_size)
                except:
                    break

            vftable_info = {
                "symbol": name,
                "address": str(addr),
                "namespace": parent_ns if parent_ns != "Global" else None,
                "entry_count": len(vtable_entries),
                "entries": vtable_entries[:20]  # Cap output
            }
            vftables.append(vftable_info)

    # --- Method 2: Find constructors by vftable store pattern ---
    # Constructors store the vftable pointer at offset 0 of the object (this->vptr = &vtable)
    # Look for functions that store an address from .rodata/.data into offset 0 of their first param
    constructor_candidates = []

    for vft in vftables:
        vft_addr = program.getAddressFactory().getAddress(vft["address"])
        refs_to_vft = ref_manager.getReferencesTo(vft_addr)

        for ref in refs_to_vft:
            from_addr = ref.getFromAddress()
            func = function_manager.getFunctionContaining(from_addr)
            if func:
                func_name = str(func.getName())
                if func_name not in [c.get("function") for c in constructor_candidates]:
                    constructor_candidates.append({
                        "function": func_name,
                        "address": str(func.getEntryPoint()),
                        "references_vftable": vft["symbol"],
                        "likely_role": "constructor" if "init" in func_name.lower() or func_name.startswith("FUN_") else "method"
                    })

    # --- Method 3: RTTI string detection (g++ stripped binaries) ---
    # g++ RTTI encodes class names as length-prefixed strings: "8SubClass" = SubClass (8 chars)
    # Search for typeinfo name patterns in .rodata
    import re

    data_iter = listing.getDefinedData(True)
    for data in data_iter:
        if data.hasStringValue():
            val = str(data.getValue())
            # g++ RTTI pattern: digit(s) followed by class name
            # e.g., "8SubClass", "10BaseObject", "12DerivedClass"
            if re.match(r'^\d{1,3}[A-Z][a-zA-Z0-9_]+$', val):
                length_str = re.match(r'^(\d+)', val).group(1)
                class_name = val[len(length_str):]
                if int(length_str) == len(class_name):
                    rtti_strings.append({
                        "address": str(data.getAddress()),
                        "raw_string": val,
                        "class_name": class_name,
                        "name_length": int(length_str)
                    })

    # --- Method 4: Detect MSVC RTTI structures ---
    # Look for symbols containing "RTTI" or "type_info"
    msvc_rtti = []
    symbol_iter2 = symbol_table.getAllSymbols(True)
    for symbol in symbol_iter2:
        name = str(symbol.getName())
        if "RTTI" in name or "type_info" in name.lower() or "TypeDescriptor" in name:
            msvc_rtti.append({
                "symbol": name,
                "address": str(symbol.getAddress()),
                "namespace": str(symbol.getParentNamespace().getName())
            })

    # --- Build class hierarchy from vftable relationships ---
    # Classes with more vftable entries likely inherit from classes with fewer entries
    # (derived class extends base class vtable)
    class_map = {}
    for vft in vftables:
        ns = vft.get("namespace") or "unknown"
        if ns not in class_map:
            class_map[ns] = {
                "name": ns,
                "vftables": [],
                "virtual_function_count": 0,
                "constructors": [],
                "rtti": None
            }
        class_map[ns]["vftables"].append(vft)
        class_map[ns]["virtual_function_count"] = max(
            class_map[ns]["virtual_function_count"],
            vft["entry_count"]
        )

    # Associate constructors with classes
    for ctor in constructor_candidates:
        for ns, info in class_map.items():
            for vft in info["vftables"]:
                if ctor["references_vftable"] == vft["symbol"]:
                    info["constructors"].append(ctor)

    # Associate RTTI strings
    for rtti in rtti_strings:
        cn = rtti["class_name"]
        if cn in class_map:
            class_map[cn]["rtti"] = rtti

    classes = list(class_map.values())

    output = {
        "vftables_found": len(vftables),
        "classes_detected": len(classes),
        "constructor_candidates": len(constructor_candidates),
        "rtti_strings_found": len(rtti_strings),
        "msvc_rtti_symbols": len(msvc_rtti),
        "classes": classes[:30],  # Cap output
        "vftables": vftables[:20],
        "rtti_strings": rtti_strings[:20],
        "msvc_rtti": msvc_rtti[:20],
        "constructor_candidates": constructor_candidates[:20]
    }
    print(json.dumps(output, indent=2))

except Exception as e:
    print(json.dumps({"error": str(e)}))
