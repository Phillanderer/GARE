# Ghidra Book Reference — Capabilities Influenced by Eagle & Nance (2020)

**Source:** Chris Eagle and Kara Nance, *The Ghidra Book: The Definitive Guide*, No Starch Press, 2020.

**Purpose:** This document tracks GARE pipeline capabilities that were added or changed by direct influence from "The Ghidra Book." It serves as a living reference for mapping book concepts to implementation decisions, tracking incremental adoption, and measuring their impact on analysis quality. All planned enhancements will be implemented incrementally and their status updated here.

**Status Key:** IMPLEMENTED = live in codebase | PLANNED = identified, not yet built | IN PROGRESS = actively being developed

---

## Book Summary

"The Ghidra Book" is a comprehensive 23-chapter guide organized into five parts covering the full scope of Ghidra's reverse engineering capabilities:

- **Part I (Ch. 1-4):** Introduction to RE, Ghidra basics, project setup
- **Part II (Ch. 5-11):** Disassembly analysis, manipulation, annotations, data types, cross-references, graphs, collaborative SRE
- **Part III (Ch. 12-13):** Tool customization, extending Ghidra
- **Part IV (Ch. 14-18):** Scripting, analyzers, headless mode, loaders, processors
- **Part V (Ch. 19-23):** Decompiler, compiler variations, obfuscated code, binary patching, version tracking

The chapters most relevant to GARE's automated pipeline are: 6 (stack frames), 7 (annotations/manipulation), 8 (data types), 9 (cross-references), 10 (graphs), 14 (scripting), 16 (headless mode), 19 (decompiler), 20 (compiler variations), and 21 (obfuscated code).

---

## Existing Capabilities Aligned with Book Concepts

The following GARE capabilities existed prior to this book review but directly implement techniques documented in the book. These mappings serve as reference for understanding the conceptual foundation of each tool.

### EC-1: Decompilation via DecompInterface

**Status:** IMPLEMENTED
**Book Chapter:** 19 (The Ghidra Decompiler, pp. 427-441)
**Files:**
- `backend/src/scripts/ghidra_scripts/decompile.py`
- `backend/src/services/agent/llm_agent.py` (tools: `decompile_function`, `decompile_function_by_address`)

**Book Alignment:**
Chapter 19 documents the `DecompInterface` API for programmatic decompilation, including `decompileFunction()` and `getDecompiledFunction().getC()`. GARE's `decompile.py` script uses exactly this API pattern to produce C pseudocode consumed by the LLM agent.

---

### EC-2: Cross-Reference Analysis

**Status:** IMPLEMENTED
**Book Chapter:** 9 (Cross-References, pp. 183-196)
**Files:**
- `backend/src/scripts/ghidra_scripts/get_xrefs.py`
- `backend/src/services/agent/llm_agent.py` (tools: `get_function_xrefs`, `get_xrefs_from`)

**Book Alignment:**
Chapter 9 describes code and data cross-references, reference types (Read/Write/Pointer), and the `ReferenceManager` API. GARE's xref tools use `getReferencesTo()` and `getReferencesFrom()` as documented in the book, returning reference addresses and types.

---

### EC-3: Function Call Graph

**Status:** IMPLEMENTED
**Book Chapter:** 10 (Graphs, pp. 197-214)
**Files:**
- `backend/src/scripts/ghidra_scripts/get_call_graph.py`
- `backend/src/services/agent/llm_agent.py` (tool: `get_call_graph`)

**Book Alignment:**
Chapter 10 documents call graphs (pp. 9102-9242) where nodes represent entire functions and edges represent call cross-references. GARE's `get_call_graph.py` uses `getCalledFunctions()` and `getReferencesTo()` to build caller/callee relationships, matching the book's described API patterns.

---

### EC-4: Data Type Listing and Application

**Status:** IMPLEMENTED
**Book Chapter:** 8 (Data Types and Data Structures, pp. 147-182)
**Files:**
- `backend/src/scripts/ghidra_scripts/list_data_types.py`
- `backend/src/scripts/ghidra_scripts/apply_data_type.py`
- `backend/src/services/agent/llm_agent.py` (tools: `list_data_types`, `apply_data_type`)

**Book Alignment:**
Chapter 8 covers the Data Type Manager, structure definitions, and type application via the API. GARE's tools use `getDataTypeManager()`, `getAllDataTypes()`, and `setDataType()` with `SourceType.USER_DEFINED` as documented. The book's guidance on applying known structure layouts (pp. 7442-7464) maps to GARE's `apply_data_type` tool.

---

### EC-5: Comment Placement (Plate Comments)

**Status:** IMPLEMENTED
**Book Chapter:** 7 (Disassembly Manipulation, pp. 128-132)
**Files:**
- `backend/src/scripts/ghidra_scripts/set_comment.py`
- `backend/src/services/agent/llm_agent.py` (tool: `set_decompiler_comment`)

**Book Alignment:**
Chapter 7 describes comment types including Plate Comments (pp. 130-131), which appear as bordered blocks visible in both the Listing and Decompiler windows. GARE's `set_comment.py` uses `CodeUnit.PLATE_COMMENT` as documented, placing comments that survive decompilation views.

---

### EC-6: Function Renaming and Symbol Management

**Status:** IMPLEMENTED
**Book Chapter:** 7 (Disassembly Manipulation, pp. 137-139)
**Files:**
- `backend/src/scripts/ghidra_scripts/rename.py`
- `backend/src/services/agent/llm_agent.py` (tool: `rename_function`)

**Book Alignment:**
Chapter 7 documents function attribute editing including name changes via the `Function.setName()` API with `SourceType.USER_DEFINED`. GARE's `rename.py` implements this pattern with the added convention of a `VIBE_` prefix for agent-applied names.

---

### EC-7: Memory Segment Listing

**Status:** IMPLEMENTED
**Book Chapter:** 6 (Making Sense of a Ghidra Disassembly, pp. 93-117)
**Files:**
- `backend/src/scripts/ghidra_scripts/list_segments.py`
- `backend/src/services/agent/llm_agent.py` (tool: `list_segments`)

**Book Alignment:**
Chapter 6 covers memory layout and segment permissions (R/W/X). GARE's `list_segments.py` uses `getMemory().getBlocks()` with `isRead()`, `isWrite()`, `isExecute()` as described in the book's memory analysis sections.

---

### EC-8: Entropy-Based Packing Detection

**Status:** IMPLEMENTED
**Book Chapter:** 21 (Obfuscated Code Analysis, pp. 469-501)
**Files:**
- `backend/src/scripts/ghidra_scripts/get_entropy.py`
- `backend/src/services/agent/llm_agent.py` (tool: `get_entropy`)

**Book Alignment:**
Chapter 21 discusses opcode obfuscation and encoding (pp. 478-480), where encrypted/encoded sections appear as high-entropy data. GARE's `get_entropy.py` computes per-section Shannon entropy, flagging sections >7.0 as potentially packed — a direct application of the detection heuristic the book describes.

---

### EC-9: Library and Thunk Function Identification

**Status:** IMPLEMENTED
**Book Chapter:** 10 (Graphs, pp. 9183-9230 — Thunk Functions)
**Files:**
- `backend/src/scripts/ghidra_scripts/identify_libraries.py`
- `backend/src/services/agent/llm_agent.py` (tool: `identify_libraries`)

**Book Alignment:**
Chapter 10 describes thunk functions as compiler stubs for external/dynamic library calls that resolve via GOT/Import Table. GARE's `identify_libraries.py` uses `isThunk()`, `isExternal()`, and `isLibrary()` to classify functions, allowing the agent to focus analysis on user code rather than library wrappers.

---

### EC-10: Disassembly Inspection

**Status:** IMPLEMENTED
**Book Chapter:** 6 (Making Sense of a Ghidra Disassembly, pp. 93-117)
**Files:**
- `backend/src/scripts/ghidra_scripts/disassemble.py`
- `backend/src/services/agent/llm_agent.py` (tool: `disassemble_function`)

**Book Alignment:**
Chapter 6 provides the foundation for understanding Ghidra disassembly output — instruction mnemonics, operand representations, and EOL comments. GARE's `disassemble.py` uses `getListing().getInstructions()` with `getMnemonicString()` and `getDefaultOperandRepresentation()` to expose raw assembly alongside decompilation.

---

### EC-11: Import and Export Symbol Analysis

**Status:** IMPLEMENTED
**Book Chapters:** 6, 9 (Symbols, Cross-References)
**Files:**
- `backend/src/scripts/ghidra_scripts/get_imports_exports.py`
- `backend/src/services/agent/llm_agent.py` (tools: `list_imports`, `list_exports`)

**Book Alignment:**
Chapters 6 and 9 document the Symbol Table and external references. GARE's script uses `getSymbolTable().getExternalSymbols()` and `getPrimarySymbolIterator()` as documented, providing the import/export data that feeds into MITRE ATT&CK mapping.

---

### EC-12: String Extraction

**Status:** IMPLEMENTED
**Book Chapter:** 7 (Disassembly Manipulation, pp. 142-144 — String Detection)
**Files:**
- `backend/src/scripts/ghidra_scripts/get_strings.py`
- `backend/src/services/agent/llm_agent.py` (tool: `list_strings`)

**Book Alignment:**
Chapter 7 documents Ghidra's string detection capabilities including the Search > For Strings feature with word models. GARE's `get_strings.py` uses `getListing().getDefinedData()` with `hasStringValue()` to extract all defined strings from the binary.

---

### EC-13: Headless Script Execution via PyGhidra

**Status:** IMPLEMENTED
**Book Chapter:** 16 (Ghidra in Headless Mode, pp. 341-360)
**Files:**
- `backend/src/services/worker/ghidra_runner.py`
- `backend/Dockerfile`

**Book Alignment:**
Chapter 16 documents `analyzeHeadless` and headless script execution patterns. GARE's worker uses PyGhidra (Python-native bridge) rather than the Java `analyzeHeadless` CLI, but follows the same conceptual model: import binary, run auto-analysis, execute post-analysis scripts, capture output. The book's `-scriptPath` and `-postScript` concepts map to GARE's `ALLOWED_SCRIPTS` whitelist and script execution pipeline.

---

### EC-14: Export and Annotation Persistence

**Status:** IMPLEMENTED
**Book Chapter:** 11 (Collaborative SRE, pp. 217-240 — Project Management)
**Files:**
- `backend/src/scripts/ghidra_scripts/export_annotations.py`
- `backend/src/scripts/ghidra_scripts/export_binary_package.py`
- `backend/src/scripts/ghidra_scripts/export_xml.py`

**Book Alignment:**
Chapter 11 discusses project archiving and sharing analysis artifacts. GARE's export scripts produce human-readable annotation files, ZIP packages, and XML exports, enabling analysis results to persist beyond the Ghidra session — a key concern the book addresses in its collaborative SRE workflow.

---

## Planned Enhancements

The following enhancements are identified from the book scan and will be implemented incrementally. Each entry includes the book source, rationale, and implementation approach.

### Priority 1 — High Impact

---

#### GB-1: Decompiler Configuration Control

**Status:** IMPLEMENTED
**Date Completed:** 2026-02-10
**Book Chapter:** 19 (The Ghidra Decompiler, pp. 429-445)
**Files Modified:** `ghidra_scripts/decompile.py`, `ghidra_scripts/get_function_signature.py`

**What Will Change:**
Expose decompiler analysis options programmatically in `DecompInterface` calls:
- `Eliminate Unreachable Code` — filter dead code from decompilation output
- `Simplify Predication` — merge redundant if/else blocks sharing conditions

**Book Rationale:**
Chapter 19 documents these as configurable decompiler options that reduce noise in output. Unreachable code appears after obfuscation and conditional jumps over data. Simplifying predication reduces visual complexity for pattern recognition.

**Efficiency Impact:**
Cleaner decompiled output means the LLM spends fewer tokens parsing noise and fewer iterations asking "what does this dead code do?" Particularly impactful on obfuscated binaries.

---

#### GB-2: Automatic Structure Creation from Offset Patterns

**Status:** IMPLEMENTED
**Date Completed:** 2026-02-10
**Book Chapter:** 19 (The Ghidra Decompiler, pp. 437-441)
**Files Added/Modified:** `ghidra_scripts/auto_create_structure.py` (new), `ghidra_runner.py`, `control_plane.py`, `tools.py`, `llm_agent.py`

**What Will Change:**
Add MCP tool to auto-create struct definitions when the decompiler shows raw pointer arithmetic patterns like `*(undefined4 *)(ptr + 0x10)`. Ghidra's "Auto Create Structure" feature detects offset patterns and generates proper struct types.

**Book Rationale:**
Chapter 19 shows that raw pointer arithmetic in decompiled output indicates unrecognized structures. Auto-creating structures dramatically improves readability — transforming `*(ptr + 0x10)` into `ptr->field_0x10` or `ptr->socket_fd`.

**Efficiency Impact:**
The agent currently wastes iterations interpreting pointer arithmetic manually. Structured types let the LLM immediately understand data access patterns.

---

#### GB-3: Variable Slicing for Data Flow Analysis

**Status:** IMPLEMENTED
**Date Completed:** 2026-02-10
**Book Chapter:** 19 (The Ghidra Decompiler, pp. 670-691)
**Files Added/Modified:** `ghidra_scripts/get_variable_slice.py` (new), `ghidra_runner.py`, `control_plane.py`, `tools.py`, `llm_agent.py`

**What Will Change:**
Add MCP tool: `get_variable_slice(function, variable_name, direction)` returning all statements that affect (backward) or are affected by (forward) a given variable. Uses Ghidra's Def-Use analysis from the decompiler's `HighFunction`.

**Book Rationale:**
Chapter 19 documents forward and backward slicing as built-in decompiler capabilities. For vulnerability analysis, the question "I control this input — where does it flow?" requires forward slicing, while "what influences this output?" requires backward slicing.

**Efficiency Impact:**
Currently the agent must manually trace variable assignments through decompiled code across multiple tool calls. A single slice query returns the complete dependency chain.

---

#### GB-4: Basic Block and Control Flow Graph Analysis

**Status:** IMPLEMENTED
**Date Completed:** 2026-02-10
**Book Chapter:** 10 (Graphs, pp. 8708-8728)
**Files Added/Modified:** `ghidra_scripts/analyze_basic_blocks.py` (new), `ghidra_runner.py`, `control_plane.py`, `tools.py`, `llm_agent.py`

**What Will Change:**
Add MCP tool: `analyze_basic_blocks(function_name)` returning structured CFG data:
- Basic blocks with start/end addresses, instruction count
- Successor/predecessor relationships
- Edge types (sequential, jump-true, jump-false, fallthrough)
- Back edges indicating loops
- Dominator information

**Book Rationale:**
Chapter 10 defines basic blocks as sequences of instructions with single entry/exit points, guaranteed to complete once entered. The book describes CFGs as the foundation for all advanced static analysis — loop detection, path enumeration, and code coverage.

**Efficiency Impact:**
Enables the agent to reason about control flow structurally rather than reading through linear decompiled code. Loop detection, branch analysis, and unreachable code identification become single-query operations.

---

#### GB-5: Enhanced Call Graph with Bidirectional Queries

**Status:** IMPLEMENTED
**Date Completed:** 2026-02-10
**Book Chapter:** 10 (Graphs, pp. 9102-9242)
**Files Modified:** `ghidra_scripts/get_call_graph.py`, `control_plane.py`, `tools.py`, `llm_agent.py`

**What Will Change:**
Enhance existing `get_call_graph()` to support:
- Configurable depth for callers AND callees (currently returns immediate neighbors only)
- Call cycle detection (mutual recursion)
- Thunk resolution to actual external function names
- Call type classification (direct, indirect, virtual)
- Stack frame size per node (for stack overflow analysis)

**Book Rationale:**
Chapter 10 describes expandable call graph nodes, thunk function handling, and multi-level graph exploration. The current implementation returns only immediate callers/callees, limiting the agent's ability to trace deep call chains for vulnerability analysis.

**Efficiency Impact:**
The agent currently needs multiple iterations to trace a call chain (get_call_graph for A, then for B, then for C). A depth parameter reduces this to one call.

---

#### GB-6: Switch Statement Detection

**Status:** IMPLEMENTED
**Date Completed:** 2026-02-10
**Book Chapter:** 20 (Compiler Variations, pp. 444-451)
**Files Added/Modified:** `ghidra_scripts/detect_switch.py` (new), `ghidra_runner.py`, `control_plane.py`, `tools.py`, `llm_agent.py`

**What Will Change:**
Add MCP tool: `detect_switch_implementation(address)` returning:
- Switch type: jump table (dense) vs. binary search (sparse) vs. hybrid
- Jump table location (`.rodata` for gcc, `.text` for MSVC)
- Case value ranges and density percentage
- Number of cases

Also update agent system prompt with compiler variation guidance for switch patterns.

**Book Rationale:**
Chapter 20 documents how compilers implement switch statements differently depending on case density. Low-density switches (<10%) become nested if/else (binary search), which the decompiler may fail to recognize as a switch. The agent needs to know this to avoid misinterpreting binary search trees as complex conditional logic.

**Efficiency Impact:**
Without this knowledge, the agent wastes iterations analyzing what appears to be complex nested conditionals but is actually a simple switch statement.

---

#### GB-7: Compiler Variation Awareness in Agent Prompt

**Status:** IMPLEMENTED
**Date Completed:** 2026-02-10
**Book Chapter:** 20 (Compiler Variations, pp. 443-465)
**Files Modified:** `backend/src/services/agent/prompts.py`

**What Will Change:**
Add a `COMPILER_VARIATION_REFERENCE` block to the system prompt covering:
- Switch implementation patterns (jump table vs. binary search, Ch. 20 pp. 444-451)
- Modulo operation via multiplicative inverse — magic constant `0x66666667` = mod 10 (Ch. 20 pp. 454-455)
- Ternary operator variations: CMOV (gcc O2), SBB/SETNZ+NEG (MSVC) (Ch. 20 pp. 610-648)
- Function inlining: optimized builds may inline small functions, reducing visible function count (Ch. 20 pp. 654-738)
- C++ RTTI differences: Microsoft auto-detected vs. g++ requiring manual string-based hunting (Ch. 20 pp. 791-958)

**Book Rationale:**
Chapter 20 is dedicated to compiler-specific patterns that affect decompiler output. Without this context, the LLM misinterprets optimized arithmetic sequences, fails to recognize inlined functions, and doesn't understand why switch statements appear as if/else chains.

**Efficiency Impact:**
Reduces incorrect analysis of optimized code. The agent stops wasting iterations on "what is this complex arithmetic?" when it's simply `x % 10` compiled with optimization.

---

### Priority 2 — Significant Enhancement

---

#### GB-8: Three-Type Cross-Reference Classification

**Status:** IMPLEMENTED
**Date Completed:** 2026-02-10
**Book Chapter:** 9 (Cross-References, pp. 8388-8435)
**Files Modified:** `ghidra_scripts/get_xrefs.py`

**What Will Change:**
Extend xref output to classify each reference as:
1. **Read (R)** — data location contents are read
2. **Write (W)** — data location is written to
3. **Pointer (*)** — address of location is taken

**Book Rationale:**
Chapter 9 defines these three reference types as fundamental to data flow analysis. Write xrefs to stack buffers indicate potential buffer overflows. Read-then-Write chains reveal data transformations. Pointer references identify string literals and function pointers.

**Efficiency Impact:**
Currently xrefs are undifferentiated — the agent sees "reference exists" but not whether data is read, written, or addressed. Classification enables targeted vulnerability detection without decompiling every referencing function.

---

#### GB-9: Array Detection from Scaling Operations

**Status:** IMPLEMENTED
**Date Completed:** 2026-02-10
**Book Chapter:** 8 (Data Types and Data Structures, pp. 6314-6523)
**Files Added/Modified:** `ghidra_scripts/detect_arrays.py` (new), `ghidra_runner.py`, `control_plane.py`, `tools.py`, `llm_agent.py`

**What Will Change:**
Add MCP tool: `detect_array_from_scaling(address)` that:
- Identifies variable index multiplication patterns (`RAX*4`, `RAX*24`)
- Computes array element size from scale factors
- Converts global data marked as separate variables into properly typed arrays
- Handles all allocation types: global, stack, and heap arrays

**Book Rationale:**
Chapter 8 documents how arrays are distinguished from structures via scaling operations in index calculations. A scale factor of 4 indicates 4-byte elements (int array), while 24 indicates 24-byte elements (array of structs). Without this detection, Ghidra shows arrays as sequences of individual variables.

**Efficiency Impact:**
The agent currently sees `DAT_00401000`, `DAT_00401004`, `DAT_00401008` as separate globals when they're actually `int array[3]`. Proper array recognition dramatically simplifies data structure analysis.

---

#### GB-10: C++ Virtual Function Table Analysis

**Status:** IMPLEMENTED
**Date Completed:** 2026-02-10
**Book Chapter:** 8 (Data Types, pp. 7548-7724); 20 (Compiler Variations, pp. 791-958)
**Files Added/Modified:** `ghidra_scripts/analyze_cpp_classes.py` (new), `ghidra_runner.py`, `control_plane.py`, `tools.py`, `llm_agent.py`

**What Will Change:**
Add MCP tool: `analyze_cpp_classes()` that:
- Auto-detects vftable pointers (always first field in polymorphic C++ classes)
- Identifies constructors/destructors via vftable references
- Extracts class inheritance hierarchy by comparing vftable entries
- Parses RTTI structures (Microsoft: `RTTICompleteObjectLocator`; GNU: `type_info`)
- For stripped g++ binaries: hunts RTTI via mangled class name strings (e.g., "8SubClass")

**Book Rationale:**
Chapter 8 documents vftable structure at offset 0 in classes with virtual functions. Chapter 20 details compiler-specific RTTI formats. Together they provide a complete methodology for recovering C++ class hierarchies from stripped binaries.

**Efficiency Impact:**
C++ malware often uses polymorphism for command dispatch. Without vftable analysis, the agent sees indirect calls (`CALL [EAX]`) with no way to determine the target. vftable resolution converts these into named virtual function calls.

---

#### GB-11: Headless Mode Optimization

**Status:** IMPLEMENTED
**Date Completed:** 2026-02-10
**Book Chapter:** 16 (Ghidra in Headless Mode, pp. 341-360)
**Files Added/Modified:** `worker/analysis_config.py` (new), `worker/ghidra_runner.py`, `worker/control_plane.py`

**What Will Change:**
Map GARE intensity presets to headless mode parameters:
- **Quick**: `-analysisTimeoutPerFile 30` + `-max-cpu 1`
- **Standard**: `-analysisTimeoutPerFile 120` + `-max-cpu 2`
- **Deep**: `-analysisTimeoutPerFile 600` + `-max-cpu 4`

Also implement:
- `-readOnly` mode for stateless analysis (reduces disk I/O)
- `-log` option for structured error parsing
- Environment variable-based `-scriptPath` for deployment portability

**Book Rationale:**
Chapter 16 documents `-analysisTimeoutPerFile` (p. 350) to prevent runaway analysis, `-max-cpu` (p. 347) for resource limiting, and `-readOnly` (p. 348) for stateless execution. GARE's current PyGhidra invocation uses none of these controls.

**Efficiency Impact:**
Prevents pathological binaries from blocking the analysis queue. CPU limiting enables predictable container resource usage. Estimated 10-15% throughput improvement from reduced disk I/O with `-readOnly`.

---

#### GB-12: Function Attribute Detection and Application

**Status:** IMPLEMENTED
**Date Completed:** 2026-02-10
**Book Chapter:** 7 (Disassembly Manipulation, pp. 137-139)
**Files Added/Modified:** `ghidra_scripts/set_function_attributes.py` (new), `ghidra_runner.py`, `control_plane.py`, `tools.py`, `llm_agent.py`

**What Will Change:**
Add MCP tool: `define_function_attributes(function_name, attributes)` supporting:
- `NoReturn` flag — prevents fallthrough analysis (critical for `exit()`, `abort()`, `longjmp()`)
- `Varargs` flag — marks variable-argument functions (`printf`, `scanf` family)
- Calling convention override — correct mis-detected conventions
- `UseCustomStorage` — override parameter/return locations for non-standard ABIs

**Book Rationale:**
Chapter 7 documents these as editable function attributes in Ghidra's Edit Function dialog. The `NoReturn` flag is particularly important — without it, Ghidra assumes bytes after a call to a no-return function are reachable, leading to disassembly errors. `Varargs` affects parameter count analysis.

**Efficiency Impact:**
The agent currently can only rename functions. Setting `NoReturn` on functions like custom `die()` or `fatal_error()` prevents cascading disassembly errors that waste analysis iterations.

---

#### GB-13: Repeatable Comments for Pattern Documentation

**Status:** IMPLEMENTED
**Date Completed:** 2026-02-10
**Book Chapter:** 7 (Disassembly Manipulation, pp. 131-132)
**Files Added/Modified:** `ghidra_scripts/set_repeatable_comment.py` (new), `ghidra_runner.py`, `control_plane.py`, `tools.py`, `llm_agent.py`

**What Will Change:**
Add MCP tool: `set_repeatable_comment(address, comment)` using `CodeUnit.REPEATABLE_COMMENT`. Repeatable comments auto-propagate to all cross-reference sources, so a comment at a function's entry point appears at every call site.

**Book Rationale:**
Chapter 7 explains that repeatable comments are tied to cross-references — a comment at the target of an xref echoes at every source. This is ideal for documenting API behavior, security-critical functions, and architectural patterns that analysts need to see at every call site.

**Efficiency Impact:**
Currently the agent can only place plate comments at specific addresses. Repeatable comments let the agent document once and have that documentation appear everywhere the function is called — reducing redundant annotation iterations.

---

#### GB-14: Named Constant Application (Equates)

**Status:** IMPLEMENTED
**Date Completed:** 2026-02-10
**Book Chapter:** 7 (Disassembly Manipulation, pp. 135-136)
**Files Added/Modified:** `ghidra_scripts/set_equate.py` (new), `ghidra_runner.py`, `control_plane.py`, `tools.py`, `llm_agent.py`

**What Will Change:**
Add MCP tool: `set_equate(address, operand_index, equate_name)` that applies Ghidra's built-in named constant library to instruction operands. Example: `0xa` at a socket call becomes `AF_INET`; `0x2` becomes `SOCK_STREAM`.

**Book Rationale:**
Chapter 7 documents the Set Equate dialog (p. 135-136) and Ghidra's internal catalog of named constants from common libraries (C standard library, Windows API, POSIX). These transform opaque hex values into meaningful identifiers without changing the underlying bytes.

**Efficiency Impact:**
The LLM currently must infer constant meanings from context (e.g., "0x2 passed to socket() is probably SOCK_STREAM"). Named equates make this explicit in the disassembly, saving reasoning steps.

---

#### GB-15: Code/Data Boundary Repair

**Status:** IMPLEMENTED
**Date Completed:** 2026-02-10
**Book Chapter:** 7 (Disassembly Manipulation, pp. 139-145)
**Files Added/Modified:** `ghidra_scripts/convert_code_data.py` (new), `ghidra_runner.py`, `control_plane.py`, `tools.py`, `llm_agent.py`

**What Will Change:**
Add MCP tools:
- `convert_data_to_code(address)` — undefine bytes and disassemble from target address
- `convert_code_to_data(address, data_type, count)` — define code bytes as data (arrays, strings, structs)

**Book Rationale:**
Chapter 7 documents that auto-analysis sometimes misclassifies code as data (missed functions) or data as code (embedded data tables). The book describes Clear Code Bytes (hotkey C) + Disassemble as the standard repair workflow. Compilers that embed data in code sections and obfuscated programs are the primary causes.

**Efficiency Impact:**
When the agent identifies misclassified regions (e.g., a jump table interpreted as code, or a function missed because it's never called directly), it currently has no way to fix the problem. These tools close that gap.

---

#### GB-16: Loop Detection via Graph Analysis

**Status:** IMPLEMENTED
**Date Completed:** 2026-02-10
**Book Chapter:** 10 (Graphs, pp. 8708-8728)
**Files Added/Modified:** `ghidra_scripts/detect_loops.py` (new), `ghidra_runner.py`, `control_plane.py`, `tools.py`, `llm_agent.py`

**What Will Change:**
Add MCP tool: `detect_loops(function_name)` returning:
- Back edges (edges pointing to earlier blocks in topological order)
- Loop body boundaries (start/end addresses)
- Loop nesting depth
- Loop type classification: for-loop, while-loop, do-while (inferred from block structure)
- Loop-carried dependencies (variables modified each iteration)

**Book Rationale:**
Chapter 10 states that back edges in a CFG indicate loops. The book's basic block analysis provides the foundation for computing dominators, which are required for natural loop detection.

**Efficiency Impact:**
Loop analysis is critical for understanding encryption routines, data processing, and network communication patterns. Currently the agent must read through decompiled code linearly to identify loops.

---

### Priority 3 — Specialized Capabilities

---

#### GB-17: Disassembly Desynchronization Detection

**Status:** IMPLEMENTED
**Date Completed:** 2026-02-10
**Book Chapter:** 21 (Obfuscated Code Analysis, pp. 470-473)
**Files Added/Modified:** `ghidra_scripts/find_desync_errors.py` (new), `ghidra_runner.py`, `control_plane.py`, `tools.py`, `llm_agent.py`

**What Will Change:**
Add MCP tool: `find_desynchronization_errors()` that:
- Scans Ghidra's error bookmarks for "conflicting instruction" messages
- Returns list of problematic addresses with the conflicting instruction context
- Provides guidance for manual resynchronization (undefine + disassemble from jump target)

**Book Rationale:**
Chapter 21 describes disassembly desynchronization as an anti-analysis technique where jumps land mid-instruction (e.g., `JMP LAB+1`). This causes Ghidra's linear sweep to generate error bookmarks. Detection is the first step toward automated repair.

**Efficiency Impact:**
On obfuscated binaries, the agent currently has no way to detect or report desynchronization issues. It may silently analyze incorrect disassembly.

---

#### GB-18: Emulation-Based Computed Jump Resolution

**Status:** IMPLEMENTED
**Date Completed:** 2026-02-10
**Book Chapter:** 21 (Obfuscated Code Analysis, pp. 474-476, 496-501)
**Files Added/Modified:** `ghidra_scripts/resolve_computed_jump.py` (new), `ghidra_runner.py`, `control_plane.py`, `tools.py`, `llm_agent.py`

**What Will Change:**
Add MCP tool: `resolve_computed_jump(address)` using Ghidra's `EmulatorHelper` to:
- Trace register values through CALL/POP/LEA chains
- Resolve `JMP EAX` and similar indirect jumps to concrete target addresses
- Return the resolved address for the agent to follow in analysis

Uses Ghidra's p-code emulation (architecture-independent).

**Book Rationale:**
Chapter 21 documents `EmulatorHelper` (pp. 496-501) for architecture-independent emulation via p-code. The SimpleEmulator example demonstrates selecting a code region, emulating instructions, tracking memory writes, and writing results back to the program. This is directly applicable to resolving computed jumps that static analysis cannot follow.

**Efficiency Impact:**
On obfuscated binaries, computed jumps break the call graph — the agent sees `JMP EAX` but cannot determine where execution goes. Emulation-based resolution restores control flow visibility.

---

#### GB-19: Emulation-Based Static Deobfuscation

**Status:** IMPLEMENTED
**Date Completed:** 2026-02-10
**Book Chapter:** 21 (Obfuscated Code Analysis, pp. 491-501)
**Files Added/Modified:** `ghidra_scripts/emulate_deobfuscation.py` (new), `ghidra_runner.py`, `control_plane.py`, `tools.py`, `llm_agent.py`

**What Will Change:**
Add MCP tool: `emulate_deobfuscation(start_address, end_address, register_state)` that:
- Instantiates `EmulatorHelper(currentProgram)` with `enableMemoryWriteTracking(true)`
- Emulates instructions in the specified range
- Writes modified bytes back to the program via `writeBackMemory()`
- Triggers re-analysis so the disassembler parses decoded instructions

**Book Rationale:**
Chapter 21 provides two deobfuscation approaches: script-oriented (mimic the unpacking algorithm, pp. 491-495) and emulation-oriented (use EmulatorHelper for generic unpacking, pp. 496-501). The emulation approach is preferred because it works across architectures and doesn't require understanding the specific obfuscation algorithm.

**Efficiency Impact:**
Packed/encoded binaries are currently opaque to GARE — the agent sees high-entropy data but cannot decode it. Emulation-based deobfuscation unlocks the actual code for analysis.

---

#### GB-20: Import Table Reconstruction for Obfuscated Binaries

**Status:** IMPLEMENTED
**Date Completed:** 2026-02-10
**Book Chapter:** 21 (Obfuscated Code Analysis, pp. 482-486)
**Files Added/Modified:** `ghidra_scripts/reconstruct_imports.py` (new), `ghidra_runner.py`, `control_plane.py`, `tools.py`, `llm_agent.py`

**What Will Change:**
Add MCP tool: `extract_reconstructed_imports()` that:
- Scans code for `LoadLibrary`/`GetProcAddress` patterns (Windows) or `dlopen`/`dlsym` (Linux)
- Detects hash-based function lookup (e.g., tElock's 4-byte character comparison, skape hash)
- Matches detected hashes against known Windows/Linux API hash databases
- Returns dictionary of `{hash_or_pattern: resolved_function_name}`

**Book Rationale:**
Chapter 21 documents imported function obfuscation (pp. 482-486) where packers hide the import table and reconstruct it at runtime. The tElock and skape hash examples show specific patterns. Without import reconstruction, the Symbol Tree is empty and the agent cannot identify API usage.

**Efficiency Impact:**
On packed malware, `list_imports` returns nothing. The agent cannot map to MITRE ATT&CK or identify capabilities. Import reconstruction restores this critical intelligence.

---

#### GB-21: Collaborative Multi-Agent Analysis

**Status:** IMPLEMENTED
**Date Completed:** 2026-02-10
**Book Chapter:** 11 (Collaborative SRE, pp. 217-240)
**Files Added/Modified:** `agent/multi_agent.py` (new), `agent/runner.py`, `routes/orchestrator.py`, `routes/main.py`

**What Will Change:**
Enable multi-agent orchestration where specialized agents analyze the same binary sequentially:
- **Triage Agent** (15% budget): Quick classification, entropy check, library identification, MITRE ATT&CK mapping, IOC extraction
- **Security Auditor** (35% budget): Crypto routines, network operations, anti-analysis techniques, C2 patterns, import reconstruction
- **Code Analyst** (50% budget): Deep decompilation, function renaming, structure recovery, loop/switch detection, call graph analysis
- All agents share the same Ghidra project via PyGhidra (sequential access)
- Each agent writes to shared notebook with agent attribution prefix ([TRIAGE], [SECURITY], [CODE])
- Conversations merged for unified report generation
- Activated via `--multi-agent` flag on runner or `multi_agent=true` on upload API

**Book Rationale:**
Chapter 11 describes the full Ghidra Server workflow: shared repositories, version control, checkout/checkin, access permissions, and merge resolution. GARE adapts this to sequential agent personas sharing a single project — delivering the core multi-perspective analysis value without Ghidra Server infrastructure.

**Efficiency Impact:**
Focused agent personas produce higher-quality findings per iteration than a single generalist. The triage agent's classification directs subsequent agents to the most relevant areas, reducing wasted iterations.

---

#### GB-22: Batch Processing for Multi-Binary Jobs

**Status:** IMPLEMENTED
**Date Completed:** 2026-02-10
**Book Chapter:** 16 (Ghidra in Headless Mode, pp. 349-350)
**Files Added/Modified:** `worker/batch_processor.py` (new), `routes/orchestrator.py`, `routes/main.py`

**What Will Change:**
Support multi-binary jobs where multiple files are uploaded and processed:
- `POST /api/upload/batch` accepts multiple files in a single request
- `BatchProcessor` class discovers and processes binaries sequentially
- Recursive glob-based file discovery with configurable patterns (`*.exe`, `*.dll`, `*.elf`)
- Per-binary subdirectories under `batch/` for isolated Ghidra projects and artifacts
- Per-binary metadata saved alongside batch summary JSON
- Batch report generator produces markdown table with per-binary status, architecture, format
- Per-file timeout prevents any single binary from blocking the batch
- Batch result summary saved to `batch/batch_summary.json`

**Book Rationale:**
Chapter 16 documents recursive directory processing (p. 349) and the Batch Import feature. The book's example processes 1,690 files from a libc.a archive in a single headless command. GARE's implementation adapts this pattern for PyGhidra.

**Efficiency Impact:**
JVM startup overhead is 10-15% of total analysis time. Batch processing via sequential reuse within a job reduces overhead for multi-binary jobs (e.g., analyzing all components of a malware dropper).

---

#### GB-23: Pre/Post Script Hook Architecture

**Status:** IMPLEMENTED
**Date Completed:** 2026-02-10
**Book Chapter:** 16 (Ghidra in Headless Mode, pp. 353-360)
**Files Added/Modified:** `worker/script_hooks.py` (new), `worker/ghidra_runner.py`

**What Will Change:**
Implement a hook system with 6 lifecycle points:
- **PRE_IMPORT**: Validate binary (size, format detection via magic bytes), log import
- **POST_IMPORT**: Configure decompiler options based on intensity
- **PRE_ANALYSIS / POST_ANALYSIS**: Metadata extraction, artifact tracking
- **PRE_SCRIPT / POST_SCRIPT**: Per-script logging with name, args, output length
- `HookManager` class manages registration, execution, and reporting
- Built-in hooks: `hook_validate_binary` (magic byte format detection for ELF/PE/Mach-O), `hook_configure_decompiler` (intensity-aware options), `hook_log_script` (execution logging)
- Per-job hook configuration via `job_meta.json` (can disable specific hook points)
- Global disable via `DISABLE_HOOKS=true` environment variable
- Hook execution report saved to `artifacts/hook_report.json`
- Custom hooks can be registered programmatically via `HookManager.register_hook()`

**Book Rationale:**
Chapter 16 documents `-preScript` and `-postScript` (pp. 353-360) with the HeadlessSimpleROP example that runs as a postScript, extracts gadgets from each analyzed file, and appends to a summary file.

**Efficiency Impact:**
Decouples analysis configuration from tool execution. Pre-import validation catches invalid files before JVM startup. Post-import decompiler configuration ensures the agent always works with optimally configured output.

---

## Mapping: Book Concepts to GARE Components

### Existing Capabilities

| Book Concept | Chapter | GARE Implementation | File | Status |
|---|---|---|---|---|
| Decompilation API | 19 | `decompile_function` tool | `ghidra_scripts/decompile.py` | IMPLEMENTED |
| Cross-references (to/from) | 9 | `get_function_xrefs`, `get_xrefs_from` tools | `ghidra_scripts/get_xrefs.py` | IMPLEMENTED |
| Function call graphs | 10 | `get_call_graph` tool | `ghidra_scripts/get_call_graph.py` | IMPLEMENTED |
| Data type manager | 8 | `list_data_types`, `apply_data_type` tools | `ghidra_scripts/list_data_types.py`, `apply_data_type.py` | IMPLEMENTED |
| Plate comments | 7 | `set_decompiler_comment` tool | `ghidra_scripts/set_comment.py` | IMPLEMENTED |
| Function renaming | 7 | `rename_function` tool | `ghidra_scripts/rename.py` | IMPLEMENTED |
| Memory segments | 6 | `list_segments` tool | `ghidra_scripts/list_segments.py` | IMPLEMENTED |
| Entropy / packing detection | 21 | `get_entropy` tool | `ghidra_scripts/get_entropy.py` | IMPLEMENTED |
| Thunk/library identification | 10 | `identify_libraries` tool | `ghidra_scripts/identify_libraries.py` | IMPLEMENTED |
| Disassembly inspection | 6 | `disassemble_function` tool | `ghidra_scripts/disassemble.py` | IMPLEMENTED |
| Import/export symbols | 6, 9 | `list_imports`, `list_exports` tools | `ghidra_scripts/get_imports_exports.py` | IMPLEMENTED |
| String extraction | 7 | `list_strings` tool | `ghidra_scripts/get_strings.py` | IMPLEMENTED |
| Headless script execution | 16 | PyGhidra worker pipeline | `worker/ghidra_runner.py` | IMPLEMENTED |
| Project export/sharing | 11 | Annotation, binary package, XML exports | `export_annotations.py`, etc. | IMPLEMENTED |

### Planned Enhancements

| Book Concept | Chapter | Enhancement ID | Target Tool | Status |
|---|---|---|---|---|
| Decompiler option control | 19 | GB-1 | `decompile.py` modification | IMPLEMENTED |
| Auto structure creation | 19 | GB-2 | `auto_create_structure.py` | IMPLEMENTED |
| Variable slicing (data flow) | 19 | GB-3 | `get_variable_slice.py` | IMPLEMENTED |
| Basic block / CFG analysis | 10 | GB-4 | `analyze_basic_blocks.py` | IMPLEMENTED |
| Bidirectional call graph | 10 | GB-5 | `get_call_graph.py` enhancement | IMPLEMENTED |
| Switch statement detection | 20 | GB-6 | `detect_switch.py` | IMPLEMENTED |
| Compiler variation prompt | 20 | GB-7 | `prompts.py` update | IMPLEMENTED |
| Xref type classification (R/W/*) | 9 | GB-8 | `get_xrefs.py` enhancement | IMPLEMENTED |
| Array detection from scaling | 8 | GB-9 | `detect_arrays.py` | IMPLEMENTED |
| C++ vftable / RTTI analysis | 8, 20 | GB-10 | `analyze_cpp_classes.py` | IMPLEMENTED |
| Headless timeout/CPU control | 16 | GB-11 | `ghidra_runner.py` + `analysis_config.py` | IMPLEMENTED |
| Function attribute setting | 7 | GB-12 | `set_function_attributes.py` | IMPLEMENTED |
| Repeatable comments | 7 | GB-13 | `set_repeatable_comment.py` | IMPLEMENTED |
| Named constants (equates) | 7 | GB-14 | `set_equate.py` | IMPLEMENTED |
| Code/data boundary repair | 7 | GB-15 | `convert_code_data.py` | IMPLEMENTED |
| Loop detection | 10 | GB-16 | `detect_loops.py` | IMPLEMENTED |
| Desync error detection | 21 | GB-17 | `find_desync_errors.py` | IMPLEMENTED |
| Computed jump resolution | 21 | GB-18 | `resolve_computed_jump.py` | IMPLEMENTED |
| Emulation deobfuscation | 21 | GB-19 | `emulate_deobfuscation.py` | IMPLEMENTED |
| Import reconstruction | 21 | GB-20 | `reconstruct_imports.py` | IMPLEMENTED |
| Multi-agent analysis | 11 | GB-21 | `agent/multi_agent.py` | IMPLEMENTED |
| Batch multi-binary processing | 16 | GB-22 | `worker/batch_processor.py` | IMPLEMENTED |
| Pre/post script hooks | 16 | GB-23 | `worker/script_hooks.py` | IMPLEMENTED |

---

## Metrics

With the `MetricsCollector` (added alongside GB enhancements), the following metrics are now automatically recorded per job in `artifacts/metrics.json` and included in analysis reports:

- **GB Tool Utilization %**: Percentage of total tool calls that used GB-enhanced tools (GB-1 through GB-23)
- **Unique GB Tools Used**: How many distinct GB-enhanced tools the agent invoked
- **Error Rate**: Tool call failure rate (success vs. failure)
- **Findings per Tool Call**: Notebook entries recorded per tool call (analysis efficiency)
- **Tool Call Counts**: Per-tool breakdown showing which tools were used most

The following before/after comparisons can be derived from `metrics.json` across runs:

- **Decompiler noise reduction**: Token count of decompiled output before vs. after GB-1 (eliminate unreachable code, simplify predication)
- **Structure recovery rate**: Number of pointer arithmetic patterns replaced by struct accesses after GB-2
- **Data flow query savings**: Tool calls needed to trace a variable's influence before vs. after GB-3 (variable slicing)
- **Loop identification accuracy**: Compare agent's loop detection from reading decompiled code vs. GB-16 structured output
- **Switch recognition rate**: Measure how often the agent correctly identifies switch statements before vs. after GB-6/GB-7
- **Obfuscation handling**: Percentage of computed jumps resolved by GB-18 on packed malware samples
- **Analysis throughput**: Time per binary before vs. after GB-11 headless optimization
- **Multi-binary overhead**: JVM startup time savings from GB-22 batch processing

Access metrics via: `GET /api/jobs/{job_id}/metrics`

---

## Implementation Tracking

| ID | Enhancement | Priority | Status | Date Started | Date Completed |
|---|---|---|---|---|---|
| GB-1 | Decompiler configuration | P1 | IMPLEMENTED | 2026-02-10 | 2026-02-10 |
| GB-2 | Auto structure creation | P1 | IMPLEMENTED | 2026-02-10 | 2026-02-10 |
| GB-3 | Variable slicing | P1 | IMPLEMENTED | 2026-02-10 | 2026-02-10 |
| GB-4 | Basic block / CFG | P1 | IMPLEMENTED | 2026-02-10 | 2026-02-10 |
| GB-5 | Enhanced call graph | P1 | IMPLEMENTED | 2026-02-10 | 2026-02-10 |
| GB-6 | Switch detection | P1 | IMPLEMENTED | 2026-02-10 | 2026-02-10 |
| GB-7 | Compiler variation prompt | P1 | IMPLEMENTED | 2026-02-10 | 2026-02-10 |
| GB-8 | Xref type classification | P2 | IMPLEMENTED | 2026-02-10 | 2026-02-10 |
| GB-9 | Array detection | P2 | IMPLEMENTED | 2026-02-10 | 2026-02-10 |
| GB-10 | C++ vftable / RTTI | P2 | IMPLEMENTED | 2026-02-10 | 2026-02-10 |
| GB-11 | Headless optimization | P2 | IMPLEMENTED | 2026-02-10 | 2026-02-10 |
| GB-12 | Function attributes | P2 | IMPLEMENTED | 2026-02-10 | 2026-02-10 |
| GB-13 | Repeatable comments | P2 | IMPLEMENTED | 2026-02-10 | 2026-02-10 |
| GB-14 | Named constants | P2 | IMPLEMENTED | 2026-02-10 | 2026-02-10 |
| GB-15 | Code/data repair | P2 | IMPLEMENTED | 2026-02-10 | 2026-02-10 |
| GB-16 | Loop detection | P2 | IMPLEMENTED | 2026-02-10 | 2026-02-10 |
| GB-17 | Desync detection | P3 | IMPLEMENTED | 2026-02-10 | 2026-02-10 |
| GB-18 | Computed jump resolution | P3 | IMPLEMENTED | 2026-02-10 | 2026-02-10 |
| GB-19 | Emulation deobfuscation | P3 | IMPLEMENTED | 2026-02-10 | 2026-02-10 |
| GB-20 | Import reconstruction | P3 | IMPLEMENTED | 2026-02-10 | 2026-02-10 |
| GB-21 | Multi-agent analysis | P3 | IMPLEMENTED | 2026-02-10 | 2026-02-10 |
| GB-22 | Batch processing | P3 | IMPLEMENTED | 2026-02-10 | 2026-02-10 |
| GB-23 | Pre/post script hooks | P3 | IMPLEMENTED | 2026-02-10 | 2026-02-10 |

---

**Last Updated:** 2026-02-10
