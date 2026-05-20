# Thesis Reference — Workflow Changes Influenced by Shrivastava (2023)

**Source Thesis:** Rashmi Shrivastava, *Static Analysis of Stripped Binary Executables to Find Function Parameters, Local Variables and Parameters Used as Pointers in Intel 32-bit and 64-bit Architectures*, M.S. Thesis, University of Idaho, May 2023.

**Advisor:** Jim Alves-Foss, Ph.D.

**Purpose:** This document tracks workflow changes made to the GARE pipeline that were directly influenced by the Shrivastava thesis. It serves as a living reference for mapping academic research to implementation decisions and measuring their impact on analysis efficiency.

---

## Thesis Summary

The Shrivastava thesis presents a novel algorithm for recovering three categories of information from stripped Intel x86/x64 binaries without debug symbols:

1. **Function parameters** — identified via calling convention analysis and a source/destination tracking heuristic
2. **Local variables** — identified via stack frame offsets relative to the base pointer
3. **Parameters used as pointers** — identified via reaching definition analysis and backward data-flow tracing

The algorithm was validated against 650+ functions from stripped binutils, coreutils, and findutils binaries (GCC and Clang, O0 and O2, 32-bit and 64-bit), achieving ~100% precision for parameter detection and 77-85% for pointer parameter identification.

---

## Workflow Changes

### WF-1: Function Signature Recovery Tool

**Date Added:** 2026-02-05
**File:** `backend/src/scripts/ghidra_scripts/get_function_signature.py`
**Thesis Sections:** 1.2.5, 1.2.6, 3.2 (Algorithm Implementation)

**What Changed:**
Added a new Ghidra script that extracts rich function signatures from stripped binaries. The script returns:
- Parameter list with index, name, inferred type, and storage location (register or stack offset)
- Local variable list with name, inferred type, and storage location
- Indices of parameters that are pointer types
- Calling convention detected by Ghidra's analyzer
- Cross-reference data (callers and callees)

**Thesis Influence:**
The script automates the three core recovery tasks from the thesis (parameters, locals, pointer parameters) by leveraging Ghidra's decompiler to produce the same categories of output that Shrivastava's algorithm computes from raw assembly. Where the thesis builds reaching definitions from scratch using the JIMA toolkit, this implementation delegates that work to Ghidra's `DecompInterface` and `HighFunction` API, then extracts the same semantic information from the decompiler's symbol map.

**Efficiency Impact:**
Before this tool, the agent could only infer parameter information indirectly by reading decompiled C pseudocode. Now the agent receives structured JSON with explicit parameter types, storage locations, and pointer classifications in a single tool call — eliminating multi-step decompile-then-parse reasoning loops.

---

### WF-2: Calling Convention Reference in Agent System Prompt

**Date Added:** 2026-02-05
**File:** `backend/src/services/agent/prompts.py` (lines 70-97, `CALLING_CONVENTION_REFERENCE`)
**Thesis Sections:** 1.2.5, 1.3, 2.1.2.4, 2.2, 5.1, 5.2

**What Changed:**
Injected a structured reference block into the LLM agent's system prompt covering:

| Prompt Section | Thesis Source |
|---|---|
| x86 32-bit CDECL: EBP+0x8 = param1, EBP+0xC = param2 | Sections 1.2.5, 1.3 (32-bit parameter locations) |
| x86-64 System V ABI: RDI, RSI, RDX, RCX, R8, R9 | Sections 1.2.5, 2.1.2.4 (64-bit register passing) |
| "Source operand never appears as prior destination = parameter" | Table 3.1 Step 2 (core algorithm heuristic) |
| "Negative offsets from EBP/RBP = local variables at O0" | Sections 1.3, 2.2 (stack frame layout) |
| "O2 may eliminate frame pointer; locals become ESP/RSP-relative" | Section 1.3 (O2 optimization handling) |
| "Clang treats struct/enum elements as separate local variables" | Section 5.2 (Limitations — Clang false positives) |
| "64-bit param split into two 32-bit stack slots" | Section 5.2 (Limitations — parameter splitting) |
| "`get_pc_thunk` calls are not real function calls" | Section 3.2.1 (Table 3.1 Step 1, thunk detection) |
| "O2: %ebp may be used as general-purpose register" | Section 5.1 (Challenges — frame pointer reuse) |

**Thesis Influence:**
The reference block translates Shrivastava's calling convention analysis (Chapter 2), algorithm heuristics (Chapter 3), and known limitations (Chapter 5) into concise guidance that the LLM can apply during autonomous analysis. The "Known False-Positive Triggers" section directly encodes the thesis's documented failure modes so the agent avoids the same pitfalls.

**Efficiency Impact:**
Without this reference, the LLM relies on general training knowledge about calling conventions, which is often imprecise for edge cases (O2 optimization, Clang quirks, PIC thunks). Encoding thesis-validated heuristics directly into the prompt reduces incorrect parameter counts and misidentified locals, especially on optimized or Clang-compiled binaries.

---

### WF-3: Pointer Tracing Instructions in Agent Workflow

**Date Added:** 2026-02-05
**File:** `backend/src/services/agent/prompts.py` (lines 128-139)
**Thesis Sections:** 3.2.6, Table 3.1 Step 6

**What Changed:**
Added explicit instructions to the agent's deep analysis step:

1. Use `get_function_signature()` to verify Ghidra's auto-detected parameters in stripped binaries
2. Apply the source/destination heuristic when Ghidra misidentifies parameters
3. Cross-check parameter counts against the detected calling convention
4. Trace pointer parameters: examine decompiled code for dereference operations (`*param`, `param->field`, `param[i]`)
5. When a parameter flows through local variables before being dereferenced, trace backward through assignments to confirm it originates from a parameter
6. Use `get_call_graph()` and `get_function_xrefs()` for inter-procedural pointer tracing

**Thesis Influence:**
Steps 4-6 are a direct translation of Shrivastava's pointer-as-parameter algorithm (Section 3.2.6, Table 3.1 Step 6). The thesis algorithm dereferences each source/destination, compares against the parameter list, and if no match, performs backward analysis through the data-flow path to determine if the pointer value originated from a parameter. The agent instructions replicate this logic using natural language reasoning over decompiled code instead of explicit reaching definition sets.

**Efficiency Impact:**
Pointer parameter identification is critical for malware analysis — understanding which function arguments are pointers reveals data structures, buffer operations, and potential C2 communication patterns. Before this change, the agent had no structured approach to pointer tracing and would either miss pointer usage or waste iterations on ad-hoc decompilation. The thesis-informed workflow gives the agent a deterministic strategy: signature check, then forward dereference scan, then backward assignment trace.

---

### WF-4: MCP Tool Registration and Agent Tool Definition

**Date Added:** 2026-02-05
**Files:**
- `backend/src/services/mcp_server/tools.py` — MCP server tool registration
- `backend/src/services/agent/llm_agent.py` — LLM agent tool definition
- `backend/src/services/worker/control_plane.py` — Worker endpoint
- `backend/src/services/worker/ghidra_runner.py` — Script whitelist entry

**Thesis Sections:** N/A (infrastructure, not algorithm)

**What Changed:**
Registered `get_function_signature` across the full tool chain:
- Whitelisted in `ALLOWED_SCRIPTS`
- Added worker endpoint to execute the Ghidra script
- Added MCP tool definition with description: "Get detailed function signature with parameter types, storage locations, local variables, pointer parameters, and cross-references"
- Added agent tool definition with usage guidance: "Use this to verify Ghidra's auto-detected parameters and trace pointer usage"

**Efficiency Impact:**
Makes the thesis-derived analysis available as a single tool call. The agent can invoke `get_function_signature("main")` and receive the full parameter/local/pointer breakdown in one round-trip instead of decompiling, then manually parsing the output for parameter patterns.

---

## Mapping: Thesis Concepts to GARE Components

| Thesis Concept | Chapter/Section | GARE Implementation | File |
|---|---|---|---|
| Parameter recovery (32-bit stack) | 1.2.5, 1.3 | `get_function_signature.py` parameter extraction | `ghidra_scripts/get_function_signature.py:49-73` |
| Parameter recovery (64-bit registers) | 1.2.5, 2.1.2.4 | System prompt calling convention reference | `prompts.py:80-84` |
| Local variable detection | 1.3, 2.2 | `get_function_signature.py` local variable extraction | `ghidra_scripts/get_function_signature.py:74-79` |
| Pointer parameter identification | 1.2.6, 3.2.6 | Pointer type check + `pointer_parameters` array | `ghidra_scripts/get_function_signature.py:65,72-73,120` |
| Source/destination heuristic | Table 3.1 Step 2 | Agent prompt: "source never as prior destination" | `prompts.py:86-89` |
| Reaching definition / backward trace | 3.1.2, 3.2.6 | Agent instructions: trace pointer through locals | `prompts.py:133-136` |
| Inter-procedural analysis | 3.2.6 (future work) | Call graph + xref tools for cross-function tracing | `prompts.py:137-139` |
| Calling convention analysis | 2.1.2.4 | Calling convention field in signature output | `ghidra_scripts/get_function_signature.py:88` |
| O2 optimization challenges | 1.3, 5.1 | Known false-positive triggers in prompt | `prompts.py:91-96` |
| Clang-specific limitations | 5.2 | "Clang treats struct/enum as separate locals" warning | `prompts.py:93` |
| JIMA thunk detection | 3.2.1, Table 3.1 | "`get_pc_thunk` calls are not real calls" warning | `prompts.py:95` |

---

## Metrics Not Yet Measured

The following efficiency comparisons would validate the thesis-informed workflow changes but have not been formally benchmarked:

- **Parameter accuracy**: Compare Ghidra's default parameter detection vs. agent-corrected parameters (using the source/destination heuristic) on stripped O2 binaries
- **Pointer identification rate**: Measure how often the agent correctly identifies pointer parameters before vs. after WF-1/WF-3
- **Iteration savings**: Count average tool calls spent on parameter/type analysis before vs. after `get_function_signature` was available
- **False positive reduction**: Measure whether the Clang/O2 warnings in WF-2 reduce incorrect local variable counts

---

## Future Work Informed by Thesis

The following thesis concepts have not yet been implemented but could further improve the workflow:

1. **Explicit reaching definition engine** (Ch. 3.1): Build a standalone Python module that computes reaching definitions from Ghidra's disassembly, independent of the decompiler. This would provide a second opinion when Ghidra's decompiler fails on obfuscated code.

2. **Variadic function detection** (Ch. 6.3): The thesis notes a companion project on detecting variadic functions in binaries. This would improve analysis of printf/scanf-family calls in malware.

3. **Array parameter detection** (Ch. 1.4): Shrivastava notes the algorithm can be extended to detect arrays passed as parameters, beyond simple pointer detection. This would improve buffer overflow analysis.

4. **Type equivalence recovery** (Ch. 1.4): The thesis's ultimate goal is recovering full type signatures (integer, unsigned, struct, etc.) from stripped binaries. This maps to GARE's existing `apply_data_type` tool but could be made more automated.

---

**Last Updated:** 2026-02-10
