"""
LLM-Driven Agent for Autonomous Reverse Engineering
Uses LLM Provider LLM with tool calling to drive intelligent analysis
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime

# Import LLM client based on provider
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "anthropic")

if LLM_PROVIDER == "anthropic":
    from anthropic import Anthropic
elif LLM_PROVIDER == "openai":
    from openai import OpenAI

logger = logging.getLogger(__name__)


class LLMAgent:
    """LLM-driven agent that uses LLM with tool calling for intelligent RE analysis"""

    # Intensity presets: (max_iterations, max_tool_calls)
    INTENSITY_PRESETS = {
        "quick":    {"max_iterations": 15,  "max_tool_calls": 30},
        "standard": {"max_iterations": 50,  "max_tool_calls": 100},
        "deep":     {"max_iterations": 100, "max_tool_calls": 250},
    }

    def __init__(self, job_id: str, data_dir: str, worker_url: str, intensity: str = "standard"):
        self.job_id = job_id
        self.data_dir = Path(data_dir)
        self.job_dir = self.data_dir / "jobs" / job_id
        self.worker_url = worker_url
        self.intensity = intensity

        # Initialize LLM Provider client
        api_key = os.environ.get("API_KEY")
        if not api_key:
            raise ValueError("API_KEY environment variable not set")

        base_url = os.environ.get("BASE_URL")  # Optional: for local LLM servers
        model_name = os.environ.get("MODEL_NAME")
        if not model_name:
            raise ValueError("MODEL_NAME environment variable must be set (model identifier from your LLM provider)")

        if LLM_PROVIDER == "anthropic":
            if base_url:
                self.client = Anthropic(api_key=api_key, base_url=base_url)
            else:
                self.client = Anthropic(api_key=api_key)
            self.model = model_name
        elif LLM_PROVIDER == "openai":
            if base_url:
                self.client = OpenAI(api_key=api_key, base_url=base_url)
            else:
                self.client = OpenAI(api_key=api_key)
            self.model = model_name
        else:
            raise ValueError(f"Unsupported LLM provider: {LLM_PROVIDER}")

        # Import tools
        from src.services.mcp_server.tools import GhidraTools
        self.ghidra_tools = GhidraTools(worker_url, job_id, data_dir=data_dir)

        # Metrics collection
        from src.services.agent.metrics_collector import MetricsCollector
        self.metrics = MetricsCollector()

        # Apply intensity presets
        preset = self.INTENSITY_PRESETS.get(intensity, self.INTENSITY_PRESETS["standard"])
        self.max_iterations = preset["max_iterations"]

        # Conversation history
        self.messages = []
        self.tool_call_count = 0
        self.max_tool_calls = preset["max_tool_calls"]
        self.cancelled = False
        # Last exception caught during the analysis loop, if any.
        # Surfaced to runner.py so the job ends in FAILED with a real reason
        # instead of silently "completed" with zero tool calls.
        self.error: Optional[str] = None

        logger.info(f"LLM Agent initialized for job {job_id} using {LLM_PROVIDER} {self.model} (intensity={intensity})")

    def get_tool_definitions(self) -> List[Dict]:
        """Get MCP tool definitions in LLM Provider format"""
        return [
            {
                "name": "list_methods",
                "description": "List all function names in the binary. Returns function addresses and names.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "offset": {"type": "integer", "description": "Pagination offset", "default": 0},
                        "limit": {"type": "integer", "description": "Max results to return", "default": 100}
                    }
                }
            },
            {
                "name": "decompile_function",
                "description": "Decompile a function to C pseudocode. Critical for understanding what a function does.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Function name to decompile"}
                    },
                    "required": ["name"]
                }
            },
            {
                "name": "list_strings",
                "description": "List all strings found in the binary. Very useful for finding clues about functionality.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "offset": {"type": "integer", "default": 0},
                        "limit": {"type": "integer", "default": 2000},
                        "filter": {"type": "string", "description": "Optional filter to match within string content"}
                    }
                }
            },
            {
                "name": "list_imports",
                "description": "List imported functions from libraries. Shows what external APIs the binary uses.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "offset": {"type": "integer", "default": 0},
                        "limit": {"type": "integer", "default": 100}
                    }
                }
            },
            {
                "name": "list_exports",
                "description": "List exported functions/symbols.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "offset": {"type": "integer", "default": 0},
                        "limit": {"type": "integer", "default": 100}
                    }
                }
            },
            {
                "name": "list_segments",
                "description": "List memory segments with addresses, sizes, and permissions.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "offset": {"type": "integer", "default": 0},
                        "limit": {"type": "integer", "default": 100}
                    }
                }
            },
            {
                "name": "rename_function",
                "description": "Rename a function to a descriptive name. Use this after analyzing a function to give it a meaningful name.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "old_name": {"type": "string", "description": "Current function name"},
                        "new_name": {"type": "string", "description": "New descriptive name (use VIBE_ prefix)"}
                    },
                    "required": ["old_name", "new_name"]
                }
            },
            {
                "name": "disassemble_function",
                "description": "Get assembly code for a function at given address. Useful for low-level analysis.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Function address in hex (e.g. 0x00101307)"}
                    },
                    "required": ["address"]
                }
            },
            {
                "name": "set_decompiler_comment",
                "description": "Add a comment to decompiled code at a specific address. Use to document your findings.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Address in hex"},
                        "comment": {"type": "string", "description": "Comment text"}
                    },
                    "required": ["address", "comment"]
                }
            },
            {
                "name": "search_functions_by_name",
                "description": "Search for functions whose name contains the given substring. Useful for finding related functions.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Substring to search for in function names"}
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "get_function_xrefs",
                "description": "Get cross-references TO a function (who calls it). Shows all callers of the named function.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Function name to get references to"}
                    },
                    "required": ["name"]
                }
            },
            {
                "name": "get_xrefs_from",
                "description": "Get cross-references FROM an address (what it calls/references). Useful for tracing outgoing calls.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Address in hex to get references from"}
                    },
                    "required": ["address"]
                }
            },
            {
                "name": "decompile_function_by_address",
                "description": "Decompile a function by its hex address. Useful when the function name is mangled or unknown.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Function address in hex (e.g. 0x00401000)"}
                    },
                    "required": ["address"]
                }
            },
            {
                "name": "get_call_graph",
                "description": "Get call graph for a function with configurable depth. Returns callers and callees with thunk resolution (shows actual library names behind stubs), call cycle detection (mutual recursion), and nested call chains up to specified depth. Use depth=1 for immediate neighbors, depth=2-3 for deeper chain analysis.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "function_name": {"type": "string", "description": "Function name or hex address"},
                        "depth": {"type": "integer", "description": "How many levels deep to trace (1=immediate, max 5)", "default": 1}
                    },
                    "required": ["function_name"]
                }
            },
            {
                "name": "get_function_signature",
                "description": "Get rich function signature: parameter types with storage locations, local variables, pointer parameter indices, calling convention, and caller/callee cross-references. Use this to verify Ghidra's auto-detected parameters and trace pointer usage.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Function name or hex address (e.g. 'main' or '0x00401000')"}
                    },
                    "required": ["name"]
                }
            },
            {
                "name": "get_entropy",
                "description": "Compute per-section entropy to detect packing or encryption. High entropy (>7.0) indicates packed/encrypted content. Run this early to guide analysis strategy.",
                "input_schema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "extract_iocs",
                "description": "Extract Indicators of Compromise (IOCs) from binary strings: IP addresses, URLs, domains, file paths, registry keys, emails, crypto wallets.",
                "input_schema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "notebook_append",
                "description": "Record a finding in the structured analysis notebook. Use this to persist important discoveries (suspected C2 addresses, encryption keys, behavioral patterns) so they survive across iterations.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "category": {"type": "string", "description": "Finding category: c2, crypto, persistence, evasion, capability, ioc, note"},
                        "content": {"type": "string", "description": "Description of the finding"}
                    },
                    "required": ["category", "content"]
                }
            },
            {
                "name": "notebook_read",
                "description": "Read all findings recorded in the analysis notebook so far.",
                "input_schema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "map_mitre_attack",
                "description": "Map the binary's imported APIs to MITRE ATT&CK techniques. Returns techniques grouped by tactic (Execution, Persistence, Defense Evasion, etc.).",
                "input_schema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "identify_libraries",
                "description": "Identify which functions are library/thunk code vs user-written code. Focus your analysis on 'user' functions — skip library code.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "offset": {"type": "integer", "default": 0},
                        "limit": {"type": "integer", "default": 200}
                    }
                }
            },
            {
                "name": "list_data_types",
                "description": "List available data types in the program (structs, enums, typedefs). Filter by name substring.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "filter": {"type": "string", "description": "Optional name filter substring", "default": ""},
                        "offset": {"type": "integer", "default": 0},
                        "limit": {"type": "integer", "default": 100}
                    }
                }
            },
            {
                "name": "apply_data_type",
                "description": "Apply a data type to a function parameter or return type. Improves decompiler output readability.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "function_address": {"type": "string", "description": "Function address in hex"},
                        "param_index": {"type": "string", "description": "Parameter index (0-based integer) or 'return' for return type"},
                        "type_name": {"type": "string", "description": "Name of the data type to apply"}
                    },
                    "required": ["function_address", "param_index", "type_name"]
                }
            },
            {
                "name": "analyze_basic_blocks",
                "description": "Get the control flow graph for a function: basic blocks with start/end addresses, successor/predecessor edges, edge types (jump/fallthrough/sequential), back edges indicating loops, and detected loop bodies. Use for understanding control flow structure, loop analysis, and identifying unreachable code.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Function name or hex address"}
                    },
                    "required": ["name"]
                }
            },
            {
                "name": "get_variable_slice",
                "description": "Get data flow slice for a variable: forward (where does this value flow?) or backward (what influences this value?). Essential for vulnerability analysis — trace user input to dangerous sinks, or trace a crypto key back to its source.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "function_name": {"type": "string", "description": "Function name or hex address"},
                        "variable_name": {"type": "string", "description": "Variable name as shown in decompiled output"},
                        "direction": {"type": "string", "description": "'forward' (where does it flow?) or 'backward' (what defines it?)", "default": "forward"}
                    },
                    "required": ["function_name", "variable_name"]
                }
            },
            {
                "name": "auto_create_structure",
                "description": "Auto-create structure definitions from pointer offset patterns in a function. Analyzes decompiled p-code for PTRSUB/PTRADD operations on pointer parameters and creates struct types with detected fields. Transforms raw pointer arithmetic like *(ptr+0x10) into structured field access.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Function name or hex address to analyze for structure patterns"}
                    },
                    "required": ["name"]
                }
            },
            {
                "name": "detect_switch",
                "description": "Detect switch statement implementations in a function. Identifies jump table switches (dense cases compiled to lookup tables in .rodata/.text) and binary search switches (sparse cases compiled to nested CMP/Jcc chains). Returns switch type, case count, target addresses, case density, and table location. Useful for understanding complex conditional logic that the decompiler may not recognize as a switch.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Function name or hex address to analyze for switch patterns"}
                    },
                    "required": ["name"]
                }
            },
            {
                "name": "detect_arrays",
                "description": "Detect array patterns in a function by analyzing scaling operations in instructions. Identifies: (1) indexed access via scale factors (REG*4 = int[], REG*8 = ptr[]), (2) SHL-based indexing, (3) IMUL with struct sizes for struct arrays, (4) global arrays from consecutive same-typed data. Returns element sizes, likely types, and access points. Use when decompiled code shows raw pointer arithmetic that may be array access.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Function name or hex address to analyze for array patterns"}
                    },
                    "required": ["name"]
                }
            },
            {
                "name": "reconstruct_imports",
                "description": "Reconstruct the import table for obfuscated/packed binaries where list_imports returns few or no results. Detects: (1) LoadLibrary/GetProcAddress dynamic loading patterns (Windows), (2) dlopen/dlsym patterns (Linux), (3) hash-based API resolution (CRC32, ROR13/skape, djb2), (4) string-based API name references. Returns reconstructed import list with source attribution. Run when the binary appears packed or has suspiciously few imports.",
                "input_schema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "emulate_deobfuscation",
                "description": "Emulate a code region using Ghidra's p-code emulator to deobfuscate/unpack encoded instructions. Tracks all memory writes during emulation and reports modified regions with hex previews. Set write_back=true to write decoded bytes back into the program for re-analysis. Use on packed/encoded sections identified by high entropy. Max 1MB range per call.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "start_address": {"type": "string", "description": "Start hex address of the encoded region"},
                        "end_address": {"type": "string", "description": "End hex address of the encoded region"},
                        "write_back": {"type": "string", "description": "Set to 'true' to write decoded bytes back into the program", "default": "false"}
                    },
                    "required": ["start_address", "end_address"]
                }
            },
            {
                "name": "resolve_computed_jump",
                "description": "Resolve an indirect/computed jump (JMP EAX, JMP [reg+offset]) using Ghidra's p-code emulator. Emulates from the function entry to the jump instruction, captures register state, and determines the actual target address. Works across architectures (x86, ARM, MIPS) via p-code intermediate representation. Use when you see computed jumps that break the call graph.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Hex address of the computed jump instruction"}
                    },
                    "required": ["address"]
                }
            },
            {
                "name": "find_desync_errors",
                "description": "Detect disassembly desynchronization errors in the binary. Finds: (1) Ghidra error bookmarks for conflicting/overlapping instructions, (2) mid-instruction jumps where targets land inside existing instructions (anti-disassembly technique), (3) undefined bytes in executable sections (hidden/obfuscated code). Returns remediation guidance for each issue type. Run on suspected obfuscated binaries.",
                "input_schema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "detect_loops",
                "description": "Detect and classify all loops in a function using CFG back-edge analysis. Returns natural loops with: header/tail blocks, loop body boundaries, instruction count, nesting depth, loop type (while_or_for, do_while, self_loop, infinite), loop-carried variables (registers/variables modified each iteration), and parent loop for nested loops. Essential for understanding encryption routines, data processing, and network communication patterns.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Function name or hex address"}
                    },
                    "required": ["name"]
                }
            },
            {
                "name": "convert_to_code",
                "description": "Convert data or undefined bytes to code by disassembling from the given address. Use when you find a function that Ghidra missed (never-called functions, indirect call targets, manually computed entry points). Clears existing definitions first, then disassembles.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Hex address to start disassembling from"}
                    },
                    "required": ["address"]
                }
            },
            {
                "name": "convert_to_data",
                "description": "Convert code or undefined bytes to typed data. Use when code bytes are actually embedded data: jump tables, string tables, vtable entries, constants. Supports built-in types (byte, word, dword, qword, float, double, pointer, string) and program-defined types. Use count > 1 to create arrays.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Hex address of the data"},
                        "data_type": {"type": "string", "description": "Type name: byte, word, dword, qword, float, double, pointer, string, or a program-defined type", "default": "byte"},
                        "count": {"type": "integer", "description": "Number of elements (>1 creates an array)", "default": 1}
                    },
                    "required": ["address"]
                }
            },
            {
                "name": "set_equate",
                "description": "Apply a named constant (equate) to an instruction operand. Replaces opaque hex values with meaningful identifiers from Ghidra's equate catalog. Example: 0x2 at a socket() call becomes SOCK_DGRAM, 0xa becomes AF_INET6. Use suggest_equates first to see what constants are available for each operand.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Instruction address in hex"},
                        "operand_index": {"type": "integer", "description": "Operand index (0-based)"},
                        "equate_name": {"type": "string", "description": "Named constant to apply (e.g., AF_INET, SOCK_STREAM, O_RDONLY)"}
                    },
                    "required": ["address", "operand_index", "equate_name"]
                }
            },
            {
                "name": "suggest_equates",
                "description": "Suggest named constants for all scalar operands at an instruction address. Returns each operand's value, existing equates, and suggestions from common constant catalogs (socket, file, memory, Windows API, signals). Use before set_equate to see available options.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Instruction address in hex to suggest equates for"}
                    },
                    "required": ["address"]
                }
            },
            {
                "name": "set_repeatable_comment",
                "description": "Set a repeatable comment at an address or function entry. Unlike plate comments, repeatable comments automatically propagate to ALL cross-reference source locations — a comment at a function entry appears at every call site. Ideal for documenting API behavior, security-critical functions, and important patterns that callers need to see.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Hex address or function name to place the comment at"},
                        "comment": {"type": "string", "description": "Comment text that will propagate to all xref sources"}
                    },
                    "required": ["address", "comment"]
                }
            },
            {
                "name": "set_function_attributes",
                "description": "Set a function attribute. Supported attributes: 'noreturn' (prevents fallthrough analysis — use for exit/abort/fatal functions), 'varargs' (marks printf/scanf family), 'calling_convention' (override: __cdecl, __stdcall, __fastcall, __thiscall), 'inline' (mark as inlined), 'custom_storage' (enable custom parameter storage). Use 'get' as attribute to read all current attributes without modifying.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Function name or hex address"},
                        "attribute": {"type": "string", "description": "Attribute to set: noreturn, varargs, calling_convention, inline, custom_storage, or get (read-only)"},
                        "value": {"type": "string", "description": "Value to set (true/false for boolean attrs, convention name for calling_convention)", "default": "true"}
                    },
                    "required": ["name", "attribute"]
                }
            },
            {
                "name": "analyze_cpp_classes",
                "description": "Analyze C++ class hierarchy in the binary. Detects vftable (virtual function table) pointers, identifies constructor functions that store vftable addresses, parses RTTI structures (MSVC RTTICompleteObjectLocator and g++ type_info), and hunts for mangled class name strings in stripped binaries. Returns class hierarchy, virtual function lists, and inheritance relationships. Use on C++ binaries when you see indirect calls through pointers at object offset 0.",
                "input_schema": {
                    "type": "object",
                    "properties": {}
                }
            }
        ]

    def _log_to_job(self, message: str):
        """Write log message to job log file for real-time monitoring"""
        try:
            from src.utils.timezone import utc_now
            log_file = self.job_dir / "logs" / "job.log"
            timestamp = utc_now().isoformat()
            with open(log_file, 'a') as f:
                f.write(f"[{timestamp}] {message}\n")
        except Exception as e:
            logger.warning(f"Failed to write to job log: {e}")

    def _check_cancelled(self) -> bool:
        """Check if the cancel flag file exists for this job"""
        cancel_flag = self.job_dir / "cancel.flag"
        if cancel_flag.exists():
            self.cancelled = True
        return self.cancelled

    def execute_tool(self, tool_name: str, tool_input: Dict) -> Any:
        """Execute an MCP tool via GhidraTools"""
        if self._check_cancelled():
            return {"error": "Analysis cancelled by user"}

        self.tool_call_count += 1

        if self.tool_call_count > self.max_tool_calls:
            return {"error": "Max tool calls reached"}

        # Log tool call with parameters
        tool_params = ", ".join([f"{k}={v}" for k, v in tool_input.items()])
        self._log_to_job(f"[TOOL #{self.tool_call_count}] {tool_name}({tool_params})")
        logger.info(f"Tool call #{self.tool_call_count}: {tool_name}({tool_input})")

        try:
            # Map tool names to GhidraTools methods
            tool_method = getattr(self.ghidra_tools, tool_name, None)
            if not tool_method:
                return {"error": f"Tool not found: {tool_name}"}

            result = tool_method(**tool_input)

            # Record metrics
            is_error = isinstance(result, dict) and "error" in result
            self.metrics.record_tool_call(tool_name, success=not is_error)

            # Record notebook findings
            if tool_name == "notebook_append" and not is_error:
                self.metrics.record_finding(tool_input.get("category", "note"))

            # Log result summary
            if isinstance(result, list):
                self._log_to_job(f"  -> Returned {len(result)} items")
            elif isinstance(result, str):
                preview = result[:100] + "..." if len(result) > 100 else result
                self._log_to_job(f"  -> {preview}")

            # Log binary modifications
            if tool_name == "rename_function":
                self._log_to_job(f"  -> Renamed: {tool_input.get('old_name')} -> {tool_input.get('new_name')}")
            elif tool_name == "rename_data":
                self._log_to_job(f"  -> Renamed data at {tool_input.get('address')} -> {tool_input.get('new_name')}")

            logger.info(f"Tool result: {str(result)[:200]}...")
            return result

        except Exception as e:
            self.metrics.record_tool_call(tool_name, success=False)
            logger.error(f"Tool execution failed: {e}", exc_info=True)
            self._log_to_job(f"  -> ERROR: Tool failed: {str(e)}")
            return {"error": str(e)}

    def _get_intensity_instructions(self) -> str:
        """Get intensity-specific instructions for the system prompt"""
        from src.services.agent.prompts import get_intensity_prompt
        return get_intensity_prompt(self.intensity)

    def run_autonomous_analysis(self) -> Dict[str, Any]:
        """Run autonomous LLM-driven analysis"""
        logger.info(f"Starting autonomous LLM-driven analysis (intensity={self.intensity})")

        # Initial system prompt with intensity-specific instructions
        intensity_instructions = self._get_intensity_instructions()

        system_prompt = f"""You are an expert malware/binary analyst using Ghidra. Your goal is to thoroughly analyze a binary and produce a comprehensive report.

Recommended analysis workflow:
1. Run get_entropy() FIRST to check for packing/encryption — if packed, note it and focus on the unpacking stub
2. Run identify_libraries() to separate user code from library/thunk functions — focus on user code
3. Run map_mitre_attack() to get an ATT&CK triage from imports — this tells you what behaviors to investigate
4. Run extract_iocs() to pull IPs, URLs, domains, file paths, registry keys from strings
5. List functions, strings, imports for the full overview
6. Decompile key functions (prioritize user code identified in step 2)
7. Rename functions with descriptive VIBE_ prefixed names
8. Use notebook_append() to record important findings as you go (C2 addresses, crypto keys, behaviors)
9. Apply data types to function parameters when it improves decompiler readability
10. Add comments to document your findings

Use the notebook to persist key findings — record anything important with notebook_append() so it isn't lost.

{intensity_instructions}

When you've completed your analysis, respond with "ANALYSIS_COMPLETE" and I'll generate the final report."""

        # Initial user message
        initial_message = f"""Analyze the binary for job {self.job_id}.

Start by getting an overview:
1. List all functions to see what we're working with
2. List strings to find interesting clues
3. List imports to understand external dependencies

Then analyze interesting functions in detail by decompiling them. Look for patterns and document your findings."""

        self.messages.append({"role": "user", "content": initial_message})

        # Run agentic loop
        analysis_complete = False
        iteration = 0

        while not analysis_complete and iteration < self.max_iterations:
            iteration += 1

            # Check for cancellation at the start of each iteration
            if self._check_cancelled():
                logger.info(f"Analysis cancelled by user at iteration {iteration}")
                self._log_to_job(f"[CANCELLED] Analysis cancelled by user at iteration {iteration}")
                break

            logger.info(f"LLM iteration {iteration}")
            self._log_to_job(f"[ITERATION {iteration}/{self.max_iterations}]")

            try:
                # Call LLM with tool use
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=4096,
                    system=system_prompt,
                    messages=self.messages,
                    tools=self.get_tool_definitions()
                )

                logger.info(f"LLM response stop_reason: {response.stop_reason}")

                # Log LLM's text responses
                for block in response.content:
                    if hasattr(block, 'text') and block.text:
                        # Log first 200 chars of response
                        text_preview = block.text[:200] + "..." if len(block.text) > 200 else block.text
                        self._log_to_job(f"[ANALYSIS] {text_preview}")

                # Add assistant response to messages
                self.messages.append({"role": "assistant", "content": response.content})

                # Check if analysis is complete
                if response.stop_reason == "end_turn":
                    # Check if LLM said "ANALYSIS_COMPLETE"
                    for block in response.content:
                        if hasattr(block, 'text') and "ANALYSIS_COMPLETE" in block.text:
                            logger.info("Analysis marked complete by LLM")
                            self._log_to_job("[COMPLETE] Analysis finished")
                            analysis_complete = True
                            break

                    if not analysis_complete:
                        # Prompt LLM to continue
                        self.messages.append({
                            "role": "user",
                            "content": "Continue your analysis. What else should we investigate?"
                        })
                        self._log_to_job("[CONTINUE] Prompting LLM for next steps")

                # Execute tool calls
                if response.stop_reason == "tool_use":
                    tool_results = []

                    for block in response.content:
                        if block.type == "tool_use":
                            tool_name = block.name
                            tool_input = block.input
                            tool_id = block.id

                            # Execute tool
                            result = self.execute_tool(tool_name, tool_input)

                            tool_results.append({
                                "type": "tool_result",
                                "tool_use_id": tool_id,
                                "content": json.dumps(result) if not isinstance(result, str) else result
                            })

                    # Add tool results to messages
                    self.messages.append({"role": "user", "content": tool_results})

            except Exception as e:
                error_msg = f"{type(e).__name__}: {e}"
                logger.error(f"LLM iteration {iteration} failed: {error_msg}", exc_info=True)
                self._log_to_job(f"[ERROR] LLM call failed in iteration {iteration}: {error_msg}")
                self.error = error_msg
                break

        if self.error:
            logger.error(f"Analysis aborted after {iteration} iterations due to: {self.error}")
            self._log_to_job(f"[FAILED] Analysis aborted: {self.error}")
        else:
            logger.info(f"Analysis complete after {iteration} iterations, {self.tool_call_count} tool calls")
            self._log_to_job(f"[SUMMARY] Analysis complete: {iteration} iterations, {self.tool_call_count} tool calls")

        # Extract findings from conversation
        return {
            "tool_call_count": self.tool_call_count,
            "iterations": iteration,
            "conversation": self.messages,
            "error": self.error,
        }
