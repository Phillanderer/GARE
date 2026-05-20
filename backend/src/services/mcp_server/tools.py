"""
MCP tools that wrap Ghidra worker endpoints
Provides a standardized interface for LLM agents
"""

import json
import requests
import logging
from pathlib import Path
from typing import Optional, List, Union, Dict, Any
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


class GhidraTools:
    """MCP-compatible tools for Ghidra analysis"""

    def __init__(self, worker_url: str, job_id: str, data_dir: str = "/app/data"):
        self.worker_url = worker_url
        self.job_id = job_id
        self.data_dir = Path(data_dir)
        self.base_url = urljoin(worker_url, f"/jobs/{job_id}/")

    def _safe_get(self, endpoint: str, params: dict = None) -> Union[List[str], str]:
        """Perform GET request with error handling"""
        try:
            url = urljoin(self.base_url, endpoint)
            response = requests.get(url, params=params or {}, timeout=30)
            response.encoding = 'utf-8'

            if response.ok:
                data = response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text
                if isinstance(data, list):
                    return [str(item) for item in data]
                return data
            else:
                return [f"Error {response.status_code}: {response.text}"]
        except Exception as e:
            logger.error(f"GET {endpoint} failed: {e}")
            return [f"Request failed: {str(e)}"]

    def _safe_post(self, endpoint: str, data: Union[dict, str]) -> str:
        """Perform POST request with error handling"""
        try:
            url = urljoin(self.base_url, endpoint)

            if isinstance(data, dict):
                response = requests.post(url, json=data, timeout=30)
            else:
                response = requests.post(url, data=data, timeout=30)

            response.encoding = 'utf-8'

            if response.ok:
                return response.text
            else:
                return f"Error {response.status_code}: {response.text}"
        except Exception as e:
            logger.error(f"POST {endpoint} failed: {e}")
            return f"Request failed: {str(e)}"

    def list_methods(self, offset: int = 0, limit: int = 100) -> List[str]:
        """List all function names in the program with pagination"""
        return self._safe_get("methods", {"offset": offset, "limit": limit})

    def list_functions(self) -> List[str]:
        """List all functions in the database"""
        return self._safe_get("list_functions")

    def list_classes(self, offset: int = 0, limit: int = 100) -> List[str]:
        """List all namespace/class names in the program with pagination"""
        return self._safe_get("classes", {"offset": offset, "limit": limit})

    def decompile_function(self, name: str) -> str:
        """Decompile a specific function by name and return decompiled C code"""
        # Send name as query parameter, not body
        try:
            url = urljoin(self.base_url, "decompile")
            response = requests.post(url, params={"name": name}, timeout=60)
            response.encoding = 'utf-8'

            if response.ok:
                return response.text
            else:
                return f"Error {response.status_code}: {response.text}"
        except Exception as e:
            logger.error(f"POST decompile failed: {e}")
            return f"Request failed: {str(e)}"

    def decompile_function_by_address(self, address: str) -> str:
        """Decompile a function at the given address"""
        result = self._safe_get("decompile_function", {"address": address})
        return "\n".join(result) if isinstance(result, list) else result

    def rename_function(self, old_name: str, new_name: str) -> str:
        """Rename a function by its current name to a new user-defined name"""
        return self._safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

    def rename_function_by_address(self, function_address: str, new_name: str) -> str:
        """Rename a function by its address"""
        return self._safe_post("rename_function_by_address", {
            "function_address": function_address,
            "new_name": new_name
        })

    def rename_data(self, address: str, new_name: str) -> str:
        """Rename a data label at the specified address"""
        return self._safe_post("renameData", {"address": address, "newName": new_name})

    def list_strings(self, offset: int = 0, limit: int = 2000, filter: Optional[str] = None) -> List[str]:
        """List all defined strings in the program with their addresses"""
        params = {"offset": offset, "limit": limit}
        if filter:
            params["filter"] = filter
        return self._safe_get("strings", params)

    def list_imports(self, offset: int = 0, limit: int = 100) -> List[str]:
        """List imported symbols in the program with pagination"""
        return self._safe_get("imports", {"offset": offset, "limit": limit})

    def list_exports(self, offset: int = 0, limit: int = 100) -> List[str]:
        """List exported functions/symbols with pagination"""
        return self._safe_get("exports", {"offset": offset, "limit": limit})

    def list_segments(self, offset: int = 0, limit: int = 100) -> List[str]:
        """List all memory segments in the program with pagination"""
        return self._safe_get("segments", {"offset": offset, "limit": limit})

    def list_namespaces(self, offset: int = 0, limit: int = 100) -> List[str]:
        """List all non-global namespaces in the program with pagination"""
        return self._safe_get("namespaces", {"offset": offset, "limit": limit})

    def search_functions_by_name(self, query: str, offset: int = 0, limit: int = 100) -> List[str]:
        """Search for functions whose name contains the given substring"""
        if not query:
            return ["Error: query string is required"]
        return self._safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

    def get_xrefs_to(self, address: str, offset: int = 0, limit: int = 100) -> List[str]:
        """Get all references to the specified address (xref to)"""
        return self._safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

    def get_xrefs_from(self, address: str, offset: int = 0, limit: int = 100) -> List[str]:
        """Get all references from the specified address (xref from)"""
        return self._safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

    def get_function_xrefs(self, name: str, offset: int = 0, limit: int = 100) -> List[str]:
        """Get all references to the specified function by name"""
        return self._safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

    def disassemble_function(self, address: str) -> List[str]:
        """Get assembly code (address: instruction; comment) for a function"""
        return self._safe_get("disassemble_function", {"address": address})

    def set_decompiler_comment(self, address: str, comment: str) -> str:
        """Set a comment at a specific address in the decompiled code"""
        return self._safe_post("set_comment", {"address": address, "comment": comment})

    def get_call_graph(self, function_name: str, depth: int = 1) -> Union[dict, str]:
        """Get the call graph for a function with configurable depth, thunk resolution, and cycle detection (GB-5)"""
        result = self._safe_get("call_graph", {"function_name": function_name, "depth": depth})
        return result

    # --- Entropy / Packing Detection ---

    def get_entropy(self) -> Union[dict, str]:
        """Compute per-section entropy to detect packing or encryption"""
        return self._safe_get("entropy")

    # --- Library Identification ---

    def identify_libraries(self, offset: int = 0, limit: int = 200) -> Union[dict, str]:
        """Identify library/thunk functions vs user code"""
        return self._safe_get("identify_libraries", {"offset": offset, "limit": limit})

    # --- Data Type Tools ---

    def list_data_types(self, filter: str = "", offset: int = 0, limit: int = 100) -> Union[dict, str]:
        """List available data types, optionally filtered by name"""
        params = {"offset": offset, "limit": limit}
        if filter:
            params["filter"] = filter
        return self._safe_get("data_types", params)

    def apply_data_type(self, function_address: str, param_index: str, type_name: str) -> str:
        """Apply a data type to a function parameter or return type"""
        return self._safe_post("apply_data_type", {
            "function_address": function_address,
            "param_index": param_index,
            "type_name": type_name
        })

    # --- Function Signature & Parameter Recovery ---

    def get_function_signature(self, name: str) -> Union[dict, str]:
        """Get rich function signature with parameters, locals, pointer info, and xrefs"""
        return self._safe_get("function_signature", {"name": name})

    # --- Basic Block / CFG Analysis (GB-4) ---

    def analyze_basic_blocks(self, name: str) -> Union[dict, str]:
        """Get basic blocks, control flow graph, back edges, and detected loops for a function"""
        return self._safe_get("analyze_basic_blocks", {"name": name})

    # --- Variable Slicing (GB-3) ---

    def get_variable_slice(self, function_name: str, variable_name: str, direction: str = "forward") -> Union[dict, str]:
        """Get forward or backward data flow slice for a variable in a function"""
        return self._safe_get("variable_slice", {
            "function_name": function_name,
            "variable_name": variable_name,
            "direction": direction
        })

    # --- Import Reconstruction (GB-20) ---

    def reconstruct_imports(self) -> Union[dict, str]:
        """Reconstruct import table from obfuscated binaries: dynamic loading, hash-based, and string-based API lookups"""
        return self._safe_get("reconstruct_imports")

    # --- Emulation Deobfuscation (GB-19) ---

    def emulate_deobfuscation(self, start_address: str, end_address: str, write_back: str = "false") -> Union[dict, str]:
        """Emulate a code region to deobfuscate/unpack, tracking all memory writes. Optionally writes decoded bytes back."""
        return self._safe_get("emulate_deobfuscation", {
            "start_address": start_address,
            "end_address": end_address,
            "write_back": write_back
        })

    # --- Computed Jump Resolution (GB-18) ---

    def resolve_computed_jump(self, address: str) -> Union[dict, str]:
        """Resolve a computed/indirect jump using p-code emulation from the function entry"""
        return self._safe_get("resolve_computed_jump", {"address": address})

    # --- Desync Error Detection (GB-17) ---

    def find_desync_errors(self) -> Union[dict, str]:
        """Detect disassembly desync errors, mid-instruction jumps, and undefined executable regions"""
        return self._safe_get("find_desync_errors")

    # --- Loop Detection (GB-16) ---

    def detect_loops(self, name: str) -> Union[dict, str]:
        """Detect and classify loops in a function: natural loops from back edges, nesting depth, type, loop-carried variables"""
        return self._safe_get("detect_loops", {"name": name})

    # --- Code/Data Boundary Repair (GB-15) ---

    def convert_to_code(self, address: str) -> Union[dict, str]:
        """Undefine bytes at address and disassemble — repairs data misclassified as code or missed functions"""
        return self._safe_get("convert_to_code", {"address": address})

    def convert_to_data(self, address: str, data_type: str = "byte", count: int = 1) -> Union[dict, str]:
        """Define code/undefined bytes as typed data — repairs code misclassified as data (jump tables, string tables)"""
        return self._safe_get("convert_to_data", {"address": address, "data_type": data_type, "count": str(count)})

    def undefine_bytes(self, address: str) -> Union[dict, str]:
        """Clear all code and data definitions at an address, leaving bytes undefined"""
        return self._safe_get("undefine_bytes", {"address": address})

    # --- Named Constants / Equates (GB-14) ---

    def set_equate(self, address: str, operand_index: int, equate_name: str) -> Union[dict, str]:
        """Apply a named constant (equate) to an instruction operand, replacing opaque hex values"""
        return self._safe_get("set_equate", {"address": address, "operand_index": str(operand_index), "equate_name": equate_name})

    def suggest_equates(self, address: str) -> Union[dict, str]:
        """Suggest named constants for all scalar operands at an instruction address"""
        return self._safe_get("suggest_equates", {"address": address})

    # --- Repeatable Comments (GB-13) ---

    def set_repeatable_comment(self, address: str, comment: str) -> Union[dict, str]:
        """Set a repeatable comment that auto-propagates to all cross-reference source locations"""
        return self._safe_get("set_repeatable_comment", {"address": address, "comment": comment})

    # --- Function Attributes (GB-12) ---

    def set_function_attributes(self, name: str, attribute: str, value: str = "true") -> Union[dict, str]:
        """Set a function attribute: noreturn, varargs, calling_convention, inline, or custom_storage"""
        return self._safe_get("set_function_attributes", {"name": name, "attribute": attribute, "value": value})

    def get_function_attributes(self, name: str) -> Union[dict, str]:
        """Get all attributes of a function (noreturn, varargs, calling convention, inline, etc.)"""
        return self._safe_get("get_function_attributes", {"name": name})

    # --- C++ Class Analysis (GB-10) ---

    def analyze_cpp_classes(self) -> Union[dict, str]:
        """Analyze C++ class hierarchy via vftable detection, RTTI parsing, and constructor identification"""
        return self._safe_get("analyze_cpp_classes")

    # --- Array Detection (GB-9) ---

    def detect_arrays(self, name: str) -> Union[dict, str]:
        """Detect array patterns from scaling operations, global data sequences, and indexed access in a function"""
        return self._safe_get("detect_arrays", {"name": name})

    # --- Switch Statement Detection (GB-6) ---

    def detect_switch(self, name: str) -> Union[dict, str]:
        """Detect switch statement implementations in a function: jump tables (dense) and binary search trees (sparse)"""
        return self._safe_get("detect_switch", {"name": name})

    # --- Auto Structure Creation (GB-2) ---

    def auto_create_structure(self, name: str) -> Union[dict, str]:
        """Auto-create structure definitions from pointer offset patterns in a function"""
        return self._safe_get("auto_create_structure", {"name": name})

    # --- IOC Extraction (pure Python, no Ghidra) ---

    def extract_iocs(self) -> Dict[str, Any]:
        """Extract IOCs (IPs, URLs, domains, paths, registry keys) from binary strings"""
        try:
            from src.services.agent.ioc_extractor import extract_iocs
            # Fetch all strings from the binary
            strings = self.list_strings(offset=0, limit=5000)
            if isinstance(strings, list):
                result = extract_iocs(strings)
                result["source_string_count"] = len(strings)
                return result
            return {"error": "Failed to fetch strings", "raw": str(strings)}
        except Exception as e:
            logger.error(f"IOC extraction failed: {e}")
            return {"error": str(e)}

    # --- MITRE ATT&CK Mapping (pure Python, no Ghidra) ---

    def map_mitre_attack(self) -> Dict[str, Any]:
        """Map imported APIs to MITRE ATT&CK techniques"""
        try:
            from src.services.agent.mitre_mapping import map_imports_to_attack
            # Fetch all imports
            imports = self.list_imports(offset=0, limit=500)
            if isinstance(imports, list):
                return map_imports_to_attack(imports)
            return {"error": "Failed to fetch imports", "raw": str(imports)}
        except Exception as e:
            logger.error(f"MITRE mapping failed: {e}")
            return {"error": str(e)}

    # --- Structured Notebook (file-based, no Ghidra) ---

    def notebook_read(self) -> Dict[str, Any]:
        """Read the analysis notebook for this job"""
        notebook_path = self.data_dir / "jobs" / self.job_id / "artifacts" / "notebook.json"
        try:
            if notebook_path.exists():
                with open(notebook_path, 'r') as f:
                    return json.load(f)
            return {"entries": [], "count": 0}
        except Exception as e:
            logger.error(f"Notebook read failed: {e}")
            return {"error": str(e)}

    def notebook_append(self, category: str, content: str) -> Dict[str, Any]:
        """Append a finding to the analysis notebook"""
        notebook_path = self.data_dir / "jobs" / self.job_id / "artifacts" / "notebook.json"
        try:
            notebook_path.parent.mkdir(parents=True, exist_ok=True)

            # Read existing
            if notebook_path.exists():
                with open(notebook_path, 'r') as f:
                    notebook = json.load(f)
            else:
                notebook = {"entries": []}

            # Append entry
            from src.utils.timezone import utc_now
            entry = {
                "category": category,
                "content": content,
                "timestamp": utc_now().isoformat()
            }
            notebook["entries"].append(entry)
            notebook["count"] = len(notebook["entries"])

            # Write back
            with open(notebook_path, 'w') as f:
                json.dump(notebook, f, indent=2)

            return {"success": True, "entry_number": len(notebook["entries"]), "entry": entry}
        except Exception as e:
            logger.error(f"Notebook append failed: {e}")
            return {"error": str(e)}
