"""
MCP Server for Ghidra Analysis
Exposes Ghidra worker capabilities as standardized MCP tools
"""

import os
import logging
from typing import Optional
from mcp.server.fastmcp import FastMCP
from tools import GhidraTools

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

# Initialize MCP server
mcp = FastMCP("ghidra-agentic-mcp")

# Global configuration
WORKER_URL = os.environ.get("WORKER_URL", "http://worker:8001")
CURRENT_JOB_ID: Optional[str] = None
tools_instance: Optional[GhidraTools] = None


def set_job_context(job_id: str):
    """Set the current job context for tool operations"""
    global CURRENT_JOB_ID, tools_instance
    CURRENT_JOB_ID = job_id
    tools_instance = GhidraTools(WORKER_URL, job_id)
    logger.info(f"Job context set to: {job_id}")


def get_tools() -> GhidraTools:
    """Get the current tools instance"""
    if tools_instance is None:
        raise RuntimeError("Job context not set. Call set_job_context first.")
    return tools_instance


# Register all MCP tools
@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """List all function names in the program with pagination"""
    return get_tools().list_methods(offset, limit)


@mcp.tool()
def list_functions() -> list:
    """List all functions in the database"""
    return get_tools().list_functions()


@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """List all namespace/class names in the program with pagination"""
    return get_tools().list_classes(offset, limit)


@mcp.tool()
def decompile_function(name: str) -> str:
    """Decompile a specific function by name and return the decompiled C code"""
    return get_tools().decompile_function(name)


@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """Decompile a function at the given address"""
    return get_tools().decompile_function_by_address(address)


@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """Rename a function by its current name to a new user-defined name"""
    return get_tools().rename_function(old_name, new_name)


@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """Rename a function by its address"""
    return get_tools().rename_function_by_address(function_address, new_name)


@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """Rename a data label at the specified address"""
    return get_tools().rename_data(address, new_name)


@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """List all defined strings in the program with their addresses"""
    return get_tools().list_strings(offset, limit, filter)


@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """List imported symbols in the program with pagination"""
    return get_tools().list_imports(offset, limit)


@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """List exported functions/symbols with pagination"""
    return get_tools().list_exports(offset, limit)


@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """List all memory segments in the program with pagination"""
    return get_tools().list_segments(offset, limit)


@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """List all non-global namespaces in the program with pagination"""
    return get_tools().list_namespaces(offset, limit)


@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """Search for functions whose name contains the given substring"""
    return get_tools().search_functions_by_name(query, offset, limit)


@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """Get all references to the specified address (xref to)"""
    return get_tools().get_xrefs_to(address, offset, limit)


@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """Get all references from the specified address (xref from)"""
    return get_tools().get_xrefs_from(address, offset, limit)


@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """Get all references to the specified function by name"""
    return get_tools().get_function_xrefs(name, offset, limit)


@mcp.tool()
def disassemble_function(address: str) -> list:
    """Get assembly code (address: instruction; comment) for a function"""
    return get_tools().disassemble_function(address)


# --- Additional analysis tools ---

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """Set a comment at a specific address in the decompiled code"""
    return get_tools().set_decompiler_comment(address, comment)


@mcp.tool()
def get_call_graph(function_name: str, depth: int = 1) -> dict:
    """Get the call graph for a function with configurable depth, thunk resolution, and cycle detection (GB-5)"""
    return get_tools().get_call_graph(function_name, depth)


@mcp.tool()
def get_entropy() -> dict:
    """Compute per-section entropy to detect packing or encryption"""
    return get_tools().get_entropy()


@mcp.tool()
def identify_libraries(offset: int = 0, limit: int = 200) -> dict:
    """Identify library/thunk functions vs user code"""
    return get_tools().identify_libraries(offset, limit)


@mcp.tool()
def list_data_types(filter: str = "", offset: int = 0, limit: int = 100) -> dict:
    """List available data types, optionally filtered by name"""
    return get_tools().list_data_types(filter, offset, limit)


@mcp.tool()
def apply_data_type(function_address: str, param_index: str, type_name: str) -> str:
    """Apply a data type to a function parameter or return type"""
    return get_tools().apply_data_type(function_address, param_index, type_name)


@mcp.tool()
def get_function_signature(name: str) -> dict:
    """Get rich function signature with parameters, locals, pointer info, and xrefs"""
    return get_tools().get_function_signature(name)


# --- GB Enhancement Tools ---

@mcp.tool()
def analyze_basic_blocks(name: str) -> dict:
    """Get basic blocks, control flow graph, back edges, and detected loops for a function (GB-4)"""
    return get_tools().analyze_basic_blocks(name)


@mcp.tool()
def get_variable_slice(function_name: str, variable_name: str, direction: str = "forward") -> dict:
    """Get forward or backward data flow slice for a variable in a function (GB-3)"""
    return get_tools().get_variable_slice(function_name, variable_name, direction)


@mcp.tool()
def reconstruct_imports() -> dict:
    """Reconstruct import table from obfuscated binaries: dynamic loading, hash-based, and string-based API lookups (GB-20)"""
    return get_tools().reconstruct_imports()


@mcp.tool()
def emulate_deobfuscation(start_address: str, end_address: str, write_back: str = "false") -> dict:
    """Emulate a code region to deobfuscate/unpack, tracking all memory writes (GB-19)"""
    return get_tools().emulate_deobfuscation(start_address, end_address, write_back)


@mcp.tool()
def resolve_computed_jump(address: str) -> dict:
    """Resolve a computed/indirect jump using p-code emulation from the function entry (GB-18)"""
    return get_tools().resolve_computed_jump(address)


@mcp.tool()
def find_desync_errors() -> dict:
    """Detect disassembly desync errors, mid-instruction jumps, and undefined executable regions (GB-17)"""
    return get_tools().find_desync_errors()


@mcp.tool()
def detect_loops(name: str) -> dict:
    """Detect and classify loops in a function: natural loops, nesting depth, type, loop-carried variables (GB-16)"""
    return get_tools().detect_loops(name)


@mcp.tool()
def convert_to_code(address: str) -> dict:
    """Undefine bytes at address and disassemble — repairs data misclassified as code (GB-15)"""
    return get_tools().convert_to_code(address)


@mcp.tool()
def convert_to_data(address: str, data_type: str = "byte", count: int = 1) -> dict:
    """Define code/undefined bytes as typed data — repairs code misclassified as data (GB-15)"""
    return get_tools().convert_to_data(address, data_type, count)


@mcp.tool()
def undefine_bytes(address: str) -> dict:
    """Clear all code and data definitions at an address, leaving bytes undefined (GB-15)"""
    return get_tools().undefine_bytes(address)


@mcp.tool()
def set_equate(address: str, operand_index: int, equate_name: str) -> dict:
    """Apply a named constant (equate) to an instruction operand, replacing opaque hex values (GB-14)"""
    return get_tools().set_equate(address, operand_index, equate_name)


@mcp.tool()
def suggest_equates(address: str) -> dict:
    """Suggest named constants for all scalar operands at an instruction address (GB-14)"""
    return get_tools().suggest_equates(address)


@mcp.tool()
def set_repeatable_comment(address: str, comment: str) -> dict:
    """Set a repeatable comment that auto-propagates to all cross-reference source locations (GB-13)"""
    return get_tools().set_repeatable_comment(address, comment)


@mcp.tool()
def set_function_attributes(name: str, attribute: str, value: str = "true") -> dict:
    """Set a function attribute: noreturn, varargs, calling_convention, inline, or custom_storage (GB-12)"""
    return get_tools().set_function_attributes(name, attribute, value)


@mcp.tool()
def get_function_attributes(name: str) -> dict:
    """Get all attributes of a function (noreturn, varargs, calling convention, inline, etc.) (GB-12)"""
    return get_tools().get_function_attributes(name)


@mcp.tool()
def analyze_cpp_classes() -> dict:
    """Analyze C++ class hierarchy via vftable detection, RTTI parsing, and constructor identification (GB-10)"""
    return get_tools().analyze_cpp_classes()


@mcp.tool()
def detect_arrays(name: str) -> dict:
    """Detect array patterns from scaling operations, global data sequences, and indexed access (GB-9)"""
    return get_tools().detect_arrays(name)


@mcp.tool()
def detect_switch(name: str) -> dict:
    """Detect switch statement implementations: jump tables (dense) and binary search trees (sparse) (GB-6)"""
    return get_tools().detect_switch(name)


@mcp.tool()
def auto_create_structure(name: str) -> dict:
    """Auto-create structure definitions from pointer offset patterns in a function (GB-2)"""
    return get_tools().auto_create_structure(name)


# --- Pure Python tools (no Ghidra backend) ---

@mcp.tool()
def extract_iocs() -> dict:
    """Extract IOCs (IPs, URLs, domains, paths, registry keys) from binary strings"""
    return get_tools().extract_iocs()


@mcp.tool()
def map_mitre_attack() -> dict:
    """Map imported APIs to MITRE ATT&CK techniques"""
    return get_tools().map_mitre_attack()


@mcp.tool()
def notebook_read() -> dict:
    """Read the analysis notebook for this job"""
    return get_tools().notebook_read()


@mcp.tool()
def notebook_append(category: str, content: str) -> dict:
    """Append a finding to the analysis notebook"""
    return get_tools().notebook_append(category, content)


if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--worker-url", type=str, default=WORKER_URL,
                        help=f"Worker URL, default: {WORKER_URL}")
    parser.add_argument("--job-id", type=str, required=True,
                        help="Job ID to analyze")
    args = parser.parse_args()

    # Set job context
    set_job_context(args.job_id)

    logger.info(f"Starting MCP server for job: {args.job_id}")
    logger.info(f"Worker URL: {args.worker_url}")

    # Run MCP server in stdio mode
    mcp.run()
