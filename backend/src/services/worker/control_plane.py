"""
Control plane API for Ghidra worker
Exposes HTTP endpoints that match the expected MCP bridge interface
"""

import os
import json
import base64
import logging
from pathlib import Path
from typing import Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from src.services.worker.ghidra_runner import GhidraRunner
from src.services.worker.security import validate_job_id, validate_file_path

logger = logging.getLogger(__name__)

app = FastAPI(title="Ghidra Worker Control Plane")

# Global state: job_id -> GhidraRunner
runners: Dict[str, GhidraRunner] = {}


class ImportRequest(BaseModel):
    binary_path: str


class DecompileRequest(BaseModel):
    name: Optional[str] = None
    address: Optional[str] = None


class RenameRequest(BaseModel):
    oldName: Optional[str] = None
    newName: Optional[str] = None
    old_name: Optional[str] = None
    new_name: Optional[str] = None
    address: Optional[str] = None
    function_address: Optional[str] = None


class CommentRequest(BaseModel):
    address: str
    comment: str


class PrototypeRequest(BaseModel):
    function_address: str
    prototype: str


class VariableTypeRequest(BaseModel):
    function_address: str
    variable_name: str
    new_type: str


def get_runner(job_id: str, intensity: str = "standard") -> GhidraRunner:
    """Get or create a GhidraRunner for a job (GB-11: intensity controls analysis config)"""
    if job_id not in runners:
        data_dir = os.environ.get("DATA_DIR", "/app/data")
        runners[job_id] = GhidraRunner(job_id, data_dir, intensity=intensity)
    return runners[job_id]


@app.get("/health")
def health_check():
    return {"status": "healthy", "active_jobs": len(runners)}


@app.post("/jobs/{job_id}/import")
def import_binary(job_id: str, request: ImportRequest, intensity: str = Query("standard")):
    """Import a binary into Ghidra project (GB-11: intensity controls timeouts)"""
    # Validate job_id format (CRITICAL-01)
    if not validate_job_id(job_id):
        raise HTTPException(status_code=400, detail="Invalid job_id format")

    # Validate intensity preset
    if intensity not in ("quick", "standard", "deep"):
        intensity = "standard"

    # Validate binary_path is within allowed data directory (CRITICAL-03)
    data_dir = Path(os.environ.get("DATA_DIR", "/app/data"))
    try:
        binary_path = validate_file_path(request.binary_path, data_dir)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))

    runner = get_runner(job_id, intensity=intensity)
    result = runner.import_binary(str(binary_path))
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("error"))
    return result


@app.get("/jobs/{job_id}/methods")
def list_methods(job_id: str, offset: int = 0, limit: int = 100):
    """List all function names (methods) in the program"""
    runner = get_runner(job_id)
    output = runner.run_script("list_functions.py", str(offset), str(limit))
    try:
        data = json.loads(output)
        # Return as array of strings for compatibility with bridge
        return [f"{func['address']}: {func['name']}" for func in data.get("functions", [])]
    except json.JSONDecodeError:
        return [output]


@app.get("/jobs/{job_id}/list_functions")
def list_functions_full(job_id: str):
    """List all functions in the database (full details)"""
    runner = get_runner(job_id)
    output = runner.run_script("list_functions.py", "0", "1000")
    try:
        data = json.loads(output)
        return [f"{func['address']}: {func['name']}" for func in data.get("functions", [])]
    except json.JSONDecodeError:
        return [output]


@app.get("/jobs/{job_id}/classes")
def list_classes(job_id: str, offset: int = 0, limit: int = 100):
    """List all namespace/class names"""
    runner = get_runner(job_id)
    output = runner.run_script("list_namespaces.py", str(offset), str(limit))
    try:
        return json.loads(output) if isinstance(output, str) else output
    except json.JSONDecodeError:
        return [output]


@app.post("/jobs/{job_id}/decompile")
def decompile_function(job_id: str, name: str = None):
    """Decompile a function by name or address"""
    if not name:
        raise HTTPException(status_code=400, detail="Function name required")

    runner = get_runner(job_id)
    output = runner.run_script("decompile.py", name)
    return output


@app.get("/jobs/{job_id}/decompile_function")
def decompile_function_by_address(job_id: str, address: str = Query(...)):
    """Decompile a function at a specific address"""
    runner = get_runner(job_id)
    output = runner.run_script("decompile.py", address)
    return [output]


@app.post("/jobs/{job_id}/renameFunction")
def rename_function(job_id: str, request: RenameRequest):
    """Rename a function"""
    old_name = request.oldName or request.old_name
    new_name = request.newName or request.new_name

    if not old_name or not new_name:
        raise HTTPException(status_code=400, detail="Both old and new names required")

    runner = get_runner(job_id)
    output = runner.run_script("rename.py", "function", old_name, new_name)
    return output


@app.post("/jobs/{job_id}/rename_function_by_address")
def rename_function_by_address(job_id: str, request: RenameRequest):
    """Rename a function by address"""
    if not request.function_address or not request.new_name:
        raise HTTPException(status_code=400, detail="Function address and new name required")

    runner = get_runner(job_id)
    output = runner.run_script("rename.py", "function_by_address", request.function_address, request.new_name)
    return output


@app.post("/jobs/{job_id}/renameData")
def rename_data(job_id: str, request: RenameRequest):
    """Rename a data label at an address"""
    if not request.address or not request.newName:
        raise HTTPException(status_code=400, detail="Address and new name required")

    runner = get_runner(job_id)
    output = runner.run_script("rename.py", "data", request.address, request.newName)
    return output


@app.get("/jobs/{job_id}/strings")
def list_strings(job_id: str, offset: int = 0, limit: int = 2000, filter: Optional[str] = None):
    """List defined strings in the program"""
    runner = get_runner(job_id)
    args = [str(offset), str(limit)]
    if filter:
        args.append(filter)

    output = runner.run_script("get_strings.py", *args)
    try:
        data = json.loads(output)
        return data.get("strings", [output])
    except json.JSONDecodeError:
        return [output]


@app.get("/jobs/{job_id}/imports")
def list_imports(job_id: str, offset: int = 0, limit: int = 100):
    """List imported symbols"""
    runner = get_runner(job_id)
    output = runner.run_script("get_imports_exports.py", "imports", str(offset), str(limit))
    try:
        data = json.loads(output)
        return data.get("imports", [])
    except json.JSONDecodeError:
        return [output]


@app.get("/jobs/{job_id}/exports")
def list_exports(job_id: str, offset: int = 0, limit: int = 100):
    """List exported symbols"""
    runner = get_runner(job_id)
    output = runner.run_script("get_imports_exports.py", "exports", str(offset), str(limit))
    try:
        data = json.loads(output)
        return data.get("exports", [])
    except json.JSONDecodeError:
        return [output]


@app.get("/jobs/{job_id}/xrefs_to")
def get_xrefs_to(job_id: str, address: str = Query(...), offset: int = 0, limit: int = 100):
    """Get cross-references to an address"""
    runner = get_runner(job_id)
    output = runner.run_script("get_xrefs.py", "to", address, str(offset), str(limit))
    try:
        data = json.loads(output)
        return data.get("xrefs", [])
    except json.JSONDecodeError:
        return [output]


@app.get("/jobs/{job_id}/xrefs_from")
def get_xrefs_from(job_id: str, address: str = Query(...), offset: int = 0, limit: int = 100):
    """Get cross-references from an address"""
    runner = get_runner(job_id)
    output = runner.run_script("get_xrefs.py", "from", address, str(offset), str(limit))
    try:
        data = json.loads(output)
        return data.get("xrefs", [])
    except json.JSONDecodeError:
        return [output]


@app.get("/jobs/{job_id}/function_xrefs")
def get_function_xrefs(job_id: str, name: str = Query(...), offset: int = 0, limit: int = 100):
    """Get cross-references to a function by name"""
    runner = get_runner(job_id)
    output = runner.run_script("get_xrefs.py", "function", name, str(offset), str(limit))
    try:
        data = json.loads(output)
        return data.get("xrefs", [])
    except json.JSONDecodeError:
        return [output]


@app.get("/jobs/{job_id}/segments")
def list_segments(job_id: str, offset: int = 0, limit: int = 100):
    """List memory segments"""
    runner = get_runner(job_id)
    output = runner.run_script("list_segments.py", str(offset), str(limit))
    try:
        data = json.loads(output)
        return data.get("segments", [])
    except json.JSONDecodeError:
        return [output]


@app.get("/jobs/{job_id}/namespaces")
def list_namespaces(job_id: str, offset: int = 0, limit: int = 100):
    """List namespaces"""
    runner = get_runner(job_id)
    output = runner.run_script("list_namespaces.py", str(offset), str(limit))
    try:
        data = json.loads(output)
        return data.get("namespaces", [])
    except json.JSONDecodeError:
        return [output]


@app.get("/jobs/{job_id}/searchFunctions")
def search_functions(job_id: str, query: str = Query(...), offset: int = 0, limit: int = 100):
    """Search for functions by name substring"""
    runner = get_runner(job_id)
    output = runner.run_script("search_functions.py", query, str(offset), str(limit))
    try:
        data = json.loads(output)
        return data.get("functions", [])
    except json.JSONDecodeError:
        return [output]


@app.get("/jobs/{job_id}/disassemble_function")
def disassemble_function(job_id: str, address: str = Query(...)):
    """Get disassembly for a function"""
    runner = get_runner(job_id)
    output = runner.run_script("disassemble.py", address)
    try:
        data = json.loads(output)
        return data.get("disassembly", [])
    except json.JSONDecodeError:
        return [output]


@app.post("/jobs/{job_id}/set_comment")
def set_comment(job_id: str, request: CommentRequest):
    """Set a comment at a specific address"""
    runner = get_runner(job_id)
    # URL-safe base64 without padding (all chars pass arg sanitization)
    b64_comment = base64.urlsafe_b64encode(request.comment.encode("utf-8")).decode("ascii").rstrip("=")
    output = runner.run_script("set_comment.py", request.address, b64_comment)
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": output}


@app.get("/jobs/{job_id}/call_graph")
def get_call_graph(job_id: str, function_name: str = Query(...), depth: int = Query(1)):
    """Get call graph for a function with configurable depth, thunk resolution, and cycle detection (GB-5)"""
    depth = min(max(depth, 1), 5)  # Clamp 1-5
    runner = get_runner(job_id)
    output = runner.run_script("get_call_graph.py", function_name, str(depth))
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": output}


@app.get("/jobs/{job_id}/entropy")
def get_entropy(job_id: str):
    """Compute per-section entropy for packing/encryption detection"""
    runner = get_runner(job_id)
    output = runner.run_script("get_entropy.py")
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": output}


@app.get("/jobs/{job_id}/identify_libraries")
def identify_libraries(job_id: str, offset: int = 0, limit: int = 200):
    """Identify library vs user functions"""
    runner = get_runner(job_id)
    output = runner.run_script("identify_libraries.py", str(offset), str(limit))
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": output}


@app.get("/jobs/{job_id}/data_types")
def list_data_types(job_id: str, filter: str = "", offset: int = 0, limit: int = 100):
    """List available data types"""
    runner = get_runner(job_id)
    args = [filter, str(offset), str(limit)] if filter else ["", str(offset), str(limit)]
    output = runner.run_script("list_data_types.py", *args)
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": output}


class ApplyTypeRequest(BaseModel):
    function_address: str
    param_index: str  # integer index or "return"
    type_name: str


@app.post("/jobs/{job_id}/apply_data_type")
def apply_data_type(job_id: str, request: ApplyTypeRequest):
    """Apply a data type to a function parameter or return type"""
    runner = get_runner(job_id)
    output = runner.run_script(
        "apply_data_type.py",
        request.function_address,
        request.param_index,
        request.type_name
    )
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": output}


@app.get("/jobs/{job_id}/function_signature")
def get_function_signature(job_id: str, name: str = Query(...)):
    """Get rich function signature with parameters, locals, pointer info, and xrefs"""
    runner = get_runner(job_id)
    output = runner.run_script("get_function_signature.py", name)
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": output}


@app.get("/jobs/{job_id}/detect_switch")
def detect_switch(job_id: str, name: str = Query(...)):
    """Detect switch statement implementations (jump table vs binary search) in a function (GB-6)"""
    runner = get_runner(job_id)
    output = runner.run_script("detect_switch.py", name)
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": output}


@app.get("/jobs/{job_id}/reconstruct_imports")
def reconstruct_imports(job_id: str):
    """Reconstruct import table from obfuscated binaries: dynamic loading, hash-based, string-based patterns (GB-20)"""
    runner = get_runner(job_id)
    output = runner.run_script("reconstruct_imports.py")
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": output}


@app.post("/jobs/{job_id}/emulate_deobfuscation")
def emulate_deobfuscation(job_id: str, start_address: str = Query(...), end_address: str = Query(...), write_back: str = Query("false")):
    """Emulate a code region to deobfuscate/unpack and optionally write decoded bytes back (GB-19)"""
    runner = get_runner(job_id)
    output = runner.run_script("emulate_deobfuscation.py", start_address, end_address, write_back)
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": output}


@app.get("/jobs/{job_id}/resolve_computed_jump")
def resolve_computed_jump(job_id: str, address: str = Query(...)):
    """Resolve a computed/indirect jump via p-code emulation (GB-18)"""
    runner = get_runner(job_id)
    output = runner.run_script("resolve_computed_jump.py", address)
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": output}


@app.get("/jobs/{job_id}/find_desync_errors")
def find_desync_errors(job_id: str):
    """Detect disassembly desynchronization errors, mid-instruction jumps, and undefined executable regions (GB-17)"""
    runner = get_runner(job_id)
    output = runner.run_script("find_desync_errors.py")
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": output}


@app.get("/jobs/{job_id}/detect_loops")
def detect_loops(job_id: str, name: str = Query(...)):
    """Detect and classify loops: back edges, natural loop bodies, nesting depth, type classification (GB-16)"""
    runner = get_runner(job_id)
    output = runner.run_script("detect_loops.py", name)
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": output}


@app.post("/jobs/{job_id}/convert_to_code")
def convert_to_code(job_id: str, address: str = Query(...)):
    """Undefine bytes and disassemble from address — repairs misclassified data (GB-15)"""
    runner = get_runner(job_id)
    output = runner.run_script("convert_code_data.py", "to_code", address)
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": output}


@app.post("/jobs/{job_id}/convert_to_data")
def convert_to_data(job_id: str, address: str = Query(...), data_type: str = Query("byte"), count: str = Query("1")):
    """Define code/undefined bytes as typed data — repairs misclassified code (GB-15)"""
    runner = get_runner(job_id)
    output = runner.run_script("convert_code_data.py", "to_data", address, data_type, count)
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": output}


@app.post("/jobs/{job_id}/undefine_bytes")
def undefine_bytes(job_id: str, address: str = Query(...)):
    """Clear all code/data definitions at an address (GB-15)"""
    runner = get_runner(job_id)
    output = runner.run_script("convert_code_data.py", "undefine", address)
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": output}


@app.post("/jobs/{job_id}/set_equate")
def set_equate(job_id: str, address: str = Query(...), operand_index: str = Query(...), equate_name: str = Query(...)):
    """Apply a named constant (equate) to an instruction operand (GB-14)"""
    runner = get_runner(job_id)
    output = runner.run_script("set_equate.py", address, operand_index, equate_name)
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": output}


@app.get("/jobs/{job_id}/suggest_equates")
def suggest_equates(job_id: str, address: str = Query(...)):
    """Suggest named constants for scalar operands at an address (GB-14)"""
    runner = get_runner(job_id)
    output = runner.run_script("set_equate.py", address, "suggest")
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": output}


@app.post("/jobs/{job_id}/set_function_attributes")
def set_function_attributes(job_id: str, name: str = Query(...), attribute: str = Query(...), value: str = Query("true")):
    """Set function attributes: noreturn, varargs, calling_convention, inline, custom_storage (GB-12)"""
    runner = get_runner(job_id)
    output = runner.run_script("set_function_attributes.py", name, attribute, value)
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": output}


@app.post("/jobs/{job_id}/set_repeatable_comment")
def set_repeatable_comment(job_id: str, address: str = Query(...), comment: str = Query(...)):
    """Set a repeatable comment that propagates to all xref sources (GB-13)"""
    runner = get_runner(job_id)
    output = runner.run_script("set_repeatable_comment.py", address, comment)
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": output}


@app.get("/jobs/{job_id}/get_function_attributes")
def get_function_attributes(job_id: str, name: str = Query(...)):
    """Get all function attributes for a function (GB-12)"""
    runner = get_runner(job_id)
    output = runner.run_script("set_function_attributes.py", name, "get")
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": output}


@app.get("/jobs/{job_id}/analyze_cpp_classes")
def analyze_cpp_classes(job_id: str):
    """Analyze C++ class hierarchy via vftable and RTTI detection (GB-10)"""
    runner = get_runner(job_id)
    output = runner.run_script("analyze_cpp_classes.py")
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": output}


@app.get("/jobs/{job_id}/detect_arrays")
def detect_arrays(job_id: str, name: str = Query(...)):
    """Detect array patterns from scaling operations in a function (GB-9)"""
    runner = get_runner(job_id)
    output = runner.run_script("detect_arrays.py", name)
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": output}


@app.get("/jobs/{job_id}/analyze_basic_blocks")
def analyze_basic_blocks(job_id: str, name: str = Query(...)):
    """Get basic blocks, CFG edges, back edges, and loop detection for a function (GB-4)"""
    runner = get_runner(job_id)
    output = runner.run_script("analyze_basic_blocks.py", name)
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": output}


class VariableSliceRequest(BaseModel):
    function_name: str
    variable_name: str
    direction: str  # "forward" or "backward"


@app.get("/jobs/{job_id}/variable_slice")
def get_variable_slice(job_id: str, function_name: str = Query(...), variable_name: str = Query(...), direction: str = Query("forward")):
    """Get forward or backward data flow slice for a variable in a function (GB-3)"""
    if direction not in ("forward", "backward"):
        raise HTTPException(status_code=400, detail="Direction must be 'forward' or 'backward'")
    runner = get_runner(job_id)
    output = runner.run_script("get_variable_slice.py", function_name, variable_name, direction)
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": output}


@app.get("/jobs/{job_id}/auto_create_structure")
def auto_create_structure(job_id: str, name: str = Query(...)):
    """Auto-create structure definitions from pointer offset patterns in a function (GB-2)"""
    runner = get_runner(job_id)
    output = runner.run_script("auto_create_structure.py", name)
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": output}


@app.get("/jobs/{job_id}/export_annotations")
def export_annotations(job_id: str):
    """Export annotated functions (renamed functions, comments, decompiled code)"""
    if not validate_job_id(job_id):
        raise HTTPException(status_code=400, detail="Invalid job_id format")

    runner = get_runner(job_id)
    data_dir = Path(os.environ.get("DATA_DIR", "/app/data"))
    export_path = data_dir / "jobs" / job_id / "report" / "annotations.txt"

    # Create report directory if it doesn't exist
    export_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        output = runner.run_script("export_annotations.py", str(export_path))
        result = json.loads(output)

        if result.get("success"):
            return {"success": True, "path": str(export_path), "stats": result}
        else:
            raise HTTPException(status_code=500, detail=f"Export failed: {result.get('error')}")
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail=f"Export failed: {output}")
    except Exception as e:
        logger.error(f"Annotation export failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
