"""
Main API server for Ghidra Agentic RE Pipeline
Simplified version using FastAPI BackgroundTasks instead of RQ/Redis
"""

import os
import logging
import time
import asyncio
import threading
import subprocess
import requests
from pathlib import Path
from typing import Optional, List
from datetime import datetime

from fastapi import FastAPI, File, Form, UploadFile, HTTPException, Query, BackgroundTasks, Request
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from sse_starlette.sse import EventSourceResponse

from src.models.models import (
    JobResponse, JobListResponse, UploadResponse,
    HealthResponse, JobStatus, AnalysisIntensity
)
from src.routes.orchestrator import JobOrchestrator
from src.config.api_config import DATA_DIR, MAX_UPLOAD_SIZE_BYTES
from src.middleware.security import safe_job_path, validate_job_id

# Configure logging
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

# Initialize FastAPI
app = FastAPI(
    title="Ghidra Agentic RE Pipeline API",
    description="API for automated reverse engineering with Ghidra and LLM agents",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize orchestrator (no Redis needed)
orchestrator = JobOrchestrator()

# Track startup time
START_TIME = time.time()

# Worker control plane process (runs Ghidra API on port 8001)
worker_process = None


@app.on_event("startup")
async def startup_event():
    """Start the worker control plane on startup"""
    global worker_process
    logger.info("Starting worker control plane...")

    worker_process = subprocess.Popen(
        ["python3", "/app/src/services/worker/main.py"],
        cwd="/app/src/services/worker",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    # Give it a moment to start
    await asyncio.sleep(2)
    logger.info("Worker control plane started")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    global worker_process
    if worker_process:
        logger.info("Stopping worker control plane...")
        worker_process.terminate()
        worker_process.wait(timeout=5)


@app.get("/", tags=["General"])
def root():
    return {
        "name": "Ghidra Agentic RE Pipeline API",
        "version": "1.0.0",
        "docs": "/docs"
    }


@app.get("/health", response_model=HealthResponse, tags=["General"])
def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        uptime=time.time() - START_TIME
    )


@app.post("/api/upload", response_model=UploadResponse, tags=["Jobs"])
async def upload_binary(
    file: UploadFile = File(...),
    intensity: str = Form("standard"),
    multi_agent: bool = Form(False),
    background_tasks: BackgroundTasks = None,
):
    """Upload a binary for analysis"""

    # Validate intensity
    try:
        intensity_level = AnalysisIntensity(intensity)
    except ValueError:
        intensity_level = AnalysisIntensity.standard

    # Validate file size
    content = await file.read()
    if len(content) > MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size is {MAX_UPLOAD_SIZE_BYTES / (1024*1024)}MB"
        )

    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Empty file")

    # Create job
    try:
        job = orchestrator.create_job(file.filename, content, intensity=intensity_level.value, multi_agent=multi_agent)

        # Start processing in background
        background_tasks.add_task(orchestrator.process_job, job.id)

        return UploadResponse(
            job_id=job.id,
            filename=job.filename,
            sha256=job.sha256,
            message="File uploaded successfully and queued for analysis"
        )

    except Exception as e:
        logger.error(f"Upload failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/upload/batch", response_model=UploadResponse, tags=["Jobs"])
async def upload_batch(
    files: List[UploadFile] = File(...),
    intensity: str = Form("standard"),
    background_tasks: BackgroundTasks = None,
):
    """Upload multiple binaries for batch analysis (GB-22)"""

    # Validate intensity
    try:
        intensity_level = AnalysisIntensity(intensity)
    except ValueError:
        intensity_level = AnalysisIntensity.standard

    if not files:
        raise HTTPException(status_code=400, detail="No files provided")

    # Read and validate all files first
    file_contents = []
    for f in files:
        content = await f.read()
        if len(content) > MAX_UPLOAD_SIZE_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"File {f.filename} too large. Maximum size is {MAX_UPLOAD_SIZE_BYTES / (1024*1024)}MB"
            )
        if len(content) == 0:
            continue  # Skip empty files
        file_contents.append((f.filename, content))

    if not file_contents:
        raise HTTPException(status_code=400, detail="All files are empty")

    try:
        # Create a batch job using the first file's name as reference
        primary_name = f"batch_{len(file_contents)}_files"
        # Concatenate all content for SHA256 (batch identity)
        import hashlib
        combined_hash = hashlib.sha256(b"".join(c for _, c in file_contents)).hexdigest()

        # Create job (uses first file content for SHA256, but saves all files)
        job = orchestrator.create_job(primary_name, file_contents[0][1], intensity=intensity_level.value)

        # Save all files to the job's input directory
        from src.middleware.security import safe_job_path, sanitize_filename
        from src.config.api_config import DATA_DIR
        job_dir = safe_job_path(DATA_DIR, job.id)
        input_dir = job_dir / "input"

        for filename, content in file_contents:
            safe_name = sanitize_filename(filename)
            file_path = input_dir / safe_name
            with open(file_path, 'wb') as fout:
                fout.write(content)

        # Mark as batch job in metadata
        job_meta_path = job_dir / "job_meta.json"
        with open(job_meta_path, 'w') as fout:
            import json
            json.dump({
                "intensity": intensity_level.value,
                "batch": True,
                "file_count": len(file_contents),
                "filenames": [sanitize_filename(fn) for fn, _ in file_contents]
            }, fout)

        # Start batch processing in background
        background_tasks.add_task(orchestrator.process_batch_job, job.id)

        return UploadResponse(
            job_id=job.id,
            filename=primary_name,
            sha256=combined_hash,
            message=f"Batch upload: {len(file_contents)} files queued for analysis"
        )

    except Exception as e:
        logger.error(f"Batch upload failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/jobs", response_model=JobListResponse, tags=["Jobs"])
def list_jobs():
    """List all jobs"""
    try:
        jobs = orchestrator.list_jobs()
        return JobListResponse(
            jobs=jobs,
            total=len(jobs)
        )
    except Exception as e:
        logger.error(f"Failed to list jobs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/jobs/{job_id}", response_model=JobResponse, tags=["Jobs"])
def get_job(job_id: str):
    """Get job details"""
    if not validate_job_id(job_id):
        raise HTTPException(status_code=400, detail="Invalid job_id format")

    job = orchestrator.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    return JobResponse(job=job)


@app.get("/api/jobs/{job_id}/logs/stream", tags=["Jobs"])
async def stream_logs(job_id: str):
    """Stream job logs via Server-Sent Events"""
    if not validate_job_id(job_id):
        raise HTTPException(status_code=400, detail="Invalid job_id format")

    job = orchestrator.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    async def event_generator():
        """Generate SSE events for log updates"""
        last_log_count = 0

        while True:
            # Get current logs
            logs = orchestrator.get_job_logs(job_id)

            # Send new logs
            if len(logs) > last_log_count:
                for log_line in logs[last_log_count:]:
                    yield {
                        "event": "log",
                        "data": log_line.strip()
                    }
                last_log_count = len(logs)

            # Check job status
            current_job = orchestrator.get_job(job_id)
            if current_job.status in [JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELED]:
                yield {
                    "event": "status",
                    "data": current_job.status.value
                }
                break

            # Wait before checking again
            await asyncio.sleep(1)

    return EventSourceResponse(event_generator())


@app.get("/api/jobs/{job_id}/logs", tags=["Jobs"])
def get_logs(job_id: str):
    """Get job logs as JSON array"""
    if not validate_job_id(job_id):
        raise HTTPException(status_code=400, detail="Invalid job_id format")

    job = orchestrator.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    logs = orchestrator.get_job_logs(job_id)
    return {"logs": [log.strip() for log in logs]}


@app.get("/api/jobs/{job_id}/report", tags=["Jobs"])
def get_report(job_id: str, download: bool = Query(False)):
    """Get job report"""
    if not validate_job_id(job_id):
        raise HTTPException(status_code=400, detail="Invalid job_id format")

    job = orchestrator.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    try:
        job_dir = safe_job_path(DATA_DIR, job_id)
        report_path = job_dir / "report" / "report.md"
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")

    if download:
        return FileResponse(
            path=str(report_path),
            media_type="text/markdown",
            filename=f"report_{job_id}.md"
        )
    else:
        # Return as JSON with content
        with open(report_path, 'r') as f:
            content = f.read()
        return {"content": content}


@app.get("/api/jobs/{job_id}/report/docx", tags=["Jobs"])
def get_report_docx(job_id: str):
    """Download job report as a formatted Word document"""
    if not validate_job_id(job_id):
        raise HTTPException(status_code=400, detail="Invalid job_id format")

    job = orchestrator.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    try:
        job_dir = safe_job_path(DATA_DIR, job_id)
        report_md_path = job_dir / "report" / "report.md"
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not report_md_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")

    # Generate .docx from the markdown report
    try:
        from src.services.agent.docx_exporter import markdown_to_docx

        docx_path = job_dir / "report" / "report.docx"
        with open(report_md_path, "r") as f:
            md_content = f.read()
        markdown_to_docx(md_content, str(docx_path))

        return FileResponse(
            path=str(docx_path),
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            filename=f"GARE_Report_{job.filename}_{job_id[-8:]}.docx",
        )
    except Exception as e:
        logger.error(f"DOCX generation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")


@app.get("/api/jobs/{job_id}/metrics", tags=["Jobs"])
def get_metrics(job_id: str):
    """Get analysis metrics for a job"""
    if not validate_job_id(job_id):
        raise HTTPException(status_code=400, detail="Invalid job_id format")

    job = orchestrator.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    try:
        job_dir = safe_job_path(DATA_DIR, job_id)
        metrics_path = job_dir / "artifacts" / "metrics.json"
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not metrics_path.exists():
        raise HTTPException(status_code=404, detail="Metrics not available for this job")

    import json
    with open(metrics_path, "r") as f:
        return json.load(f)


@app.get("/api/jobs/{job_id}/download/project", tags=["Downloads"])
def download_ghidra_project(job_id: str):
    """Download the Ghidra project database (internal Ghidra format - use /annotations for human-readable export)"""
    import zipfile
    import tempfile

    if not validate_job_id(job_id):
        raise HTTPException(status_code=400, detail="Invalid job_id format")

    job = orchestrator.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    try:
        job_dir = safe_job_path(DATA_DIR, job_id)
        project_dir = job_dir / "ghidra_project"
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not project_dir.exists():
        raise HTTPException(status_code=404, detail="Ghidra project not found")

    # Create temporary zip file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp:
        zip_path = tmp.name
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in project_dir.rglob("*"):
                if file_path.is_file():
                    arcname = file_path.relative_to(project_dir.parent)
                    zipf.write(file_path, arcname)

        return FileResponse(
            path=zip_path,
            media_type="application/zip",
            filename=f"{job.filename}_ghidra_project.zip"
        )


@app.get("/api/jobs/{job_id}/download/annotations", tags=["Downloads"])
def download_annotations(job_id: str):
    """Download annotated analysis (renamed functions, comments, decompiled code)"""
    if not validate_job_id(job_id):
        raise HTTPException(status_code=400, detail="Invalid job_id format")

    job = orchestrator.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    # Call worker to generate annotations export
    worker_url = os.environ.get("WORKER_URL", "http://localhost:8001")
    try:
        response = requests.get(f"{worker_url}/jobs/{job_id}/export_annotations", timeout=120)
        response.raise_for_status()
        result = response.json()

        if not result.get("success"):
            raise HTTPException(status_code=500, detail="Annotation export failed")

        export_path = Path(result["path"])
        if not export_path.exists():
            raise HTTPException(status_code=404, detail="Annotation file not found after export")

        return FileResponse(
            path=str(export_path),
            media_type="text/plain",
            filename=f"{job.filename}_annotations.txt"
        )

    except requests.RequestException as e:
        logger.error(f"Failed to export annotations: {e}")
        raise HTTPException(status_code=500, detail=f"Export failed: {str(e)}")


@app.get("/api/jobs/{job_id}/download/binary", tags=["Downloads"])
def download_original_binary(job_id: str):
    """Download the original binary that was analyzed"""
    if not validate_job_id(job_id):
        raise HTTPException(status_code=400, detail="Invalid job_id format")

    job = orchestrator.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    try:
        job_dir = safe_job_path(DATA_DIR, job_id)
        binary_path = job_dir / "input" / job.filename
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not binary_path.exists():
        raise HTTPException(status_code=404, detail="Binary not found")

    return FileResponse(path=str(binary_path), filename=job.filename)


@app.post("/api/jobs/{job_id}/cancel", tags=["Jobs"])
def cancel_job(job_id: str):
    """Cancel a running job"""
    if not validate_job_id(job_id):
        raise HTTPException(status_code=400, detail="Invalid job_id format")

    success = orchestrator.cancel_job(job_id)
    if not success:
        raise HTTPException(
            status_code=400,
            detail="Job cannot be canceled (not found or not running)"
        )

    return {"message": f"Job {job_id} canceled"}


@app.delete("/api/jobs/{job_id}", tags=["Jobs"])
def delete_job(job_id: str):
    """Delete a job and its artifacts"""
    if not validate_job_id(job_id):
        raise HTTPException(status_code=400, detail="Invalid job_id format")

    job = orchestrator.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    # Delete job directory using safe path
    try:
        job_dir = safe_job_path(DATA_DIR, job_id)
        if job_dir.exists():
            import shutil
            shutil.rmtree(job_dir)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Remove from orchestrator cache
    if job_id in orchestrator.jobs:
        del orchestrator.jobs[job_id]

    return {"message": f"Job {job_id} deleted"}


if __name__ == "__main__":
    import uvicorn

    logger.info("Starting API server")
    logger.info(f"Data directory: {DATA_DIR}")

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level=os.environ.get("LOG_LEVEL", "info").lower()
    )
