"""
Job orchestrator - manages job lifecycle and worker coordination
Simplified version without Redis/RQ - uses direct subprocess calls
"""

import json
import hashlib
import logging
import subprocess
import requests
import os
from pathlib import Path
from typing import Dict, Any, Optional
from src.utils.timezone import utc_now

from src.models.models import Job, JobStatus
from src.config.api_config import DATA_DIR, WORKER_URL
from src.middleware.security import safe_job_path, sanitize_filename

logger = logging.getLogger(__name__)


class JobOrchestrator:
    """Orchestrates job processing workflow"""

    def __init__(self):
        self.jobs: Dict[str, Job] = {}  # In-memory job cache
        self.running_processes: Dict[str, subprocess.Popen] = {}  # Track agent subprocesses

    def create_job(self, filename: str, file_content: bytes, intensity: str = "standard", multi_agent: bool = False) -> Job:
        """Create a new job from uploaded file"""

        # Compute SHA256
        sha256 = hashlib.sha256(file_content).hexdigest()

        # Generate job ID with crypto random component for unpredictability
        import secrets
        random_suffix = secrets.token_hex(4)
        job_id = f"job_{utc_now().strftime('%Y%m%d_%H%M%S')}_{sha256[:8]}_{random_suffix}"

        # Sanitize filename to prevent path traversal
        safe_filename_str = sanitize_filename(filename)

        # Create job directory structure using safe path function
        job_dir = safe_job_path(DATA_DIR, job_id)
        job_dir.mkdir(parents=True, exist_ok=True)
        (job_dir / "input").mkdir(exist_ok=True)
        (job_dir / "ghidra_project").mkdir(exist_ok=True)
        (job_dir / "artifacts").mkdir(exist_ok=True)
        (job_dir / "logs").mkdir(exist_ok=True)
        (job_dir / "report").mkdir(exist_ok=True)

        # Save uploaded file with sanitized name
        input_path = job_dir / "input" / safe_filename_str
        with open(input_path, 'wb') as f:
            f.write(file_content)

        # Create job object
        job = Job(
            id=job_id,
            filename=safe_filename_str,  # Use sanitized filename
            sha256=sha256,
            created_at=utc_now(),
            status=JobStatus.QUEUED,
            progress=0,
            intensity=intensity
        )

        # Store job
        self.jobs[job_id] = job
        self._save_job_state(job)

        # Save intensity and multi-agent flag to job metadata
        job_dir = safe_job_path(DATA_DIR, job_id)
        job_meta_path = job_dir / "job_meta.json"
        with open(job_meta_path, 'w') as f:
            json.dump({"intensity": intensity, "multi_agent": multi_agent}, f)

        logger.info(f"Created job {job_id} for file {filename} (intensity={intensity})")

        return job

    def _is_cancelled(self, job_id: str) -> bool:
        """Check if a job has been cancelled"""
        job = self.get_job(job_id)
        return job is not None and job.status == JobStatus.CANCELED

    def process_job(self, job_id: str):
        """Process a job through the full pipeline"""
        logger.info(f"Starting processing for job {job_id}")

        try:
            job = self.get_job(job_id)
            if not job:
                raise ValueError(f"Job not found: {job_id}")

            # Step 1: Update status to running
            self.update_job_status(job_id, JobStatus.RUNNING, 10)
            self._log_to_job(job_id, f"[{utc_now().isoformat()}] Job started")

            # Step 2: Import to Ghidra and analyze
            if self._is_cancelled(job_id):
                self._log_to_job(job_id, f"[{utc_now().isoformat()}] Job cancelled by user")
                return

            self.update_job_status(job_id, JobStatus.ANALYZING_GHIDRA, 20)
            self._log_to_job(job_id, f"[{utc_now().isoformat()}] Starting Ghidra analysis")

            job_dir = safe_job_path(DATA_DIR, job_id)
            binary_path = job_dir / "input" / job.filename

            # Call worker to import and analyze
            import_result = self._call_worker_import(job_id, str(binary_path))

            if not import_result.get("success"):
                raise Exception(f"Ghidra import failed: {import_result.get('error')}")

            # Save metadata
            metadata = import_result.get("metadata", {})
            metadata_path = job_dir / "artifacts" / "metadata.json"
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)

            self._log_to_job(job_id, f"[{utc_now().isoformat()}] Ghidra analysis complete")

            # Check cancellation before agent phase
            if self._is_cancelled(job_id):
                self._log_to_job(job_id, f"[{utc_now().isoformat()}] Job cancelled by user")
                return

            self.update_job_status(job_id, JobStatus.AGENT_RUNNING, 50)

            # Step 3: Run agent analysis
            self._log_to_job(job_id, f"[{utc_now().isoformat()}] Starting agent analysis")

            agent_success, agent_error = self._run_agent(job_id, str(metadata_path))

            if self._is_cancelled(job_id):
                self._log_to_job(job_id, f"[{utc_now().isoformat()}] Job cancelled by user during agent analysis")
                return

            if not agent_success:
                raise Exception(agent_error or "Agent analysis failed")

            self._log_to_job(job_id, f"[{utc_now().isoformat()}] Agent analysis complete")

            # Check cancellation before report phase
            if self._is_cancelled(job_id):
                self._log_to_job(job_id, f"[{utc_now().isoformat()}] Job cancelled by user")
                return

            # Step 4: Finalize
            self.update_job_status(job_id, JobStatus.REPORT_WRITING, 90)

            # Check for report
            report_path = job_dir / "report" / "report.md"
            if report_path.exists():
                job.artifacts.append(str(report_path.relative_to(DATA_DIR)))
                self._log_to_job(job_id, f"[{utc_now().isoformat()}] Report generated at {report_path}")
            else:
                self._log_to_job(job_id, f"[{utc_now().isoformat()}] Warning: Report not found")

            # Complete
            self.update_job_status(job_id, JobStatus.COMPLETED, 100)
            self._log_to_job(job_id, f"[{utc_now().isoformat()}] Job completed successfully")

            logger.info(f"Job {job_id} completed successfully")

        except Exception as e:
            logger.error(f"Job {job_id} failed: {e}", exc_info=True)
            # Don't overwrite CANCELED status with FAILED
            if not self._is_cancelled(job_id):
                self.update_job_status(job_id, JobStatus.FAILED, error_message=str(e))
            self._log_to_job(job_id, f"[{utc_now().isoformat()}] ERROR: {str(e)}")

    def _call_worker_import(self, job_id: str, binary_path: str) -> Dict[str, Any]:
        """Call worker to import binary into Ghidra"""
        try:
            # Worker runs locally in same container
            url = f"http://localhost:8001/jobs/{job_id}/import"
            response = requests.post(
                url,
                json={"binary_path": binary_path},
                timeout=600
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Worker import call failed: {e}")
            return {"success": False, "error": str(e)}

    def _run_agent(self, job_id: str, metadata_path: str):
        """Run the analysis agent as subprocess with cancellation support.

        Returns:
            tuple[bool, Optional[str]]: (success, error_message). On success
            error_message is None. On failure error_message carries the most
            specific reason available (agent's stderr last line, or "timed out
            after Ns", etc.), so the orchestrator can surface it in the job's
            error_message instead of a generic "Agent analysis failed".
        """
        try:
            # Read intensity from job metadata
            intensity = "standard"
            multi_agent = False
            job_dir = safe_job_path(DATA_DIR, job_id)
            job_meta_path = job_dir / "job_meta.json"
            if job_meta_path.exists():
                with open(job_meta_path, 'r') as f:
                    meta = json.load(f)
                    intensity = meta.get("intensity", "standard")
                    multi_agent = meta.get("multi_agent", False)

            cmd = [
                "python3",
                "/app/src/services/agent/runner.py",
                "--job-id", job_id,
                "--data-dir", str(DATA_DIR),
                "--metadata-file", metadata_path,
                "--auto-mode",  # Enable automated analysis
                "--intensity", intensity
            ]

            # GB-21: Multi-agent analysis with specialized personas
            if multi_agent:
                cmd.append("--multi-agent")

            logger.info(f"Running agent: {' '.join(cmd)}")

            # Run agent as subprocess (pass through environment variables)
            agent_env = {
                **os.environ,
                "WORKER_URL": "http://localhost:8001"
            }

            # Ensure API_KEY is passed through
            if "API_KEY" in os.environ:
                agent_env["API_KEY"] = os.environ["API_KEY"]

            # Timeout based on intensity (generous to allow for LLM response latency)
            # Each API call can take 30-60s; budget = iterations * 65s + 120s overhead
            timeouts = {"quick": 1200, "standard": 3600, "deep": 7200}
            timeout = timeouts.get(intensity, 1500)

            # Use Popen so we can track and kill the process
            import time
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=agent_env,
                cwd="/app/src/services/agent"
            )

            # Track the process for cancel_job() to find
            self.running_processes[job_id] = process

            try:
                # Poll loop: check for completion or cancellation every 2 seconds
                start_time = time.time()
                while process.poll() is None:
                    elapsed = time.time() - start_time

                    # Check timeout
                    if elapsed > timeout:
                        logger.error(f"Agent timed out after {timeout}s")
                        process.terminate()
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.kill()
                        return False, f"Agent timed out after {timeout}s"

                    # Check cancellation
                    if self._is_cancelled(job_id):
                        logger.info(f"Agent cancelled for job {job_id}, terminating subprocess")
                        process.terminate()
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.kill()
                        return False, "Job cancelled"

                    time.sleep(2)

                # Process finished naturally
                returncode = process.returncode
                stdout = process.stdout.read() if process.stdout else ""
                stderr = process.stderr.read() if process.stderr else ""

                if returncode == 0:
                    logger.info(f"Agent completed successfully")
                    if stdout:
                        logger.debug(f"Agent stdout: {stdout}")
                    return True, None
                else:
                    logger.error(f"Agent failed with code {returncode}")
                    if stderr:
                        logger.error(f"Agent stderr: {stderr}")
                    if stdout:
                        logger.error(f"Agent stdout: {stdout}")
                    # Extract the most specific reason from stderr. The agent's
                    # runner.py prints "ERROR: Analysis failed: <reason>" right
                    # before exit(1); fall back to last stderr line or exit code.
                    reason = None
                    for line in (stderr or "").strip().splitlines()[::-1]:
                        if line.startswith("ERROR:"):
                            reason = line[len("ERROR:"):].strip()
                            break
                    if not reason:
                        last_stderr = (stderr or "").strip().splitlines()
                        reason = last_stderr[-1] if last_stderr else f"Agent exited with code {returncode}"
                    return False, reason
            finally:
                # Always clean up process reference
                self.running_processes.pop(job_id, None)

        except Exception as e:
            logger.error(f"Failed to run agent: {e}")
            self.running_processes.pop(job_id, None)
            return False, f"Failed to launch agent: {e}"

    def process_batch_job(self, job_id: str):
        """Process a batch job containing multiple binaries (GB-22)"""
        logger.info(f"Starting batch processing for job {job_id}")

        try:
            job = self.get_job(job_id)
            if not job:
                raise ValueError(f"Job not found: {job_id}")

            self.update_job_status(job_id, JobStatus.RUNNING, 10)
            self._log_to_job(job_id, f"[{utc_now().isoformat()}] Batch job started")

            # Read intensity from job metadata
            intensity = "standard"
            job_dir = safe_job_path(DATA_DIR, job_id)
            job_meta_path = job_dir / "job_meta.json"
            if job_meta_path.exists():
                with open(job_meta_path, 'r') as f:
                    meta = json.load(f)
                    intensity = meta.get("intensity", "standard")

            # Discover binaries in input directory
            from src.services.worker.batch_processor import BatchProcessor
            processor = BatchProcessor(job_id, str(DATA_DIR), intensity=intensity)
            binaries = processor.discover_binaries()

            if not binaries:
                raise ValueError("No binaries found in input directory")

            self._log_to_job(job_id, f"[{utc_now().isoformat()}] Found {len(binaries)} binaries")
            self.update_job_status(job_id, JobStatus.ANALYZING_GHIDRA, 20)

            # Process all binaries
            batch_result = processor.process_batch(binaries)

            if self._is_cancelled(job_id):
                self._log_to_job(job_id, f"[{utc_now().isoformat()}] Batch job cancelled by user")
                return

            # Generate batch report
            self.update_job_status(job_id, JobStatus.REPORT_WRITING, 80)
            report = processor.generate_batch_report(batch_result)

            # Save report
            report_dir = job_dir / "report"
            report_dir.mkdir(parents=True, exist_ok=True)
            report_path = report_dir / "report.md"
            with open(report_path, 'w') as f:
                f.write(report)

            job.artifacts.append(str(report_path.relative_to(DATA_DIR)))

            # Complete
            self.update_job_status(job_id, JobStatus.COMPLETED, 100)
            self._log_to_job(job_id, f"[{utc_now().isoformat()}] Batch job completed: {batch_result['succeeded']}/{batch_result['total_binaries']} succeeded")

        except Exception as e:
            logger.error(f"Batch job {job_id} failed: {e}", exc_info=True)
            if not self._is_cancelled(job_id):
                self.update_job_status(job_id, JobStatus.FAILED, error_message=str(e))
            self._log_to_job(job_id, f"[{utc_now().isoformat()}] ERROR: {str(e)}")

    def get_job(self, job_id: str) -> Optional[Job]:
        """Get job by ID"""
        if job_id in self.jobs:
            return self.jobs[job_id]

        # Try to load from disk
        try:
            job_dir = safe_job_path(DATA_DIR, job_id)
            job_file = job_dir / "job.json"
            if job_file.exists():
                with open(job_file, 'r') as f:
                    data = json.load(f)
                    job = Job(**data)
                    # Normalize naive datetimes to UTC-aware
                    if job.created_at.tzinfo is None:
                        from datetime import timezone
                        job.created_at = job.created_at.replace(tzinfo=timezone.utc)
                    if job.completed_at and job.completed_at.tzinfo is None:
                        from datetime import timezone
                        job.completed_at = job.completed_at.replace(tzinfo=timezone.utc)
                    # Backfill intensity from job_meta.json for older jobs
                    if not job.intensity:
                        meta_path = job_dir / "job_meta.json"
                        if meta_path.exists():
                            try:
                                with open(meta_path, 'r') as mf:
                                    meta = json.load(mf)
                                    job.intensity = meta.get("intensity")
                            except Exception:
                                pass
                    self.jobs[job_id] = job
                    return job
        except ValueError as e:
            logger.warning(f"Invalid job_id: {job_id} - {e}")
            return None
        except Exception as e:
            logger.error(f"Error loading job: {e}")
            return None

        return None

    def list_jobs(self) -> list:
        """List all jobs"""
        jobs_dir = DATA_DIR / "jobs"
        all_jobs = []

        if not jobs_dir.exists():
            return all_jobs

        for job_dir in jobs_dir.iterdir():
            if job_dir.is_dir():
                job = self.get_job(job_dir.name)
                if job:
                    all_jobs.append(job)

        return sorted(all_jobs, key=lambda j: j.created_at, reverse=True)

    def update_job_status(self, job_id: str, status: JobStatus, progress: Optional[int] = None, error_message: Optional[str] = None):
        """Update job status"""
        job = self.get_job(job_id)
        if job:
            job.status = status
            if progress is not None:
                job.progress = progress
            if error_message:
                job.error_message = error_message

            # Set completed_at on terminal states
            if status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELED):
                job.completed_at = utc_now()

            self._save_job_state(job)
            logger.info(f"Job {job_id} updated: status={status}, progress={progress}")

    def _save_job_state(self, job: Job):
        """Save job state to disk"""
        try:
            job_dir = safe_job_path(DATA_DIR, job.id)
            job_file = job_dir / "job.json"
            with open(job_file, 'w') as f:
                json.dump(job.dict(), f, indent=2, default=str)
        except ValueError as e:
            logger.error(f"Failed to save job state: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error saving job state: {e}")
            raise

    def _log_to_job(self, job_id: str, message: str):
        """Append log message to job logs"""
        job = self.get_job(job_id)
        if job:
            job.logs.append(message)
            self._save_job_state(job)

            # Also write to log file
            try:
                job_dir = safe_job_path(DATA_DIR, job_id)
                log_file = job_dir / "logs" / "job.log"
                with open(log_file, 'a') as f:
                    f.write(message + "\n")
            except ValueError as e:
                logger.error(f"Failed to write log: {e}")
            except Exception as e:
                logger.error(f"Unexpected error writing log: {e}")

    def get_job_logs(self, job_id: str) -> list:
        """Get job logs"""
        try:
            job_dir = safe_job_path(DATA_DIR, job_id)
            log_file = job_dir / "logs" / "job.log"
            if log_file.exists():
                with open(log_file, 'r') as f:
                    return f.readlines()
        except ValueError as e:
            logger.error(f"Failed to get logs: {e}")
        except Exception as e:
            logger.error(f"Unexpected error getting logs: {e}")
        return []

    def cancel_job(self, job_id: str) -> bool:
        """Cancel a running job"""
        job = self.get_job(job_id)
        if not job:
            return False

        active_states = [
            JobStatus.QUEUED,
            JobStatus.RUNNING,
            JobStatus.ANALYZING_GHIDRA,
            JobStatus.AGENT_RUNNING,
            JobStatus.REPORT_WRITING,
        ]
        if job.status not in active_states:
            return False

        # Set status to CANCELED
        self.update_job_status(job_id, JobStatus.CANCELED)
        self._log_to_job(job_id, f"[{utc_now().isoformat()}] Job cancelled by user")

        # Write cancel flag file so the agent subprocess can detect cancellation
        try:
            job_dir = safe_job_path(DATA_DIR, job_id)
            cancel_flag = job_dir / "cancel.flag"
            cancel_flag.write_text(utc_now().isoformat())
        except Exception as e:
            logger.error(f"Failed to write cancel flag for {job_id}: {e}")

        # Terminate tracked subprocess if running
        process = self.running_processes.get(job_id)
        if process and process.poll() is None:
            logger.info(f"Terminating agent subprocess for job {job_id}")
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()

        logger.info(f"Job {job_id} canceled")
        return True
