"""
Security utilities for input validation and sanitization
"""

import re
from pathlib import Path, PurePath
from typing import Union


def validate_job_id(job_id: str) -> bool:
    """
    Validate job_id contains only safe characters.

    Args:
        job_id: Job identifier to validate

    Returns:
        True if valid, False otherwise
    """
    if not job_id or not isinstance(job_id, str):
        return False

    # Only allow alphanumeric, underscore, hyphen
    if not re.match(r'^[a-zA-Z0-9_-]+$', job_id):
        return False

    # Reasonable length limit
    if len(job_id) < 1 or len(job_id) > 128:
        return False

    return True


def safe_job_path(data_dir: Path, job_id: str) -> Path:
    """
    Get validated job path, raises ValueError if invalid.

    Prevents path traversal attacks by:
    1. Validating job_id format
    2. Resolving to absolute path
    3. Checking path is within allowed base directory

    Args:
        data_dir: Base data directory
        job_id: Job identifier

    Returns:
        Validated absolute path to job directory

    Raises:
        ValueError: If job_id is invalid or path traversal detected
    """
    if not validate_job_id(job_id):
        raise ValueError(f"Invalid job_id format: {job_id}")

    # Build and resolve paths
    job_path = (data_dir / "jobs" / job_id).resolve()
    allowed_base = (data_dir / "jobs").resolve()

    # Ensure path is within allowed directory (prevents path traversal)
    if not str(job_path).startswith(str(allowed_base) + "/"):
        raise ValueError(f"Path traversal attempt detected: {job_id}")

    return job_path


def validate_file_path(file_path: Union[str, Path], allowed_base: Union[str, Path]) -> Path:
    """
    Validate that a file path is within an allowed base directory.

    Args:
        file_path: Path to validate
        allowed_base: Base directory that must contain the file

    Returns:
        Resolved absolute path

    Raises:
        ValueError: If path is outside allowed base or doesn't exist
    """
    file_path = Path(file_path).resolve()
    allowed_base = Path(allowed_base).resolve()

    # Check path is within allowed base
    if not str(file_path).startswith(str(allowed_base) + "/"):
        raise ValueError(f"Path outside allowed directory: {file_path}")

    # Optionally check existence
    if not file_path.exists():
        raise ValueError(f"Path does not exist: {file_path}")

    return file_path
