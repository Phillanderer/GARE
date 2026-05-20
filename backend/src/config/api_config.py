"""
Configuration for API service
"""

import os
from pathlib import Path

# Service URLs
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
WORKER_URL = os.environ.get("WORKER_URL", "http://worker:8001")

# Storage
DATA_DIR = Path(os.environ.get("DATA_DIR", "/app/data"))
MAX_UPLOAD_SIZE_MB = int(os.environ.get("MAX_UPLOAD_SIZE_MB", 100))
MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_SIZE_MB * 1024 * 1024

# Security
SAFE_MODE = os.environ.get("SAFE_MODE", "false").lower() == "true"

# Logging
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

# Ensure data directory exists
DATA_DIR.mkdir(parents=True, exist_ok=True)
(DATA_DIR / "jobs").mkdir(parents=True, exist_ok=True)
