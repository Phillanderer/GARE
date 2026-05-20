"""
Worker service main entry point
Starts the Ghidra control plane API server
"""

import os
import logging
import uvicorn
from control_plane import app

# Configure logging
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

if __name__ == "__main__":
    logger.info("Starting Ghidra Worker Control Plane")
    logger.info(f"Data directory: {os.environ.get('DATA_DIR', '/app/data')}")
    logger.info(f"Ghidra version: {os.environ.get('GHIDRA_VERSION', 'unknown')}")

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8001,
        log_level=os.environ.get("LOG_LEVEL", "info").lower()
    )
