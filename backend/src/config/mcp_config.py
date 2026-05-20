"""
Configuration for MCP server
"""

import os

WORKER_URL = os.environ.get("WORKER_URL", "http://worker:8001")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
