"""
Data models for the API
"""

from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class AnalysisIntensity(str, Enum):
    """Analysis intensity level"""
    quick = "quick"
    standard = "standard"
    deep = "deep"


class JobStatus(str, Enum):
    """Job status enumeration"""
    QUEUED = "queued"
    RUNNING = "running"
    ANALYZING_GHIDRA = "analyzing_ghidra"
    AGENT_RUNNING = "agent_running"
    REPORT_WRITING = "report_writing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"


class Job(BaseModel):
    """Job model"""
    id: str
    filename: str
    sha256: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    status: JobStatus
    progress: int = Field(default=0, ge=0, le=100)
    intensity: Optional[str] = None
    error_message: Optional[str] = None
    artifacts: List[str] = Field(default_factory=list)
    logs: List[str] = Field(default_factory=list)


class JobCreate(BaseModel):
    """Job creation request"""
    filename: str


class JobUpdate(BaseModel):
    """Job update request"""
    status: Optional[JobStatus] = None
    progress: Optional[int] = Field(default=None, ge=0, le=100)
    error_message: Optional[str] = None


class JobResponse(BaseModel):
    """Job response"""
    job: Job


class JobListResponse(BaseModel):
    """Job list response"""
    jobs: List[Job]
    total: int


class UploadResponse(BaseModel):
    """Upload response"""
    job_id: str
    filename: str
    sha256: str
    message: str


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    version: str
    uptime: float
