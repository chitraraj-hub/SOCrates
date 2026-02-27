# backend/src/socrates/db.py
#
# In-memory job store — holds pipeline results keyed by job_id.
# NOTE: Prototype — results lost on server restart.
# Production would replace with PostgreSQL using SQLAlchemy async.

from typing import Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime

from socrates.services.pipeline import PipelineResult


@dataclass
class Job:
    job_id:     str
    status:     str                      # "pending" | "processing" | "complete" | "failed"
    filename:   str
    created_at: datetime                 = field(default_factory=datetime.now)
    result:     Optional[PipelineResult] = None
    error:      Optional[str]            = None


# Global in-memory store
_jobs: Dict[str, Job] = {}


def create_job(job_id: str, filename: str) -> Job:
    job = Job(job_id=job_id, status="pending", filename=filename)
    _jobs[job_id] = job
    return job


def get_job(job_id: str) -> Optional[Job]:
    return _jobs.get(job_id)


def update_job(job_id: str, **kwargs) -> Optional[Job]:
    job = _jobs.get(job_id)
    if not job:
        return None
    for k, v in kwargs.items():
        setattr(job, k, v)
    return job