# backend/src/socrates/api/analysis.py
#
# File upload and analysis endpoints.
# Upload triggers pipeline as FastAPI background task.
# Results polled via GET /analysis/{job_id}
#
# NOTE: Prototype — no file size limit, no file type validation beyond .csv
# Production would add: file size limits, virus scanning,
# rate limiting per user, PostgreSQL persistence.

import os
import uuid
import shutil
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, UploadFile, File, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel

from socrates.config   import settings
from socrates.db       import create_job, get_job, update_job
from socrates.api.auth import verify_token
from socrates.services.pipeline import run_pipeline

router = APIRouter(prefix="/analysis", tags=["analysis"])


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------

class AnomalyResponse(BaseModel):
    src_ip:             str
    domain:             str
    username:           str
    threat_summary:     str
    what_happened:      str
    why_suspicious:     str
    recommended_action: str
    confidence:         float
    severity:           str
    tier1_fired:        bool
    tier2_fired:        bool


class JobStatusResponse(BaseModel):
    job_id:          str
    status:          str
    filename:        str
    created_at:      datetime
    total_logs:      Optional[int]              = None
    tier1_flagged:   Optional[int]              = None
    tier2_flagged:   Optional[int]              = None
    tier3_explained: Optional[int]              = None
    total_time_ms:   Optional[float]            = None
    anomalies:       Optional[List[AnomalyResponse]] = None
    error:           Optional[str]              = None


class UploadResponse(BaseModel):
    job_id:   str
    filename: str
    status:   str
    message:  str


# ---------------------------------------------------------------------------
# Background task
# ---------------------------------------------------------------------------

def _run_pipeline_task(job_id: str, filepath: str):
    try:
        update_job(job_id, status="processing")
        result = run_pipeline(filepath)
        update_job(job_id, status="complete", result=result)
        print(f"[analysis] Job {job_id} complete — {len(result.anomalies)} anomalies")
    except Exception as e:
        update_job(job_id, status="failed", error=str(e))
        print(f"[analysis] Job {job_id} failed — {e}")
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/upload", response_model=UploadResponse)
async def upload_log(
    background_tasks: BackgroundTasks,
    file:             UploadFile = File(...),
    username:         str        = Depends(verify_token),
):
    if not file.filename.endswith(".csv"):
        raise HTTPException(400, detail="Only .csv files are supported")

    os.makedirs(settings.upload_dir, exist_ok=True)
    job_id   = str(uuid.uuid4())
    filepath = os.path.join(settings.upload_dir, f"{job_id}.csv")

    with open(filepath, "wb") as f:
        shutil.copyfileobj(file.file, f)

    create_job(job_id, file.filename)
    background_tasks.add_task(_run_pipeline_task, job_id, filepath)

    return UploadResponse(
        job_id=   job_id,
        filename= file.filename,
        status=   "pending",
        message=  "File uploaded. Poll /analysis/{job_id} for results.",
    )


@router.get("/{job_id}", response_model=JobStatusResponse)
def get_results(
    job_id:   str,
    username: str = Depends(verify_token),
):
    job = get_job(job_id)
    if not job:
        raise HTTPException(404, detail=f"Job {job_id} not found")

    response = JobStatusResponse(
        job_id=     job.job_id,
        status=     job.status,
        filename=   job.filename,
        created_at= job.created_at,
        error=      job.error,
    )

    if job.status == "complete" and job.result:
        r = job.result
        response.total_logs      = r.total_logs
        response.tier1_flagged   = r.tier1_flagged
        response.tier2_flagged   = r.tier2_flagged
        response.tier3_explained = r.tier3_explained
        response.total_time_ms   = r.total_time_ms
        response.anomalies       = [
            AnomalyResponse(
                src_ip=             a.src_ip,
                domain=             a.domain,
                username=           a.username,
                threat_summary=     a.threat_summary,
                what_happened=      a.what_happened,
                why_suspicious=     a.why_suspicious,
                recommended_action= a.recommended_action,
                confidence=         a.confidence,
                severity=           a.severity,
                tier1_fired=        a.tier1_fired,
                tier2_fired=        a.tier2_fired,
            )
            for a in r.anomalies
        ]

    return response