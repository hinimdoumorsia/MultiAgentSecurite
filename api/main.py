"""
API REST FastAPI — SecureCodeAgent
====================================
Endpoints:
  GET  /health
  POST /analyze          → job async (retourne job_id)
  GET  /jobs/{job_id}    → résultat du job
  POST /analyze/sync     → synchrone (attend le résultat)
  GET  /analyze/stream   → Server-Sent Events, résultats en temps réel
"""

import os, time, asyncio, json, logging, warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Header, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator
import uvicorn

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from core.orchestrator import run_analysis, run_analysis_stream

logger = logging.getLogger(__name__)

# ─── Modèles ──────────────────────────────────────────────────────────────────

class AnalysisRequest(BaseModel):
    repo_url: str
    pr_number: Optional[int] = None
    target_files: Optional[list[str]] = None
    language: str = "python"

    @field_validator("language")
    @classmethod
    def validate_language(cls, v):
        allowed = {"python","javascript","typescript","java","go","php","ruby","rust"}
        if v not in allowed:
            raise ValueError(f"Langage non supporté: {allowed}")
        return v

# ─── État jobs ────────────────────────────────────────────────────────────────

job_results: dict[str, dict] = {}

# ─── App ──────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("SecureCodeAgent API démarrée")
    yield

app = FastAPI(title="SecureCodeAgent API", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware,
    allow_origins=["http://localhost:3000","http://localhost:8080"],
    allow_methods=["GET","POST"],
    allow_headers=["X-API-Key","Content-Type"])

def verify_api_key(x_api_key: str = Header(...)):
    expected = os.environ.get("SECURE_AGENT_API_KEY", "dev-key-change-me")
    if x_api_key != expected:
        raise HTTPException(status_code=401, detail="Clé API invalide")
    return x_api_key

# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "groq_configured": bool(os.environ.get("GROQ_API_KEY")),
        "version": "1.0.0",
        "timestamp": time.time()
    }


@app.post("/analyze")
async def start_analysis(
    request: AnalysisRequest,
    background_tasks: BackgroundTasks,
    _: str = Depends(verify_api_key)
):
    """Lance une analyse en arrière-plan. Retourne un job_id."""
    import hashlib
    job_id = hashlib.md5(f"{request.repo_url}{time.time()}".encode()).hexdigest()[:12]
    job_results[job_id] = {"status": "queued", "created_at": time.time()}

    async def run_job():
        job_results[job_id]["status"] = "running"
        try:
            result = await run_analysis(
                repo_url=request.repo_url,
                pr_number=request.pr_number,
                target_files=request.target_files or [],
                language=request.language
            )
            job_results[job_id] = {"status": "completed", "result": result, "completed_at": time.time()}
        except Exception as e:
            job_results[job_id] = {"status": "failed", "error": str(e)[:200], "completed_at": time.time()}

    background_tasks.add_task(run_job)
    return {"job_id": job_id, "status": "queued",
            "poll_url": f"/jobs/{job_id}",
            "stream_url": f"/analyze/stream?repo_url={request.repo_url}&language={request.language}"}


@app.get("/jobs/{job_id}")
async def get_job(job_id: str, _: str = Depends(verify_api_key)):
    if job_id not in job_results:
        raise HTTPException(status_code=404, detail="Job introuvable")
    return job_results[job_id]


@app.post("/analyze/sync")
async def analyze_sync(request: AnalysisRequest, _: str = Depends(verify_api_key)):
    """Analyse synchrone avec timeout 5 minutes."""
    try:
        result = await asyncio.wait_for(
            run_analysis(
                repo_url=request.repo_url,
                target_files=request.target_files or [],
                language=request.language
            ),
            timeout=300.0
        )
        return result
    except asyncio.TimeoutError:
        raise HTTPException(status_code=408, detail="Timeout. Utilisez /analyze (async) ou /analyze/stream.")


@app.get("/analyze/stream")
async def analyze_stream(
    repo_url: str = Query(..., description="URL GitHub ou chemin local"),
    language: str = Query("python"),
    x_api_key: str = Header(...)
):
    """
    Server-Sent Events — stream les événements du pipeline en temps réel.

    Test depuis le terminal :
        curl -N -H "X-API-Key: dev-key-change-me" \\
          "http://localhost:8000/analyze/stream?repo_url=https://github.com/user/repo"

    Chaque ligne reçue :
        data: {"type": "step_start", "step": "indexation"}
        data: {"type": "token", "token": "{\\"vulnerabilities\\""}
        data: {"type": "finding", "severity": "HIGH", ...}
        data: {"type": "done", "risk_score": 8.4}
    """
    verify_api_key(x_api_key)

    async def event_generator():
        # Heartbeat initial pour que le client sache que ça démarre
        yield "data: {\"type\": \"connected\", \"repo\": \"" + repo_url[:60] + "\"}\n\n"
        try:
            async for sse_line in run_analysis_stream(
                repo_url=repo_url,
                language=language
            ):
                yield sse_line
        except Exception as e:
            yield f"data: {{\"type\": \"error\", \"message\": \"{str(e)[:100]}\"}}\n\n"
        finally:
            yield "data: {\"type\": \"stream_end\"}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # Désactive le buffering nginx
            "Connection": "keep-alive"
        }
    )


if __name__ == "__main__":
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=False, log_level="info")