"""FastAPI server for Multi-Agent Security Scanner."""

from __future__ import annotations

import logging
import uuid
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
import uvicorn

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from graph.state import AgentState
from graph.workflow import build_workflow
from memory.persistent import PersistentMemory
from llm.client import LLMClient
from graph.workflow import run_workflow_with_tracing 

# ============================================
# PYDANTIC MODELS
# ============================================

class ScanRequest(BaseModel):
    repo_path: str = Field(..., description="Path to the repository to scan")
    max_iterations: int = Field(3, ge=1, le=5, description="Max patch iterations")

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str

class AgentInfo(BaseModel):
    name: str
    description: str
    status: str
    methods: list[str]

class MemoryTestRequest(BaseModel):
    pattern: str
    code_snippet: str
    action: str = "store"

class GitHubScanRequest(BaseModel):
    repo_url: str = Field(..., description="GitHub repository URL")
    branch: str = Field("main", description="Branch to scan")
    max_iterations: int = Field(3, ge=1, le=5)
    cleanup_after: bool = Field(True, description="Delete local clone after scan")

class GitHubScanResponse(BaseModel):
    scan_id: str
    status: str
    repo_url: str
    branch: str
    local_path: str
    message: str

class UserRegisterRequest(BaseModel):
    user_id: str = Field(..., description="Unique user identifier")
    username: Optional[str] = Field(None, description="Display name")

class UserScanRequest(BaseModel):
    repo_url: str = Field(..., description="GitHub repository URL")
    branch: str = Field("main", description="Branch to scan")
    max_iterations: int = Field(3, ge=1, le=5)

class LocalScanRequest(BaseModel):
    repo_path: str = Field(..., description="Path to local repository")
    max_iterations: int = Field(3, ge=1, le=5)



# ============================================
# MODÈLES POUR LA TRACE DES AGENTS
# ============================================

class AgentExecutionTrace(BaseModel):
    agent_name: str
    status: str  # "running", "completed", "failed", "skipped"
    tools_used: list[str]
    methods_called: list[str]
    findings_count: int
    execution_time_ms: float
    started_at: str | None = None
    completed_at: str | None = None
    error: str | None = None

class ScanTrace(BaseModel):
    scan_id: str
    repo_path: str
    total_agents: int
    agents_execution: dict[str, AgentExecutionTrace]
    total_findings: int
    overall_status: str
    started_at: str
    completed_at: str | None = None




# ============================================
# FONCTIONS UTILITAIRES
# ============================================

def init_user_db():
    conn = sqlite3.connect(".memory_cache.db")
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username TEXT UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            repo_url TEXT NOT NULL,
            repo_name TEXT,
            last_scan TIMESTAMP,
            vulnerabilities_count INTEGER DEFAULT 0,
            status TEXT DEFAULT 'pending',
            UNIQUE(user_id, repo_url)
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            scan_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            repo_url TEXT NOT NULL,
            repo_name TEXT,
            scan_type TEXT DEFAULT 'github',
            started_at TIMESTAMP,
            completed_at TIMESTAMP,
            vulnerabilities_count INTEGER DEFAULT 0,
            vulnerabilities TEXT,
            report TEXT,
            status TEXT
        )
    """)
    
    conn.commit()
    conn.close()
    logger.info("[user_db] Database initialized")

def get_or_create_user(user_id: str, username: str = None) -> dict:
    conn = sqlite3.connect(".memory_cache.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
    user = cursor.fetchone()
    
    if not user:
        if not username:
            username = f"user_{user_id[:8]}"
        cursor.execute("INSERT INTO users (user_id, username) VALUES (?, ?)", (user_id, username))
        conn.commit()
        user = {"user_id": user_id, "username": username, "created_at": datetime.now().isoformat()}
    else:
        user = dict(user)
    
    conn.close()
    return user

def save_scan_for_user(scan_id: str, user_id: str, repo_url: str, repo_name: str, 
                       vulnerabilities_count: int, vulnerabilities: list, 
                       report: dict, scan_type: str = "github", status: str = "completed"):
    conn = sqlite3.connect(".memory_cache.db")
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT OR REPLACE INTO user_projects 
        (user_id, repo_url, repo_name, last_scan, vulnerabilities_count, status)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user_id, repo_url, repo_name, datetime.now().isoformat(), vulnerabilities_count, status))
    
    cursor.execute("""
        INSERT INTO scan_history 
        (scan_id, user_id, repo_url, repo_name, scan_type, started_at, completed_at, 
         vulnerabilities_count, vulnerabilities, report, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (scan_id, user_id, repo_url, repo_name, scan_type, datetime.now().isoformat(), 
          datetime.now().isoformat(), vulnerabilities_count, json.dumps(vulnerabilities), 
          json.dumps(report), status))
    
    conn.commit()
    conn.close()

# ============================================
# LIFESPAN
# ============================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀 Starting Multi-Agent Security Scanner API")
    logger.info("💾 Using SQLite persistent memory")
    
    init_user_db()
    
    app.state.workflow = build_workflow()
    app.state.memory = PersistentMemory()
    app.state.llm = LLMClient()
    app.state.scans = {}
    app.state.scan_traces = {}
    
    yield
    
    logger.info("👋 Shutting down...")

# ============================================
# FASTAPI APP
# ============================================

app = FastAPI(
    title="Multi-Agent Security Scanner",
    description="Security scanning with multi-agent orchestration",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve demo UI static files
_STATIC_DIR = Path(__file__).parent / "static"
if _STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

# ============================================
# ENDPOINTS DE BASE
# ============================================

@app.get("/ui", include_in_schema=False)
async def demo_ui():
    """Interface utilisateur de démonstration."""
    index = _STATIC_DIR / "index.html"
    if not index.exists():
        raise HTTPException(status_code=404, detail="UI not found")
    return FileResponse(str(index))

@app.get("/")
async def root():
    return {
        "name": "Multi-Agent Security Scanner",
        "version": "2.0.0",
        "status": "operational",
        "memory_backend": "SQLite",
        "endpoints": {
            "agents": "/agents",
            "local_scan": "/scan/local",
            "github_scan": "/scan/github",
            "user_register": "/user/register",
            "user_scan_github": "/user/{user_id}/scan",
            "user_scan_local": "/user/{user_id}/scan/local",
            "memory": "/memory/stats"
        }
    }

@app.get("/agents", response_model=list[AgentInfo])
async def list_agents():
    agents = [
        {"name": "triage", "description": "Detects languages, classifies targets", "status": "active", "methods": ["detect_languages", "classify_targets"]},
        {"name": "scanner", "description": "Static code analysis", "status": "active", "methods": ["semgrep", "bandit", "gosec"]},
        {"name": "memory_safety", "description": "Memory vulnerability analysis", "status": "active", "methods": ["buffer_overflow", "memory_leak"]},
        {"name": "semantic_analyst", "description": "LLM-based logic flaw detection", "status": "active", "methods": ["logic_analysis", "auth_bypass"]},
        {"name": "exploit_scorer", "description": "CVSS scoring", "status": "active", "methods": ["cvss_compute", "exploit_assess"]},
        {"name": "patcher", "description": "Patch generation", "status": "active", "methods": ["generate_patch", "apply_diff"]},
        {"name": "validator", "description": "Patch validation", "status": "active", "methods": ["validate", "regression_test"]},
        {"name": "report", "description": "Report generation", "status": "active", "methods": ["json", "markdown"]}
    ]
    return [AgentInfo(**agent) for agent in agents]

# ============================================
# SCAN LOCAL (dépôt sur disque)
# ============================================

@app.post("/scan/local")
async def scan_local_repository(request: LocalScanRequest, background_tasks: BackgroundTasks):
    """Scanner un dépôt local (sur disque)."""
    scan_id = str(uuid.uuid4())[:8]
    
    if not Path(request.repo_path).exists():
        raise HTTPException(status_code=400, detail=f"Repository path does not exist: {request.repo_path}")
    
    state = AgentState(
        repo_root=request.repo_path,
        scan_id=scan_id,
        max_patch_iterations=request.max_iterations
    )
    
    app.state.scans[scan_id] = {
        "state": state,
        "status": "running",
        "started_at": datetime.now().isoformat(),
        "repo_path": request.repo_path,
        "type": "local"
    }
    
    background_tasks.add_task(run_local_scan, scan_id, state)
    
    return {
        "scan_id": scan_id,
        "status": "started",
        "repo_path": request.repo_path,
        "message": f"Local scan started for {request.repo_path}"
    }

@app.get("/scan/local/{scan_id}")
async def get_local_scan_status(scan_id: str):
    """Statut d'un scan local."""
    if scan_id not in app.state.scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = app.state.scans[scan_id]
    state = scan_data.get("state")
    
    result = {
        "scan_id": scan_id,
        "status": scan_data["status"],
        "repo_path": scan_data.get("repo_path"),
        "started_at": scan_data["started_at"],
        "type": "local"
    }
    
    if scan_data["status"] == "completed" and state:
        result["vulnerabilities_count"] = len(state.vulnerabilities) if hasattr(state, 'vulnerabilities') else 0
        result["completed_at"] = scan_data.get("completed_at")
    elif scan_data["status"] == "failed":
        result["error"] = scan_data.get("error")
    
    return result

@app.get("/scan/local/{scan_id}/vulnerabilities")
async def get_local_vulnerabilities(scan_id: str):
    """Vulnérabilités d'un scan local."""
    if scan_id not in app.state.scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = app.state.scans[scan_id]
    state = scan_data.get("state")
    
    if not state or scan_data["status"] != "completed":
        return {"error": "Scan not completed yet"}
    
    vulns = []
    for v in state.vulnerabilities:
        vulns.append({
            "id": v.id,
            "title": v.title,
            "severity": v.severity.value,
            "cwe_id": v.cwe_id,
            "file_path": v.file_path,
            "line_start": v.line_start,
            "description": v.description,
            "cvss_score": v.cvss_score,
            "is_exploitable": v.is_exploitable,
            "suggested_fix": v.extra.get("suggested_fix", "")
        })
    
    return {
        "scan_id": scan_id,
        "repo_path": scan_data.get("repo_path"),
        "total": len(vulns),
        "vulnerabilities": vulns
    }

# ============================================
# SCAN GITHUB (distant)
# ============================================

@app.post("/scan/github")
async def scan_github_repository(request: GitHubScanRequest, background_tasks: BackgroundTasks):
    from github_client import get_github_client
    
    github = get_github_client()
    scan_id = str(uuid.uuid4())[:8]
    
    if "github.com" not in request.repo_url:
        raise HTTPException(status_code=400, detail="Invalid GitHub URL")
    
    logger.info(f"Cloning repository: {request.repo_url}")
    local_path = github.clone_repository(request.repo_url, request.branch)
    
    state = AgentState(repo_root=local_path, scan_id=scan_id, max_patch_iterations=request.max_iterations)
    
    app.state.scans[scan_id] = {
        "state": state,
        "status": "running",
        "started_at": datetime.now().isoformat(),
        "repo_url": request.repo_url,
        "branch": request.branch,
        "local_path": local_path,
        "type": "github",
        "cleanup_after": request.cleanup_after
    }
    
    background_tasks.add_task(run_github_scan, scan_id, state, local_path, request.cleanup_after)
    
    return GitHubScanResponse(
        scan_id=scan_id,
        status="started",
        repo_url=request.repo_url,
        branch=request.branch,
        local_path=local_path,
        message=f"Scan started for {request.repo_url}"
    )

@app.get("/scan/github/{scan_id}")
async def get_github_scan_status(scan_id: str):
    if scan_id not in app.state.scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = app.state.scans[scan_id]
    state = scan_data.get("state")
    
    result = {
        "scan_id": scan_id,
        "status": scan_data["status"],
        "repo_url": scan_data.get("repo_url"),
        "started_at": scan_data["started_at"]
    }
    
    if scan_data["status"] == "completed" and state:
        result["vulnerabilities_count"] = len(state.vulnerabilities) if hasattr(state, 'vulnerabilities') else 0
        result["completed_at"] = scan_data.get("completed_at")
    elif scan_data["status"] == "failed":
        result["error"] = scan_data.get("error")
    
    return result

@app.get("/scan/github/{scan_id}/vulnerabilities")
async def get_github_vulnerabilities(scan_id: str):
    if scan_id not in app.state.scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = app.state.scans[scan_id]
    state = scan_data.get("state")
    
    if not state or scan_data["status"] != "completed":
        return {"error": "Scan not completed yet"}
    
    vulns = []
    for v in state.vulnerabilities:
        vulns.append({
            "id": v.id,
            "title": v.title,
            "severity": v.severity.value,
            "cwe_id": v.cwe_id,
            "file_path": v.file_path,
            "line_start": v.line_start,
            "description": v.description,
            "cvss_score": v.cvss_score,
            "is_exploitable": v.is_exploitable
        })
    
    return {
        "scan_id": scan_id,
        "repo_url": scan_data.get("repo_url"),
        "total": len(vulns),
        "vulnerabilities": vulns
    }

# ============================================
# UTILISATEURS
# ============================================

@app.post("/user/register")
async def register_user(request: UserRegisterRequest):
    user = get_or_create_user(request.user_id, request.username)
    return {"status": "success", "user": user}

@app.post("/user/{user_id}/scan")
async def scan_github_for_user(user_id: str, request: UserScanRequest, background_tasks: BackgroundTasks):
    from github_client import get_github_client
    
    user = get_or_create_user(user_id)
    github = get_github_client()
    scan_id = str(uuid.uuid4())[:8]
    repo_name = request.repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    
    if "github.com" not in request.repo_url:
        raise HTTPException(status_code=400, detail="Invalid GitHub URL")
    
    local_path = github.clone_repository(request.repo_url, request.branch)
    state = AgentState(repo_root=local_path, scan_id=scan_id, max_patch_iterations=request.max_iterations)
    
    app.state.scans[scan_id] = {
        "state": state,
        "status": "running",
        "started_at": datetime.now().isoformat(),
        "repo_url": request.repo_url,
        "user_id": user_id,
        "repo_name": repo_name,
        "type": "github",
        "local_path": local_path
    }
    
    background_tasks.add_task(run_user_github_scan, scan_id, user_id, state, local_path, request.repo_url, repo_name)
    
    return {
        "scan_id": scan_id,
        "status": "started",
        "user_id": user_id,
        "repo_url": request.repo_url,
        "message": f"GitHub scan started for {request.repo_url}"
    }

@app.post("/user/{user_id}/scan/local")
async def scan_local_for_user(user_id: str, request: LocalScanRequest, background_tasks: BackgroundTasks):
    """Scanner un dépôt local pour un utilisateur."""
    user = get_or_create_user(user_id)
    scan_id = str(uuid.uuid4())[:8]
    repo_name = Path(request.repo_path).name
    
    if not Path(request.repo_path).exists():
        raise HTTPException(status_code=400, detail=f"Path does not exist: {request.repo_path}")
    
    state = AgentState(
        repo_root=request.repo_path,
        scan_id=scan_id,
        max_patch_iterations=request.max_iterations
    )
    
    app.state.scans[scan_id] = {
        "state": state,
        "status": "running",
        "started_at": datetime.now().isoformat(),
        "repo_path": request.repo_path,
        "user_id": user_id,
        "repo_name": repo_name,
        "type": "local"
    }
    
    background_tasks.add_task(run_user_local_scan, scan_id, user_id, state, request.repo_path, repo_name)
    
    return {
        "scan_id": scan_id,
        "status": "started",
        "user_id": user_id,
        "repo_path": request.repo_path,
        "message": f"Local scan started for {request.repo_path}"
    }

@app.get("/user/{user_id}/history")
async def get_user_history(user_id: str):
    get_or_create_user(user_id)
    
    conn = sqlite3.connect(".memory_cache.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT scan_id, repo_url, repo_name, scan_type, started_at, completed_at, vulnerabilities_count, status
        FROM scan_history
        WHERE user_id = ?
        ORDER BY started_at DESC
    """, (user_id,))
    
    history = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return {"user_id": user_id, "total_scans": len(history), "history": history}

@app.get("/user/{user_id}/projects")
async def get_user_projects(user_id: str):
    get_or_create_user(user_id)
    
    conn = sqlite3.connect(".memory_cache.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT repo_url, repo_name, last_scan, vulnerabilities_count, status
        FROM user_projects
        WHERE user_id = ?
        ORDER BY last_scan DESC
    """, (user_id,))
    
    projects = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return {"user_id": user_id, "total_projects": len(projects), "projects": projects}

# ============================================
# TRACES DES AGENTS (NOUVEAUX ENDPOINTS)
# ============================================

@app.get("/scan/{scan_id}/trace", response_model=ScanTrace)
async def get_scan_trace(scan_id: str):
    """Retourne la trace détaillée de l'exécution de tous les agents."""
    if scan_id not in app.state.scan_traces:
        raise HTTPException(status_code=404, detail="Scan trace not found")
    return app.state.scan_traces[scan_id]

@app.get("/scan/{scan_id}/agents")
async def get_agents_execution(scan_id: str):
    """Retourne quel agent a exécuté quel tool."""
    if scan_id not in app.state.scan_traces:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    trace = app.state.scan_traces[scan_id]
    result = []
    for agent_name, exec_trace in trace.agents_execution.items():
        result.append({
            "agent": agent_name,
            "status": exec_trace.status,
            "tools": exec_trace.tools_used,
            "methods_called": exec_trace.methods_called,
            "findings": exec_trace.findings_count,
            "duration_ms": exec_trace.execution_time_ms,
            "error": exec_trace.error
        })
    return {
        "scan_id": scan_id,
        "agents": result,
        "total_agents": len(result),
        "total_findings": trace.total_findings
    }

@app.get("/scan/{scan_id}/timeline")
async def get_agent_timeline(scan_id: str):
    """Timeline chronologique de l'exécution des agents."""
    if scan_id not in app.state.scan_traces:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    trace = app.state.scan_traces[scan_id]
    timeline = []
    for agent_name, exec_trace in trace.agents_execution.items():
        if exec_trace.started_at:
            timeline.append({
                "agent": agent_name,
                "status": exec_trace.status,
                "tools": exec_trace.tools_used,
                "started": exec_trace.started_at,
                "completed": exec_trace.completed_at,
                "duration_ms": exec_trace.execution_time_ms,
                "findings": exec_trace.findings_count
            })
    
    timeline.sort(key=lambda x: x["started"] if x["started"] else "")
    
    total_duration = None
    if trace.completed_at and trace.started_at:
        start = datetime.fromisoformat(trace.started_at)
        end = datetime.fromisoformat(trace.completed_at)
        total_duration = (end - start).total_seconds() * 1000
    
    return {
        "scan_id": scan_id,
        "timeline": timeline,
        "total_duration_ms": total_duration
    }

@app.get("/scans/latest")
async def get_latest_scans(limit: int = 10):
    """Retourne les derniers scans avec leur résumé."""
    scans = []
    for scan_id, trace in list(app.state.scan_traces.items())[-limit:]:
        scans.append({
            "scan_id": scan_id,
            "repo_path": trace.repo_path,
            "total_findings": trace.total_findings,
            "overall_status": trace.overall_status,
            "started_at": trace.started_at,
            "completed_at": trace.completed_at,
            "agents_summary": {
                agent: {
                    "status": exec_trace.status,
                    "findings": exec_trace.findings_count,
                    "tools": exec_trace.tools_used[:3]
                }
                for agent, exec_trace in trace.agents_execution.items()
            }
        })
    return {"scans": scans, "total": len(scans)}

@app.get("/diagnostic/scan/{scan_id}")
async def diagnostic_scan(scan_id: str):
    """Diagnostic rapide - montre l'état de tous les agents."""
    if scan_id not in app.state.scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = app.state.scans[scan_id]
    trace = app.state.scan_traces.get(scan_id)
    
    if not trace:
        return {
            "scan_id": scan_id,
            "status": scan_data["status"],
            "message": "Trace not yet available (scan may be running)",
            "agents": []
        }
    
    status_counts = {}
    agents_list = []
    for agent_name, exec_trace in trace.agents_execution.items():
        status_counts[exec_trace.status] = status_counts.get(exec_trace.status, 0) + 1
        agents_list.append({
            "name": agent_name,
            "status": exec_trace.status,
            "tools": exec_trace.tools_used[:3],
            "findings": exec_trace.findings_count
        })
    
    return {
        "scan_id": scan_id,
        "status": scan_data["status"],
        "agents_status": status_counts,
        "total_findings": trace.total_findings,
        "agents": agents_list,
        "trace_complete": trace.completed_at is not None
    }
# ============================================
# MÉMOIRE PERSISTANTE
# ============================================

@app.post("/memory/test")
async def test_persistent_memory(request: MemoryTestRequest):
    memory = app.state.memory
    
    if not hasattr(memory, '_enabled') or not memory._enabled:
        return {"status": "disabled", "message": "Persistent memory not available"}
    
    if request.action == "store":
        memory.store_pattern(request.pattern, request.code_snippet)
        return {"status": "success", "action": "store", "message": f"Stored pattern: {request.pattern[:50]}"}
    elif request.action == "retrieve":
        similar = memory.retrieve_similar_patterns([request.code_snippet])
        return {"status": "success", "action": "retrieve", "count": len(similar), "patterns": similar}
    
    return {"status": "error", "message": "Unknown action. Use 'store' or 'retrieve'"}

@app.get("/memory/stats")
async def memory_stats():
    memory = app.state.memory
    
    if hasattr(memory, 'get_stats'):
        return memory.get_stats()
    
    return {"status": "disabled", "message": "Stats not available"}

# ============================================
# BACKGROUND TASKS
# ============================================

async def run_local_scan(scan_id: str, state: AgentState):
    """Exécute un scan local en arrière-plan avec traçabilité."""
    from agents.triage import TriageAgent
    from agents.scanner import ScannerAgent
    from agents.memory_safety import MemorySafetyAgent
    from agents.semantic import SemanticAnalystAgent
    from agents.exploit_scorer import ExploitScorerAgent
    from agents.patcher import PatcherAgent
    from agents.validator import ValidatorAgent
    from agents.report import ReportAgent
    
    app.state.scans[scan_id]["status"] = "running"
    
    try:
        # Créer la liste des agents
        agents = [
            TriageAgent(),
            ScannerAgent(),
            MemorySafetyAgent(),
            SemanticAnalystAgent(),
            ExploitScorerAgent(),
            PatcherAgent(),
            ValidatorAgent(),
            ReportAgent()
        ]
        
        # Exécuter avec tracing
        final_state, traces = await run_workflow_with_tracing(state, agents)
        
        from graph.state import AgentState as StateClass
        if isinstance(final_state, dict):
            final_state = StateClass.from_dict(final_state)
        
        # Créer la trace
        now_iso = datetime.now().isoformat()
        
        # Convertir les traces au format ScanTrace
        agents_execution = {}
        for agent_name, trace_data in traces.items():
            agents_execution[agent_name] = AgentExecutionTrace(
                agent_name=agent_name,
                status=trace_data.get("status", "unknown"),
                tools_used=trace_data.get("tools_used", []),
                methods_called=trace_data.get("methods_called", []),
                findings_count=trace_data.get("findings_count", 0),
                execution_time_ms=trace_data.get("execution_time_ms", 0),
                started_at=trace_data.get("started_at"),
                completed_at=trace_data.get("completed_at"),
                error=trace_data.get("error")
            )
        
        scan_trace = ScanTrace(
            scan_id=scan_id,
            repo_path=app.state.scans[scan_id]["repo_path"],
            total_agents=len(agents),
            agents_execution=agents_execution,
            total_findings=len(final_state.vulnerabilities),
            overall_status="completed",
            started_at=app.state.scans[scan_id]["started_at"],
            completed_at=now_iso
        )
        
        app.state.scan_traces[scan_id] = scan_trace
        app.state.scans[scan_id]["state"] = final_state
        app.state.scans[scan_id]["status"] = "completed"
        app.state.scans[scan_id]["completed_at"] = now_iso
        
        logger.info(f"Local scan {scan_id} completed: {len(final_state.vulnerabilities)} findings")
        
        # Afficher résumé
        for agent_name, trace_data in traces.items():
            logger.info(f"  📊 {agent_name}: {trace_data.get('status')} - {trace_data.get('findings_count', 0)} findings in {trace_data.get('execution_time_ms', 0):.2f}ms")
        
    except Exception as e:
        logger.error(f"Local scan {scan_id} failed: {e}", exc_info=True)
        app.state.scans[scan_id]["status"] = "failed"
        app.state.scans[scan_id]["error"] = str(e)

async def run_github_scan(scan_id: str, state: AgentState, local_path: str, cleanup_after: bool):
    from github_client import get_github_client
    
    github = get_github_client()
    
    try:
        workflow = app.state.workflow
        final_state = await workflow.ainvoke(state)
        
        from graph.state import AgentState as StateClass
        if isinstance(final_state, dict):
            final_state = StateClass.from_dict(final_state)
        
        app.state.scans[scan_id]["state"] = final_state
        app.state.scans[scan_id]["status"] = "completed"
        app.state.scans[scan_id]["completed_at"] = datetime.now().isoformat()
        
        logger.info(f"github scan {scan_id} completed: {len(final_state.vulnerabilities)} findings")
        
    except Exception as e:
        logger.error(f"github scan {scan_id} failed: {e}", exc_info=True)
        app.state.scans[scan_id]["status"] = "failed"
        app.state.scans[scan_id]["error"] = str(e)
    finally:
        if cleanup_after:
            try:
                github.cleanup(local_path)
            except Exception as e:
                logger.warning(f"Cleanup failed: {e}")

async def run_user_github_scan(scan_id: str, user_id: str, state: AgentState, local_path: str, 
                                repo_url: str, repo_name: str):
    from github_client import get_github_client
    
    github = get_github_client()
    
    try:
        workflow = app.state.workflow
        final_state = await workflow.ainvoke(state)
        
        from graph.state import AgentState as StateClass
        if isinstance(final_state, dict):
            final_state = StateClass.from_dict(final_state)
        
        vulns = []
        for v in final_state.vulnerabilities:
            vulns.append({
                "id": v.id,
                "title": v.title,
                "severity": v.severity.value,
                "cwe_id": v.cwe_id,
                "file_path": v.file_path,
                "description": v.description,
                "cvss_score": v.cvss_score
            })
        
        app.state.scans[scan_id]["state"] = final_state
        app.state.scans[scan_id]["status"] = "completed"
        app.state.scans[scan_id]["completed_at"] = datetime.now().isoformat()
        
        save_scan_for_user(scan_id, user_id, repo_url, repo_name, len(final_state.vulnerabilities), 
                          vulns, final_state.report, "github")
        
        logger.info(f"User {user_id} github scan completed: {len(final_state.vulnerabilities)} findings")
        
    except Exception as e:
        logger.error(f"User github scan failed: {e}", exc_info=True)
        app.state.scans[scan_id]["status"] = "failed"
        app.state.scans[scan_id]["error"] = str(e)
    finally:
        try:
            github.cleanup(local_path)
        except Exception as e:
            logger.warning(f"Cleanup failed: {e}")

async def run_user_local_scan(scan_id: str, user_id: str, state: AgentState, repo_path: str, repo_name: str):
    """Exécute un scan local pour un utilisateur."""
    try:
        workflow = app.state.workflow
        final_state = await workflow.ainvoke(state)
        
        from graph.state import AgentState as StateClass
        if isinstance(final_state, dict):
            final_state = StateClass.from_dict(final_state)
        
        vulns = []
        for v in final_state.vulnerabilities:
            vulns.append({
                "id": v.id,
                "title": v.title,
                "severity": v.severity.value,
                "cwe_id": v.cwe_id,
                "file_path": v.file_path,
                "description": v.description,
                "cvss_score": v.cvss_score
            })
        
        app.state.scans[scan_id]["state"] = final_state
        app.state.scans[scan_id]["status"] = "completed"
        app.state.scans[scan_id]["completed_at"] = datetime.now().isoformat()
        
        save_scan_for_user(scan_id, user_id, repo_path, repo_name, len(final_state.vulnerabilities), 
                          vulns, final_state.report, "local")
        
        logger.info(f"User {user_id} local scan completed: {len(final_state.vulnerabilities)} findings")
        
    except Exception as e:
        logger.error(f"User local scan failed: {e}", exc_info=True)
        app.state.scans[scan_id]["status"] = "failed"
        app.state.scans[scan_id]["error"] = str(e)

# ============================================
# MAIN
# ============================================

def main():
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║     Multi-Agent Security Scanner - Serveur API              ║
    ║                                                              ║
    ║    REST API:  http://localhost:8000                         ║
    ║    Docs:      http://localhost:8000/docs                    ║
    ║                                                              ║
    ║    Memory:    SQLite (persistant)                           ║
    ║    Agents:    8 agents spécialisés                          ║
    ║                                                              ║
    ║    Endpoints disponibles:                                   ║
    ║    - GET  /agents                          → Liste des agents
    ║    - POST /scan/local                      → Scanner dépôt local
    ║    - POST /scan/github                     → Scanner dépôt GitHub
    ║    - POST /user/register                   → Créer utilisateur
    ║    - POST /user/{id}/scan                  → Scan GitHub pour user
    ║    - POST /user/{id}/scan/local            → Scan local pour user
    ║    - GET  /user/{id}/history               → Historique user
    ║    - GET  /user/{id}/projects              → Projets user
    ║    - POST /memory/test                     → Tester mémoire
    ║    - GET  /memory/stats                    → Stats mémoire
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True, log_level="info")

if __name__ == "__main__":
    main()