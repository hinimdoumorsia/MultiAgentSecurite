"""
SecureCodeAgent — Orchestrateur LangGraph
Architecture multi-agent pour la révision de code orientée sécurité.
Utilise Groq API (llama-3.3-70b-versatile) comme moteur LLM.
"""

import os
import json
import asyncio
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from typing import Optional, Callable, AsyncIterator

# LangGraph
from langgraph.graph import StateGraph, END

# Groq
from groq import AsyncGroq

# Agents locaux
from agents.indexation_agent import CodeIndexer
from agents.security_agent import SecurityAnalyzer
from agents.review_agent import LLMReviewer
from agents.aggregator_agent import ResultAggregator
from agents.patch_agent import PatchGenerator

# Reporter (événements terminal)
from .reporter import (
    EVENT_STEP_START, EVENT_STEP_DONE, EVENT_FINDING,
    EVENT_MEMORY, EVENT_ERROR, EVENT_DONE, EVENT_TOKEN
)


# ─────────────────────────────────────────────
# 1. ÉTAT PARTAGÉ
# ─────────────────────────────────────────────

from typing import TypedDict

class AgentState(TypedDict):
    repo_url: str
    pr_number: Optional[int]
    target_files: list[str]
    language: str
    code_index: dict
    security_findings: list
    llm_review: dict
    aggregated_report: dict
    patches: list
    errors: list[str]
    iteration: int
    confidence_score: float
    should_patch: bool
    status: str
    # callback injecté pour les événements (non sérialisable, ignoré par LangGraph)
    _emit: Optional[object]


# ─────────────────────────────────────────────
# 2. HELPER D'ÉMISSION D'ÉVÉNEMENTS
# ─────────────────────────────────────────────

def _emit(state: AgentState, event_type: str, data: dict):
    """Appelle le callback reporter si présent. Thread-safe."""
    cb = state.get("_emit")
    if cb and callable(cb):
        try:
            cb(event_type, data)
        except Exception:
            pass  # ne jamais bloquer le pipeline pour le reporter


# ─────────────────────────────────────────────
# 3. NŒUDS DU GRAPHE
# ─────────────────────────────────────────────

async def node_indexation(state: AgentState) -> AgentState:
    _emit(state, EVENT_STEP_START, {"step": "indexation"})
    _emit(state, EVENT_MEMORY, {"key": "repo", "value": state["repo_url"][-50:]})
    try:
        indexer = CodeIndexer()
        index = await indexer.index_repository(
            repo_url=state["repo_url"],
            target_files=state["target_files"],
            language=state["language"]
        )
        _emit(state, EVENT_MEMORY, {"key": "files_found", "value": str(index.get("files_count", 0))})
        _emit(state, EVENT_MEMORY, {"key": "total_lines", "value": str(index.get("total_lines", 0))})
        _emit(state, EVENT_STEP_DONE, {"step": "indexation"})
        return {**state, "code_index": index, "status": "indexed"}
    except Exception as e:
        _emit(state, EVENT_ERROR, {"message": f"Indexation: {e}"})
        return {**state, "errors": state["errors"] + [f"Indexation: {e}"], "status": "failed"}


async def node_security_analysis(state: AgentState) -> AgentState:
    if state["status"] == "failed":
        return state
    _emit(state, EVENT_STEP_START, {"step": "security"})
    try:
        analyzer = SecurityAnalyzer()
        findings = await analyzer.analyze(
            code_index=state["code_index"],
            language=state["language"]
        )
        # Émettre chaque finding individuellement → visible en temps réel
        for f in findings:
            _emit(state, EVENT_FINDING, f)
        _emit(state, EVENT_MEMORY, {"key": "static_findings", "value": str(len(findings))})
        _emit(state, EVENT_STEP_DONE, {"step": "security"})
        return {**state, "security_findings": findings, "status": "analyzed"}
    except Exception as e:
        _emit(state, EVENT_ERROR, {"message": f"SecurityAnalysis: {e}"})
        return {**state, "errors": state["errors"] + [f"SecurityAnalysis: {e}"], "status": "failed"}


async def node_llm_review(state: AgentState) -> AgentState:
    if state["status"] == "failed":
        return state
    _emit(state, EVENT_STEP_START, {"step": "llm_review"})
    _emit(state, EVENT_MEMORY, {"key": "llm_model", "value": "llama-3.3-70b-versatile"})
    try:
        reviewer = LLMReviewer(
            api_key=os.environ["GROQ_API_KEY"],
            model="llama-3.3-70b-versatile",
            max_context_tokens=8000,
            # On passe le callback token pour streaming terminal
            token_callback=lambda t: _emit(state, EVENT_TOKEN, {"token": t})
        )
        review = await reviewer.review(
            code_index=state["code_index"],
            security_findings=state["security_findings"]
        )
        # Émettre les findings LLM
        for file_result in review.get("results", []):
            for vuln in file_result.get("vulnerabilities", []):
                _emit(state, EVENT_FINDING, vuln)
        llm_count = sum(len(r.get("vulnerabilities", [])) for r in review.get("results", []))
        _emit(state, EVENT_MEMORY, {"key": "llm_findings", "value": str(llm_count)})
        _emit(state, EVENT_STEP_DONE, {"step": "llm_review"})
        return {**state, "llm_review": review, "status": "reviewed"}
    except Exception as e:
        _emit(state, EVENT_ERROR, {"message": f"LLMReview: {e}"})
        return {**state, "errors": state["errors"] + [f"LLMReview: {e}"], "status": "failed"}


async def node_aggregation(state: AgentState) -> AgentState:
    if state["status"] == "failed":
        return state
    _emit(state, EVENT_STEP_START, {"step": "aggregation"})
    try:
        aggregator = ResultAggregator()
        report = await aggregator.aggregate(
            security_findings=state["security_findings"],
            llm_review=state["llm_review"],
            code_index=state["code_index"]
        )
        confidence = report.get("confidence_score", 0.0)
        risk = report.get("risk_score", 0.0)
        should_patch = confidence > 0.75 and len(report.get("critical_vulns", [])) > 0
        _emit(state, EVENT_MEMORY, {"key": "risk_score", "value": f"{risk:.2f}/10"})
        _emit(state, EVENT_MEMORY, {"key": "confidence", "value": f"{confidence*100:.0f}%"})
        _emit(state, EVENT_MEMORY, {"key": "patch_needed", "value": str(should_patch)})
        _emit(state, EVENT_STEP_DONE, {"step": "aggregation"})
        return {
            **state,
            "aggregated_report": report,
            "confidence_score": confidence,
            "should_patch": should_patch,
            "status": "aggregated"
        }
    except Exception as e:
        _emit(state, EVENT_ERROR, {"message": f"Aggregation: {e}"})
        return {**state, "errors": state["errors"] + [f"Aggregation: {e}"], "status": "failed"}


async def node_patch_generation(state: AgentState) -> AgentState:
    if state["status"] == "failed" or not state.get("should_patch", False):
        return {**state, "patches": [], "status": "completed"}
    _emit(state, EVENT_STEP_START, {"step": "patching"})
    try:
        patcher = PatchGenerator(
            api_key=os.environ["GROQ_API_KEY"],
            model="llama-3.3-70b-versatile"
        )
        patches = await patcher.generate(
            report=state["aggregated_report"],
            code_index=state["code_index"]
        )
        _emit(state, EVENT_MEMORY, {"key": "patches_generated", "value": str(len(patches))})
        _emit(state, EVENT_STEP_DONE, {"step": "patching"})
        return {**state, "patches": patches, "status": "completed"}
    except Exception as e:
        _emit(state, EVENT_ERROR, {"message": f"PatchGen: {e}"})
        return {**state, "patches": [], "status": "completed"}


# ─────────────────────────────────────────────
# 4. ROUTEUR
# ─────────────────────────────────────────────

def route_after_aggregation(state: AgentState) -> str:
    if state["status"] == "failed":
        return "end"
    return "patch" if state.get("should_patch", False) else "end"


# ─────────────────────────────────────────────
# 5. CONSTRUCTION DU GRAPHE
# ─────────────────────────────────────────────

def build_graph() -> StateGraph:
    graph = StateGraph(AgentState)
    graph.add_node("indexation", node_indexation)
    graph.add_node("security", node_security_analysis)
    graph.add_node("llm_review", node_llm_review)
    graph.add_node("aggregation", node_aggregation)
    graph.add_node("patching", node_patch_generation)
    graph.set_entry_point("indexation")
    graph.add_edge("indexation", "security")
    graph.add_edge("security", "llm_review")
    graph.add_edge("llm_review", "aggregation")
    graph.add_conditional_edges(
        "aggregation",
        route_after_aggregation,
        {"patch": "patching", "end": END}
    )
    graph.add_edge("patching", END)
    return graph.compile()


# ─────────────────────────────────────────────
# 6. POINT D'ENTRÉE PUBLIC
# ─────────────────────────────────────────────

async def run_analysis(
    repo_url: str,
    pr_number: Optional[int] = None,
    target_files: Optional[list] = None,
    language: str = "python",
    on_event: Optional[Callable] = None  # ← callback pour le reporter
) -> dict:
    """Lance une analyse complète avec événements en temps réel."""
    graph = build_graph()

    initial_state: AgentState = {
        "repo_url": repo_url,
        "pr_number": pr_number,
        "target_files": target_files or [],
        "language": language,
        "code_index": {},
        "security_findings": [],
        "llm_review": {},
        "aggregated_report": {},
        "patches": [],
        "errors": [],
        "iteration": 0,
        "confidence_score": 0.0,
        "should_patch": False,
        "status": "running",
        "_emit": on_event,  # callback injecté, non sérialisé par LangGraph
    }

    final_state = await graph.ainvoke(initial_state)

    result = {
        "status": final_state["status"],
        "report": final_state["aggregated_report"],
        "patches": final_state["patches"],
        "errors": final_state["errors"],
        "confidence": final_state["confidence_score"]
    }

    # Événement final
    if on_event:
        on_event(EVENT_DONE, {
            "risk_score": final_state["aggregated_report"].get("risk_score", 0),
            "total_findings": final_state["aggregated_report"].get("total_findings", 0)
        })

    return result


# ─────────────────────────────────────────────
# 7. GÉNÉRATEUR SSE (pour FastAPI)
# ─────────────────────────────────────────────

async def run_analysis_stream(
    repo_url: str,
    target_files: Optional[list] = None,
    language: str = "python"
) -> AsyncIterator[str]:
    """
    Générateur async pour Server-Sent Events.
    Chaque événement est émis sous forme de 'data: {...}\\n\\n'
    Compatible avec EventSource côté navigateur et curl --no-buffer.
    """
    queue: asyncio.Queue = asyncio.Queue()

    def on_event(event_type: str, data: dict):
        """Callback synchrone → push dans la queue async."""
        payload = json.dumps({"type": event_type, **data}, ensure_ascii=False)
        asyncio.get_running_loop().call_soon_threadsafe(queue.put_nowait, payload)

    async def run():
        result = await run_analysis(
            repo_url=repo_url,
            target_files=target_files or [],
            language=language,
            on_event=on_event
        )
        await queue.put(None)  # sentinel de fin
        return result

    task = asyncio.create_task(run())

    while True:
        item = await queue.get()
        if item is None:
            break
        yield f"data: {item}\n\n"

    await task  # s'assurer que les exceptions remontent