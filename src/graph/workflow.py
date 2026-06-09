"""LangGraph workflow definition for the multi-agent security pipeline."""

from __future__ import annotations

import sys
import os

# Ajoute le dossier src au chemin Python
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from langgraph.graph import END, StateGraph

# Changement : enlever "orchestrator."
from agents.exploit_scorer import ExploitScorerAgent
from agents.memory_safety import MemorySafetyAgent
from agents.patcher import PatcherAgent
from agents.report import ReportAgent
from agents.scanner import ScannerAgent
from agents.semantic import SemanticAnalystAgent
from agents.triage import TriageAgent
from agents.validator import ValidatorAgent

import time
from datetime import datetime
from typing import Dict, List

# Changement : enlever "orchestrator."
from graph.router import (
    route_after_analysis,
    route_after_exploit_scorer,
    route_after_patcher,
    route_after_triage,
    route_after_validator,
)
from graph.state import AgentState


def build_workflow(detection_only: bool = False, skip_semantic: bool = False,
                   skip_scanner: bool = False, skip_memory: bool = False) -> StateGraph:
    """Construit le graphe LangGraph.

    detection_only=True : pipeline de DÉTECTION seule (triage -> scanner ->
        memory_safety -> semantic_analyst -> report). On saute exploit_scorer
        (scoring LLM coûteux et inutile pour la détection), patcher et validator.
        Utilisé par le benchmark de détection sur gros volume.

    detection_only=False : pipeline complet avec scoring, génération de patch et
        validation (boucle de retry jusqu'à max_patch_iterations).

    skip_semantic=True : ABLATION — on ne câble PAS le SemanticAnalystAgent (LLM).
        Le flux passe directement de memory_safety à l'étape suivante (report en
        détection, exploit_scorer sinon). Sert à mesurer l'apport réel du
        raisonnement sémantique LLM par rapport aux seuls outils SAST.

    Note : l'analyse est câblée en SÉQUENTIEL (scanner -> memory_safety ->
    semantic_analyst) pour garantir que les deux agents tournent réellement.
    memory_safety se court-circuite seul s'il n'y a pas de C/C++/Rust.
    """
    graph = StateGraph(AgentState)

    # Sous-ensemble d'analyseurs activés (ablation : skip_scanner/skip_memory/skip_semantic).
    analyzers = [
        ("scanner", ScannerAgent, not skip_scanner),
        ("memory_safety", MemorySafetyAgent, not skip_memory),
        ("semantic_analyst", SemanticAnalystAgent, not skip_semantic),
    ]
    enabled = [name for name, _, on in analyzers if on]

    # Register agents as nodes
    graph.add_node("triage", TriageAgent().run)
    for name, cls, on in analyzers:
        if on:
            graph.add_node(name, cls().run)
    graph.add_node("report", ReportAgent().run)
    if not detection_only:
        graph.add_node("exploit_scorer", ExploitScorerAgent().run)
        graph.add_node("patcher", PatcherAgent().run)
        graph.add_node("validator", ValidatorAgent().run)

    # Entry point
    graph.set_entry_point("triage")

    # triage -> premier analyseur activé (ou report si aucun).
    first = enabled[0] if enabled else "report"
    graph.add_conditional_edges(
        "triage",
        route_after_triage,
        {"scanner": first, "report": "report"},
    )

    # Analyse séquentielle sur le sous-ensemble activé.
    for a, b in zip(enabled, enabled[1:]):
        graph.add_edge(a, b)
    analysis_exit = enabled[-1] if enabled else "triage"

    if detection_only:
        graph.add_edge(analysis_exit, "report")
    else:
        graph.add_edge(analysis_exit, "exploit_scorer")
        graph.add_conditional_edges(
            "exploit_scorer",
            route_after_exploit_scorer,
            {"patcher": "patcher", "report": "report"},
        )
        graph.add_conditional_edges(
            "patcher",
            route_after_patcher,
            {"validator": "validator", "report": "report"},
        )
        graph.add_conditional_edges(
            "validator",
            route_after_validator,
            {"patcher": "patcher", "report": "report"},
        )

    graph.add_edge("report", END)

    return graph.compile()



# Ajouter dans workflow.py

async def run_workflow_with_tracing(state: AgentState, agents: List[BaseAgent]) -> tuple[AgentState, Dict[str, dict]]:
    """Exécute tous les agents avec traçabilité complète."""
    traces = {}
    current_state = state
    
    for agent in agents:
        # Exécuter l'agent avec trace
        result_state, trace = agent.run_with_trace(current_state)
        traces[agent.name] = trace.to_dict()
        current_state = result_state
        
        # Logging
        print(f"[WORKFLOW] {agent.name}: {trace.status} - {trace.findings_count} findings in {trace.execution_time_ms:.2f}ms")
        if trace.tools_used:
            print(f"         Tools: {', '.join(trace.tools_used)}")
    
    return current_state, traces