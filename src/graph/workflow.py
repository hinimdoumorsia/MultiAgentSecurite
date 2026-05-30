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


def build_workflow() -> StateGraph:
    graph = StateGraph(AgentState)

    # Register agents as nodes
    graph.add_node("triage", TriageAgent().run)
    graph.add_node("scanner", ScannerAgent().run)
    graph.add_node("memory_safety", MemorySafetyAgent().run)
    graph.add_node("semantic_analyst", SemanticAnalystAgent().run)
    graph.add_node("exploit_scorer", ExploitScorerAgent().run)
    graph.add_node("patcher", PatcherAgent().run)
    graph.add_node("validator", ValidatorAgent().run)
    graph.add_node("report", ReportAgent().run)

    # Entry point
    graph.set_entry_point("triage")

    # Edges
    graph.add_conditional_edges(
        "triage",
        route_after_triage,
        {"scanner": "scanner", "report": "report"},
    )

    # After scanner: parallel fan-out to memory_safety + semantic_analyst
    graph.add_conditional_edges(
        "scanner",
        route_after_analysis,
        {
            "exploit_scorer": "exploit_scorer",
            "report": "report",
        },
    )

    graph.add_edge("memory_safety", "exploit_scorer")
    graph.add_edge("semantic_analyst", "exploit_scorer")

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