"""Base class for all security agents."""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Dict, Any

from graph.state import AgentState

logger = logging.getLogger(__name__)


# ============================================
# TRACING CLASSES (définies AVANT BaseAgent)
# ============================================

class AgentTrace:
    """Trace d'exécution d'un agent."""
    
    def __init__(self, agent_name: str):
        self.agent_name = agent_name
        self.status = "pending"  # pending, running, completed, failed, skipped
        self.tools_used: List[str] = []
        self.methods_called: List[str] = []
        self.findings_count = 0
        self.execution_time_ms = 0.0
        self.started_at: str | None = None
        self.completed_at: str | None = None
        self.error: str | None = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "status": self.status,
            "tools_used": self.tools_used,
            "methods_called": self.methods_called,
            "findings_count": self.findings_count,
            "execution_time_ms": self.execution_time_ms,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "error": self.error
        }


class AgentTracingMixin:
    """Mixin pour ajouter le tracing aux agents."""
    
    name: str = "base"
    
    def run_with_trace(self, state: AgentState) -> tuple[AgentState, AgentTrace]:
        """Exécute l'agent avec traçage complet."""
        trace = AgentTrace(self.name)
        
        # Récupérer les méthodes disponibles pour cet agent
        trace.tools_used = self._get_available_methods()
        
        try:
            trace.status = "running"
            trace.started_at = datetime.now().isoformat()
            start_time = time.time()
            
            # Exécuter l'agent
            result_state = self.run(state)
            
            # Calculer le temps d'exécution
            trace.execution_time_ms = (time.time() - start_time) * 1000
            trace.completed_at = datetime.now().isoformat()
            
            # Compter les findings
            trace.findings_count = self._count_findings(result_state)
            trace.methods_called = self._get_called_methods(result_state)
            trace.status = "completed"
            
            return result_state, trace
            
        except Exception as e:
            trace.status = "failed"
            trace.error = str(e)
            trace.completed_at = datetime.now().isoformat()
            return state, trace
    
    def _get_available_methods(self) -> List[str]:
        """Retourne la liste des méthodes/tools disponibles pour cet agent."""
        return []
    
    def _get_called_methods(self, state: AgentState) -> List[str]:
        """Retourne quelles méthodes ont été effectivement appelées."""
        return []
    
    def _count_findings(self, state: AgentState) -> int:
        """Compte le nombre de vulnérabilités trouvées."""
        total = 0
        if hasattr(state, 'vulnerabilities'):
            total += len(state.vulnerabilities)
        if hasattr(state, 'memory_safety_findings'):
            total += len(state.memory_safety_findings)
        if hasattr(state, 'semantic_findings'):
            total += len(state.semantic_findings)
        return total


# ============================================
# BASE AGENT (hérite du Mixin)
# ============================================

class BaseAgent(ABC, AgentTracingMixin):
    """Classe de base pour tous les agents."""
    
    name: str = "base"

    def run(self, state: AgentState) -> AgentState:
        """Exécute l'agent (sans tracing - utilisé en interne)."""
        logger.info("[%s] starting", self.name)
        state.current_agent = self.name
        try:
            state = self._execute(state)
        except Exception as exc:  # noqa: BLE001
            logger.exception("[%s] error: %s", self.name, exc)
            state.errors.append(f"{self.name}: {exc}")
        logger.info("[%s] done", self.name)
        return state

    @abstractmethod
    def _execute(self, state: AgentState) -> AgentState:
        """Méthode interne à implémenter par chaque agent."""
        pass