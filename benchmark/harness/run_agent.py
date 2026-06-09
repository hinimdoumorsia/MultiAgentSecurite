"""Invocation de l'agent MultiAgentSecurite sur un cas, sortie normalisee.

Deux runners interchangeables (meme interface .run(label) -> CaseResult) :

  - AgentRunner : invoque le vrai workflow LangGraph (necessite cles API + outils SAST).
  - MockRunner  : lit benchmark/datasets/.../_mock_findings.json a cote du cas.
                  Sert a valider toute la chaine matching/metriques SANS API ni reseau.

Pour brancher un outil concurrent plus tard, ecrire un runner equivalent qui
ressort une liste[AgentFinding] (cf. plan, section "Extension future").
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from MultiAgentSecurite.benchmark.harness.schema import AgentFinding, CaseResult, GroundTruthLabel

# Racine du repo = parent de benchmark/
_REPO_ROOT = Path(__file__).resolve().parents[2]
_SRC = _REPO_ROOT / "src"


class MockRunner:
    """Runner sans agent : lit des findings preenregistres. Pour tests/CI."""

    name = "mock"

    def run(self, label: GroundTruthLabel, run_index: int = 0) -> CaseResult:
        mock_file = Path(label.repo_path) / "_mock_findings.json"
        findings: list[AgentFinding] = []
        error = None
        if mock_file.exists():
            try:
                data = json.loads(mock_file.read_text(encoding="utf-8"))
                findings = [AgentFinding.from_report_dict(d) for d in data]
            except Exception as exc:  # noqa: BLE001
                error = f"mock parse error: {exc}"
        return CaseResult(
            case_id=label.case_id,
            dataset=label.dataset,
            language=label.language,
            run_index=run_index,
            findings=findings,
            error=error,
        )


class AgentRunner:
    """Runner reel : invoque le workflow LangGraph de l'agent."""

    name = "agent"

    def __init__(self, max_iterations: int = 3, timeout_sec: int = 600,
                 detection_only: bool = False, skip_semantic: bool = False,
                 skip_scanner: bool = False, skip_memory: bool = False) -> None:
        self.max_iterations = max_iterations
        self.timeout_sec = timeout_sec
        self.detection_only = detection_only
        self.skip_semantic = skip_semantic  # ablation : désactive le SemanticAnalystAgent (LLM)
        self.skip_scanner = skip_scanner    # ablation : désactive le ScannerAgent (SAST)
        self.skip_memory = skip_memory      # ablation : désactive le MemorySafetyAgent (Rust)
        self._app = None  # construit paresseusement (import lourd)

    def _ensure_app(self):
        if self._app is None:
            if str(_SRC) not in sys.path:
                sys.path.insert(0, str(_SRC))
            os.chdir(_REPO_ROOT)  # l'agent ecrit .scan_cache relatif a la racine
            from graph.workflow import build_workflow  # noqa: WPS433
            self._app = build_workflow(detection_only=self.detection_only,
                                       skip_semantic=self.skip_semantic,
                                       skip_scanner=self.skip_scanner,
                                       skip_memory=self.skip_memory)
        return self._app

    def run(self, label: GroundTruthLabel, run_index: int = 0) -> CaseResult:
        app = self._ensure_app()          # ajoute src/ au sys.path AVANT d'importer graph
        from graph.state import AgentState  # import tardif (apres _ensure_app)
        result = CaseResult(
            case_id=label.case_id,
            dataset=label.dataset,
            language=label.language,
            run_index=run_index,
        )
        start = time.time()
        try:
            state = AgentState(
                repo_root=label.repo_path,
                scan_id=f"{label.case_id}-r{run_index}",
                max_patch_iterations=self.max_iterations,
            )
            final = app.invoke(state)
            report = _extract_report(final)
            vulns = report.get("vulnerabilities", []) if report else []
            result.findings = [AgentFinding.from_report_dict(v) for v in vulns]
        except Exception as exc:  # noqa: BLE001
            result.error = f"{type(exc).__name__}: {exc}"
        finally:
            result.duration_sec = round(time.time() - start, 2)
        return result


def _extract_report(final) -> dict | None:
    """LangGraph peut renvoyer un AddableValuesDict ou un AgentState."""
    if final is None:
        return None
    if isinstance(final, dict):
        return final.get("report")
    return getattr(final, "report", None)
