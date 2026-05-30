"""Memory Safety Agent: deep analysis of memory vulnerabilities via Rust engine."""

from __future__ import annotations

import json
import logging
import platform
import subprocess
from pathlib import Path

from agents.base import BaseAgent
from graph.state import AgentState, Severity, Vulnerability

logger = logging.getLogger(__name__)

# ── Résolution du binaire ────────────────────────────────────────────────────
# On cherche dans cet ordre :
#   1. memory-engine/bins/<os>/   <- binaire commité dans le repo (prioritaire)
#   2. memory-engine/target/release/   <- build local cargo
#
# _PROJECT_ROOT = racine du dépôt (deux niveaux au-dessus de src/agents/)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

_OS_DIR = {
    "windows": "windows",
    "linux":   "linux",
    "darwin":  "macos",
}.get(platform.system().lower(), "linux")

_BIN_NAME = "memory-engine.exe" if platform.system().lower() == "windows" else "memory-engine"

_SEARCH_PATHS = [
    _PROJECT_ROOT / "memory-engine" / "bins" / _OS_DIR / _BIN_NAME,
    _PROJECT_ROOT / "memory-engine" / "target" / "release" / _BIN_NAME,
]


def _find_binary() -> Path | None:
    for p in _SEARCH_PATHS:
        if p.exists():
            logger.debug("memory-engine binary found at %s", p)
            return p
    return None


class MemorySafetyAgent(BaseAgent):
    name = "memory_safety"

    def _execute(self, state: AgentState) -> AgentState:
        if not state.needs_memory_safety:
            logger.debug("[memory_safety] no C/C++/Rust files — skipping")
            return state

        bin_path = _find_binary()
        if bin_path is None:
            logger.warning(
                "[memory_safety] binary not found. Searched:\n%s\n"
                "Build it with: cd memory-engine && cargo build --release",
                "\n".join(f"  - {p}" for p in _SEARCH_PATHS),
            )
            return state

        try:
            result = subprocess.run(
                [str(bin_path), "--json", state.repo_root],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode != 0:
                logger.error("[memory_safety] engine stderr: %s", result.stderr)
                state.errors.append(f"memory_safety: engine exited {result.returncode}")
                return state

            raw = json.loads(result.stdout)

        except subprocess.TimeoutExpired:
            state.errors.append("memory_safety: timeout after 120s")
            return state
        except json.JSONDecodeError as exc:
            state.errors.append(f"memory_safety: invalid JSON output — {exc}")
            return state

        findings: list[Vulnerability] = []
        for item in raw.get("findings", []):
            try:
                vuln = Vulnerability(
                    id=item["id"],
                    title=item["title"],
                    severity=Severity(item.get("severity", "high")),
                    cwe_id=item.get("cwe", "CWE-119"),
                    cve_id=item.get("cve"),
                    file_path=item["file"],
                    line_start=item["line_start"],
                    line_end=item["line_end"],
                    code_snippet=item.get("snippet", ""),
                    description=item["description"],
                    memory_safety_issue=True,
                )
                findings.append(vuln)
            except (KeyError, ValueError) as exc:
                logger.warning("[memory_safety] skipping malformed finding: %s", exc)

        state.memory_safety_findings = findings
        logger.info(
            "[memory_safety] %d finding(s) via %s",
            len(findings),
            bin_path.relative_to(_PROJECT_ROOT),
        )
        return state
    


    # Ajouter ces méthodes à la fin de la classe MemorySafetyAgent

    def _get_available_methods(self) -> list[str]:
        """Retourne les méthodes disponibles pour cet agent."""
        return ["buffer_overflow", "memory_leak", "use_after_free", "double_free", "null_dereference", "out_of_bounds"]
    
    def _get_called_methods(self, state: AgentState) -> list[str]:
        """Retourne quelles méthodes ont été appelées."""
        called = []
        # Vérifier quels types de vulnérabilités ont été trouvés
        for finding in getattr(state, 'memory_safety_findings', []):
            title = finding.title.lower()
            if "buffer" in title or "overflow" in title:
                called.append("buffer_overflow")
            if "use after free" in title or "use-after-free" in title:
                called.append("use_after_free")
            if "double free" in title:
                called.append("double_free")
            if "leak" in title:
                called.append("memory_leak")
            if "null" in title:
                called.append("null_dereference")
        return list(set(called))  # Éliminer les doublons
