"""Validator Agent: applies patches and re-scans to confirm fixes don't regress."""

from __future__ import annotations

import logging
import subprocess
import tempfile
from pathlib import Path

from agents.base import BaseAgent
from graph.state import AgentState, Vulnerability
from memory.persistent import PersistentMemory
from tools.semgrep_tool import SemgrepTool

logger = logging.getLogger(__name__)


class ValidatorAgent(BaseAgent):
    name = "validator"

    def __init__(self) -> None:
        self._semgrep = SemgrepTool()
        self._memory = PersistentMemory()

    def _execute(self, state: AgentState) -> AgentState:
        validated: list[Vulnerability] = []
        rejected: list[Vulnerability] = []

        for vuln in state.patches_pending:
            if vuln.patch_diff is None:
                rejected.append(vuln)
                continue

            ok, regression_findings = self._apply_and_verify(
                state.repo_root, vuln, state.detected_languages
            )
            if ok and not regression_findings:
                vuln.patch_applied = True
                validated.append(vuln)
                # Store successful patch in persistent memory for future retrieval
                self._memory.store_patch(vuln.cwe_id, vuln.patch_diff)
                logger.info("[validator] patch accepted for %s (%s)", vuln.id, vuln.title)
            else:
                rejected.append(vuln)
                if regression_findings:
                    logger.warning(
                        "[validator] patch for %s introduced %d regression(s)",
                        vuln.id, len(regression_findings),
                    )

        state.patches_validated = validated
        state.patches_rejected = rejected
        state.patches_pending = []
        return state

    def _apply_and_verify(
        self,
        repo_root: str,
        vuln: Vulnerability,
        detected_languages,
    ) -> tuple[bool, list[dict]]:
        """Apply patch in a temp copy and re-run semgrep to detect regressions."""
        full_path = Path(repo_root) / vuln.file_path
        if not full_path.exists():
            return False, []

        original = full_path.read_text(errors="replace")
        patched = self._apply_diff(original, vuln.patch_diff)
        if patched is None:
            return False, []

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_file = Path(tmpdir) / full_path.name
            tmp_file.write_text(patched)
            new_findings = self._semgrep.run(tmpdir, detected_languages)

        # Check original vuln is gone
        still_present = any(
            f.get("line") in range(vuln.line_start, vuln.line_end + 1)
            for f in new_findings
        )
        if still_present:
            return False, new_findings

        return True, new_findings

    def _apply_diff(self, original: str, diff: str) -> str | None:
        """Apply a unified diff string to original content via `patch`."""
        try:
            result = subprocess.run(
                ["patch", "-p1", "--dry-run"],
                input=diff,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None
            # Apply for real
            with tempfile.NamedTemporaryFile(mode="w", suffix=".orig", delete=False) as f:
                f.write(original)
                orig_path = f.name
            subprocess.run(
                ["patch", orig_path],
                input=diff,
                capture_output=True,
                text=True,
                timeout=10,
            )
            return Path(orig_path).read_text()
        except Exception as exc:  # noqa: BLE001
            logger.warning("[validator] patch apply failed: %s", exc)
            # Fallback: return None to reject
            return None



# Ajouter ces méthodes à la fin de la classe ValidatorAgent

    def _get_available_methods(self) -> list[str]:
        return ["validate", "regression_test"]
    
    def _get_called_methods(self, state: AgentState) -> list[str]:
        called = []
        if state.patches_validated:
            called.append("validate")
        if getattr(state, 'patches_rejected', []):
            called.append("regression_test")
        return called