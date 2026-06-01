"""Patcher Agent: generates security patches using Llama-3.1-70B with context from RAG."""

from __future__ import annotations

import json
import logging

from agents.base import BaseAgent
from graph.state import AgentState, Vulnerability
from llm.client import LLMClient
from memory.persistent import PersistentMemory

logger = logging.getLogger(__name__)

# Approche FICHIER COMPLET : on demande le fichier corrigé entier (fiable), puis on
# calcule le diff nous-mêmes via difflib -> toujours applicable par `git apply`
# (contrairement aux diffs unifiés écrits par le LLM, qui échouent souvent).
SYSTEM_PROMPT = """\
You are a security engineer. Fix ONLY the described vulnerability in this file.
- Fix only the vulnerability, do not refactor unrelated code.
- Preserve the package, imports, coding style, indentation and all other behaviour.
- For C/C++ memory safety: prefer bounds-checked alternatives (strncpy, snprintf...).
- Do not introduce new vulnerabilities.
Return the COMPLETE corrected file content and NOTHING else (no markdown fences, no explanation)."""


class PatcherAgent(BaseAgent):
    name = "patcher"

    def __init__(self) -> None:
        self._llm = LLMClient()
        self._memory = PersistentMemory()

    def _execute(self, state: AgentState) -> AgentState:
        if not state.patches_pending:
            return state

        # On retry, only re-process rejected patches
        to_patch = state.patches_rejected if state.iteration > 0 else state.patches_pending
        state.patches_rejected = []
        state.iteration += 1

        for vuln in to_patch:
            file_content = self._read_file(state.repo_root, vuln.file_path)
            if file_content is None:
                continue

            similar_patches = self._memory.retrieve_patches(vuln.cwe_id)
            patch_diff = self._generate_patch(vuln, file_content, similar_patches)

            if patch_diff:
                vuln.patch_diff = patch_diff
                state.patches_pending = [v for v in state.patches_pending if v.id != vuln.id]
                # Move to validator queue (re-uses patches_pending with diff set)
                state.patches_pending.append(vuln)

        return state

    def _generate_patch(
        self,
        vuln: Vulnerability,
        file_content: str,
        similar_patches: list[str],
    ) -> str | None:
        context_block = ""
        if similar_patches:
            context_block = "Similar past patches for reference:\n" + "\n---\n".join(similar_patches[:2]) + "\n\n"

        prompt = (
            f"{context_block}"
            f"Vulnerability: {vuln.title}\n"
            f"CWE: {vuln.cwe_id}\n"
            f"File: {vuln.file_path} lines {vuln.line_start}-{vuln.line_end}\n"
            f"Description: {vuln.description}\n\n"
            f"Vulnerable file:\n```\n{file_content[:12000]}\n```"
        )

        raw = self._llm.query(system=SYSTEM_PROMPT, user=prompt, model="strong", max_tokens=8192)
        corrected = self._clean_fullfile(raw)
        if not corrected or corrected.strip() == file_content.strip():
            return None

        # Diff mécanique (toujours applicable par git apply).
        import difflib
        diff = "".join(difflib.unified_diff(
            file_content.splitlines(keepends=True),
            (corrected if corrected.endswith("\n") else corrected + "\n").splitlines(keepends=True),
            fromfile=f"a/{vuln.file_path}", tofile=f"b/{vuln.file_path}",
        ))
        vuln.extra["patched_content"] = corrected  # pour application par remplacement
        return diff or None

    @staticmethod
    def _clean_fullfile(raw: str) -> str:
        s = (raw or "").strip()
        if s.startswith("```"):
            s = s.split("\n", 1)[1] if "\n" in s else s
            if s.rstrip().endswith("```"):
                s = s.rstrip()[:-3]
        return s.strip("\n")

    def _read_file(self, repo_root: str, rel_path: str) -> str | None:
        from pathlib import Path
        full = Path(repo_root) / rel_path
        if full.exists():
            return full.read_text(errors="replace")
        return None




# Ajouter ces méthodes à la fin de la classe PatcherAgent

    def _get_available_methods(self) -> list[str]:
        return ["generate_patch", "apply_diff"]
    
    def _get_called_methods(self, state: AgentState) -> list[str]:
        called = []
        if hasattr(state, 'patches_pending') and state.patches_pending:
            for vuln in state.patches_pending:
                if vuln.patch_diff:
                    called.append("generate_patch")
                    called.append("apply_diff")
                    break
        return list(set(called))