"""Triage Agent: detects languages, classifies targets, routes the workflow."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from agents.base import BaseAgent
from graph.state import AgentState, Language, ScanTarget
from graph.router import MEMORY_UNSAFE_LANGUAGES

EXTENSION_MAP: dict[str, Language] = {
    ".c": Language.C,
    ".h": Language.C,
    ".cpp": Language.CPP,
    ".cc": Language.CPP,
    ".cxx": Language.CPP,
    ".hpp": Language.CPP,
    ".py": Language.PYTHON,
    ".js": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT,
    ".ts": Language.TYPESCRIPT,
    ".tsx": Language.TYPESCRIPT,
    ".rs": Language.RUST,
    ".java": Language.JAVA,
    ".go": Language.GO,
    ".php": Language.PHP,
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "target", "build", "dist", ".mypy_cache",
}


class TriageAgent(BaseAgent):
    name = "triage"

    def _execute(self, state: AgentState) -> AgentState:
        root = Path(state.repo_root)
        targets: list[ScanTarget] = []

        for filepath in root.rglob("*"):
            if any(part in SKIP_DIRS for part in filepath.parts):
                continue
            if not filepath.is_file():
                continue

            lang = EXTENSION_MAP.get(filepath.suffix.lower())
            if lang is None:
                continue

            content = filepath.read_text(errors="replace")
            file_hash = hashlib.sha256(content.encode()).hexdigest()
            targets.append(
                ScanTarget(
                    path=str(filepath.relative_to(root)),
                    language=lang,
                    content=content,
                    file_hash=file_hash,
                )
            )
            state.detected_languages.add(lang)

        state.targets = targets
        state.needs_memory_safety = bool(
            state.detected_languages & MEMORY_UNSAFE_LANGUAGES
        )
        return state
    

# Ajouter ces méthodes à la fin de la classe TriageAgent

    def _get_available_methods(self) -> list[str]:
        return ["detect_languages", "classify_targets"]
    
    def _get_called_methods(self, state: AgentState) -> list[str]:
        called = []
        if state.detected_languages:
            called.append("detect_languages")
        if state.targets:
            called.append("classify_targets")
        return called
