"""Semantic Analyst Agent: LLM + RAG for logic flaws and context-aware vulnerabilities."""

from __future__ import annotations

import json
import logging
import uuid
import re

from agents.base import BaseAgent
from graph.state import AgentState, Severity, Vulnerability
from llm.client import LLMClient
from memory.persistent import PersistentMemory

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are an expert security code reviewer. Analyze the provided code for:
- Logic vulnerabilities (auth bypass, IDOR, business logic flaws)
- Injection flaws (SQL, command, LDAP, XPath, template injection)
- Cryptographic weaknesses (weak algorithms, hardcoded keys, improper IV)
- Insecure deserialization
- Race conditions and TOCTOU vulnerabilities
- Information disclosure

For each finding, respond with a JSON array of objects with keys:
title, severity (critical/high/medium/low), cwe_id, description, line_start, line_end, code_snippet.

Example response format:
[
  {
    "title": "SQL Injection vulnerability",
    "severity": "high",
    "cwe_id": "CWE-89",
    "description": "User input is concatenated directly into SQL query",
    "line_start": 15,
    "line_end": 15,
    "code_snippet": "query = \"SELECT * FROM users WHERE id = \" + user_input"
  }
]

Return ONLY valid JSON, no other text."""


class SemanticAnalystAgent(BaseAgent):
    name = "semantic_analyst"

    def __init__(self) -> None:
        self._llm = LLMClient()
        self._memory = PersistentMemory()

    def _execute(self, state: AgentState) -> AgentState:
        findings: list[Vulnerability] = []

        # Prioritize files flagged by static scanners for deeper analysis
        flagged_paths = {f.get("file") for f in state.raw_findings}
        priority_targets = [t for t in state.targets if t.path in flagged_paths]
        # Also include all targets if no static findings yet
        if not priority_targets:
            priority_targets = state.targets[:20]  # cap at 20 to control cost

        similar_patterns = self._memory.retrieve_similar_patterns(
            [t.content or "" for t in priority_targets[:3]]
        )

        for target in priority_targets:
            if not target.content:
                continue

            context = _build_context(target.content, similar_patterns)
            raw = self._llm.query(
                system=SYSTEM_PROMPT,
                user=f"File: {target.path}\n\n```\n{context}\n```",
                model="strong"
            )

            # 🔧 CORRECTION: Nettoyer la réponse JSON
            raw = self._clean_json_response(raw)
            
            try:
                items = json.loads(raw)
                if not isinstance(items, list):
                    # Si c'est un objet avec une clé 'findings'
                    if isinstance(items, dict) and 'findings' in items:
                        items = items.get('findings', [])
                    else:
                        items = []
            except json.JSONDecodeError as e:
                logger.warning("[semantic] failed to parse LLM response for %s: %s", target.path, e)
                logger.debug(f"[semantic] Raw response (first 200 chars): {raw[:200]}")
                continue

            for item in items:
                if not isinstance(item, dict):
                    continue
                findings.append(
                    Vulnerability(
                        id=str(uuid.uuid4()),
                        title=item.get("title", "Unknown"),
                        severity=Severity(item.get("severity", "medium")),
                        cwe_id=item.get("cwe_id", "CWE-Unknown"),
                        cve_id=None,
                        file_path=target.path,
                        line_start=item.get("line_start", 0),
                        line_end=item.get("line_end", 0),
                        code_snippet=item.get("code_snippet", ""),
                        description=item.get("description", ""),
                    )
                )

        state.semantic_findings = findings
        logger.info("[semantic] found %d semantic vulnerabilities", len(findings))
        return state

    def _clean_json_response(self, raw: str) -> str:
        """Nettoie la réponse LLM pour extraire le JSON valide."""
        raw = raw.strip()
        
        # Enlever les balises markdown
        if raw.startswith('```json'):
            raw = raw[7:]
        elif raw.startswith('```'):
            raw = raw[3:]
        if raw.endswith('```'):
            raw = raw[:-3]
        
        raw = raw.strip()
        
        # Si la réponse ne commence pas par [ ou {, essayer de trouver un JSON
        if not raw.startswith(('[', '{')):
            # Chercher un pattern JSON
            json_pattern = r'(\[.*\]|\{.*\})'
            match = re.search(json_pattern, raw, re.DOTALL)
            if match:
                raw = match.group(1)
        
        return raw

    # ============================================
    # Méthodes pour la traçabilité
    # ============================================

    def _get_available_methods(self) -> list[str]:
        return ["logic_analysis", "auth_bypass"]
    
    def _get_called_methods(self, state: AgentState) -> list[str]:
        called = []
        findings = getattr(state, 'semantic_findings', [])
        for finding in findings:
            title = finding.title.lower()
            if "auth" in title or "bypass" in title or "privilege" in title:
                called.append("auth_bypass")
            else:
                called.append("logic_analysis")
        return list(set(called))


def _build_context(content: str, similar_patterns: list[str]) -> str:
    """Prepend retrieved vulnerability patterns as context for the LLM."""
    if not similar_patterns:
        return content
    pattern_block = "\n".join(f"# Known pattern: {p}" for p in similar_patterns[:3])
    return f"{pattern_block}\n\n{content}"