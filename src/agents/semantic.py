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

# Limite de caracteres envoyes au LLM par fichier. Le 8B (llama-3.1-8b-instant)
# plafonne a 6000 tokens/MINUTE sur free-tier ; on garde la requete bien en dessous.
# ~8000 caracteres ~= 2600 tokens (+ prompt ~300 + max_tokens 1024 ~= 4000 < 6000).
MAX_FILE_CHARS = 8000

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

            file_content = target.content[:MAX_FILE_CHARS]
            if len(target.content) > MAX_FILE_CHARS:
                logger.debug("[semantic] %s tronque a %d/%d caracteres",
                             target.path, MAX_FILE_CHARS, len(target.content))
            context = _build_context(file_content, similar_patterns)
            # model="fast" (llama-3.1-8b-instant) : limite tokens/jour ~5x plus
            # haute que le 70B sur free-tier -> beaucoup plus de cas/jour pour le
            # benchmark. Compromis qualite a documenter dans le memoire.
            # max_tokens reduit : un tableau JSON de findings tient largement.
            raw = self._llm.query(
                system=SYSTEM_PROMPT,
                user=f"File: {target.path}\n\n```\n{context}\n```",
                model="fast",
                max_tokens=1024,
            )

            # Parsing robuste (le 8B renvoie souvent du JSON mal formé).
            items = self._parse_findings(raw, target.path)

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

    @staticmethod
    def _repair_json(s: str) -> str:
        """Répare les erreurs fréquentes du 8B : échappements invalides, virgule finale."""
        if not s:
            return s
        # Backslash non suivi d'un caractère d'échappement JSON valide -> on l'échappe.
        s = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', s)
        # Virgule finale avant } ou ]
        s = re.sub(r",\s*([}\]])", r"\1", s)
        return s

    def _parse_findings(self, raw: str, path: str) -> list:
        """Parse robuste de la réponse LLM -> liste de findings.

        Gère le JSON mal formé du 8B : tente le parse direct, puis une réparation
        (échappements/virgules), puis en dernier recours extrait les objets {...}
        individuellement. Renvoie [] si rien n'est récupérable (au lieu de tout perdre).
        """
        cleaned = self._clean_json_response(raw)
        for candidate in (cleaned, self._repair_json(cleaned)):
            try:
                data = json.loads(candidate)
            except (json.JSONDecodeError, TypeError):
                continue
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return data.get("findings", []) if "findings" in data else [data]

        # Secours : récupérer les objets JSON isolés (findings plats, sans imbrication).
        objs = []
        for m in re.finditer(r"\{[^{}]*\}", cleaned, re.DOTALL):
            try:
                objs.append(json.loads(self._repair_json(m.group(0))))
            except json.JSONDecodeError:
                pass
        if not objs:
            logger.warning("[semantic] JSON irrécupérable pour %s (%d cars)", path, len(raw))
        return objs

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