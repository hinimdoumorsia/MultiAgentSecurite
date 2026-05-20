"""
Agent d'Analyse Statique de Sécurité
=====================================
Bandit (Python) + Semgrep (multi-lang) + lookup CVE

SÉCURITÉ : 
- Les outils de scan s'exécutent en subprocess isolé (pas d'import du code)
- Timeout strict pour éviter les DoS via code malformé
- Sortie JSON seulement (pas d'évaluation du code)
"""

import asyncio
import json
import subprocess
import tempfile
import os
import time
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Sévérités CVSS mappées
SEVERITY_MAP = {
    "CRITICAL": 9.0,
    "HIGH": 7.0,
    "MEDIUM": 5.0,
    "LOW": 3.0,
    "INFO": 1.0
}


class SecurityAnalyzer:
    """Analyse statique multi-outil avec isolation subprocess."""

    def __init__(self, timeout: int = 60):
        self.timeout = timeout  # Timeout en secondes par outil

    async def analyze(self, code_index: dict, language: str) -> list[dict]:
        """Lance l'analyse et retourne une liste unifiée de findings."""
        findings = []
        files = code_index.get("files", {})

        if not files:
            return []

        # Écriture temporaire des fichiers pour les outils
        with tempfile.TemporaryDirectory(prefix="securecodeagent_") as tmpdir:
            # Écriture sécurisée des fichiers
            written_files = self._write_files_safely(files, tmpdir)

            if not written_files:
                return []

            # Analyse selon le langage
            tasks = []
            if language == "python":
                tasks.append(self._run_bandit(tmpdir))
            tasks.append(self._run_semgrep(tmpdir, language))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Erreur outil d'analyse: {result}")
                    continue
                findings.extend(result)

        # Normalisation et déduplication
        return self._normalize_and_deduplicate(findings)

    def _write_files_safely(self, files: dict, tmpdir: str) -> list[str]:
        """
        Écrit les fichiers dans un répertoire temporaire.
        SÉCURITÉ: Validation du chemin pour éviter le path traversal.
        """
        written = []
        for filepath, file_data in files.items():
            # Anti path traversal
            safe_name = Path(filepath).name  # Prend seulement le nom de fichier
            if not safe_name or safe_name.startswith("."):
                continue

            dest = Path(tmpdir) / safe_name
            try:
                content = file_data.get("content", "")
                dest.write_text(content, encoding="utf-8")
                written.append(str(dest))
            except (OSError, UnicodeEncodeError) as e:
                logger.warning(f"Impossible d'écrire {filepath}: {e}")

        return written

    async def _run_bandit(self, directory: str) -> list[dict]:
        """
        Lance Bandit sur le répertoire.
        SÉCURITÉ: subprocess avec shell=False, timeout strict.
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                "bandit", "-r", directory, "-f", "json", "-q",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            except asyncio.TimeoutError:
                proc.kill()
                logger.warning("Bandit timeout — analyse interrompue")
                return []

            if not stdout:
                return []

            data = json.loads(stdout.decode("utf-8", errors="ignore"))
            return self._normalize_bandit(data)

        except FileNotFoundError:
            logger.info("Bandit non installé, analyse Python statique ignorée")
            return []
        except json.JSONDecodeError:
            logger.warning("Bandit: sortie JSON invalide")
            return []

    def _normalize_bandit(self, data: dict) -> list[dict]:
        """Normalise les résultats Bandit au format unifié."""
        findings = []
        for issue in data.get("results", []):
            findings.append({
                "tool": "bandit",
                "file": os.path.basename(issue.get("filename", "")),
                "line_start": issue.get("line_number", 0),
                "line_end": issue.get("line_number", 0),
                "severity": issue.get("issue_severity", "MEDIUM").upper(),
                "confidence": issue.get("issue_confidence", "MEDIUM").upper(),
                "cwe": issue.get("issue_cwe", {}).get("id", ""),
                "title": issue.get("test_name", ""),
                "description": issue.get("issue_text", ""),
                "snippet": issue.get("code", ""),
                "cvss_score": SEVERITY_MAP.get(issue.get("issue_severity", "MEDIUM").upper(), 5.0)
            })
        return findings

    async def _run_semgrep(self, directory: str, language: str) -> list[dict]:
        """
        Lance Semgrep avec les règles de sécurité.
        Utilise le registry public Semgrep pour les patterns OWASP.
        """
        lang_rules = {
            "python": "p/python",
            "javascript": "p/javascript",
            "typescript": "p/typescript",
            "java": "p/java",
            "go": "p/golang",
            "php": "p/php",
            "ruby": "p/ruby",
        }
        ruleset = lang_rules.get(language, "p/default")

        try:
            proc = await asyncio.create_subprocess_exec(
                "semgrep", "--config", ruleset,
                "--json", "--quiet",
                "--no-git-ignore",
                directory,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "SEMGREP_SEND_METRICS": "off"}
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            except asyncio.TimeoutError:
                proc.kill()
                logger.warning("Semgrep timeout")
                return []

            if not stdout:
                return []

            data = json.loads(stdout.decode("utf-8", errors="ignore"))
            return self._normalize_semgrep(data)

        except FileNotFoundError:
            logger.info("Semgrep non installé")
            return []
        except json.JSONDecodeError:
            return []

    def _normalize_semgrep(self, data: dict) -> list[dict]:
        """Normalise les résultats Semgrep."""
        findings = []
        for result in data.get("results", []):
            meta = result.get("extra", {}).get("metadata", {})
            severity_raw = result.get("extra", {}).get("severity", "WARNING")
            severity_map_sg = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
            severity = severity_map_sg.get(severity_raw, "MEDIUM")

            findings.append({
                "tool": "semgrep",
                "file": os.path.basename(result.get("path", "")),
                "line_start": result.get("start", {}).get("line", 0),
                "line_end": result.get("end", {}).get("line", 0),
                "severity": severity,
                "confidence": "HIGH",
                "cwe": str(meta.get("cwe", [""])[0]) if meta.get("cwe") else "",
                "title": result.get("check_id", "").split(".")[-1],
                "description": result.get("extra", {}).get("message", ""),
                "snippet": result.get("extra", {}).get("lines", ""),
                "cvss_score": SEVERITY_MAP.get(severity, 5.0),
                "owasp": meta.get("owasp", [])
            })
        return findings

    def _normalize_and_deduplicate(self, findings: list[dict]) -> list[dict]:
        """
        Déduplique les findings par (file, line_start, title).
        En cas de doublon, garde celui avec le score CVSS le plus élevé.
        """
        seen: dict[tuple, dict] = {}
        for finding in findings:
            key = (
                finding.get("file", ""),
                finding.get("line_start", 0),
                finding.get("title", "")[:30]
            )
            existing = seen.get(key)
            if not existing or finding.get("cvss_score", 0) > existing.get("cvss_score", 0):
                seen[key] = finding

        # Tri par score CVSS décroissant
        return sorted(seen.values(), key=lambda x: x.get("cvss_score", 0), reverse=True)
