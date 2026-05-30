"""Enhanced scanner with caching, parallel execution, and AI enrichment."""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from datetime import datetime

from agents.base import BaseAgent
from graph.state import AgentState, Vulnerability, Severity, Language
from tools.semgrep_tool import SemgrepTool
from tools.bandit_tool import BanditTool
from tools.gosec_tool import GosecTool
from tools.spotbugs_tool import SpotBugsTool
from tools.phpcs_tool import PhpCsTool

logger = logging.getLogger(__name__)


class EnhancedScanner:
    """Scanner with caching, parallel execution, and AI enhancement."""

    def __init__(self, cache_dir: str = ".scan_cache", force_refresh: bool = False):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.force_refresh = (
            force_refresh
            or os.environ.get("SCAN_FORCE_REFRESH", "false").lower() == "true"
        )

        self._semgrep = SemgrepTool()
        self._bandit = BanditTool()
        self._gosec = GosecTool()
        self._spotbugs = SpotBugsTool()
        self._phpcs = PhpCsTool()

    def _get_semgrep_version(self) -> str:
        """Get Semgrep version for cache invalidation."""
        try:
            # FIX: encoding='utf-8' + errors='replace' évite UnicodeDecodeError sur Windows
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
            )
            return result.stdout.strip()[:20] if result.returncode == 0 else "unknown"
        except Exception:
            return "unknown"

    def _get_rules_hash(self) -> str:
        """Get hash of custom rules for cache invalidation."""
        rules_path = Path(__file__).parent.parent / "rules" / "custom.yml"
        if rules_path.exists():
            try:
                with open(rules_path, "rb") as f:
                    return hashlib.md5(f.read()).hexdigest()[:10]
            except Exception:
                pass
        return "no_custom_rules"

    def _get_file_hash(self, repo_path: str) -> str:
        """Generate hash of repository for caching."""
        hash_md5 = hashlib.md5()
        repo = Path(repo_path)
        for file_path in sorted(repo.rglob("*")):
            if file_path.is_file() and file_path.suffix in [
                ".py", ".js", ".java", ".go", ".php", ".c", ".cpp",
            ]:
                try:
                    hash_md5.update(file_path.read_bytes()[:10000])
                except Exception:
                    pass
        return hash_md5.hexdigest()

    def _get_cached_results(self, repo_hash: str) -> list[dict] | None:
        """Get cached scan results with invalidation checks."""
        if self.force_refresh:
            logger.info("Force refresh enabled, ignoring cache")
            return None

        cache_file = self.cache_dir / f"{repo_hash}.json"
        if cache_file.exists():
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                current_rules_hash = self._get_rules_hash()
                cached_rules_hash = data.get("rules_hash", "")
                if current_rules_hash != cached_rules_hash:
                    logger.info(
                        f"Rules updated ({cached_rules_hash} -> {current_rules_hash}), cache invalidated"
                    )
                    return None

                current_semgrep = self._get_semgrep_version()
                cached_semgrep = data.get("semgrep_version", "")
                if current_semgrep != cached_semgrep:
                    logger.info(
                        f"Semgrep version changed ({cached_semgrep} -> {current_semgrep}), cache invalidated"
                    )
                    return None

                if datetime.now().timestamp() - data.get("timestamp", 0) < 3600:
                    logger.info(f"Using cached results for {repo_hash[:8]}")
                    return data.get("findings", [])
                else:
                    logger.info(f"Cache expired for {repo_hash[:8]}")

            except Exception as e:
                logger.warning(f"Cache read error: {e}")
        return None

    def _cache_results(self, repo_hash: str, findings: list[dict]) -> None:
        """Cache scan results with metadata."""
        cache_file = self.cache_dir / f"{repo_hash}.json"
        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "timestamp": datetime.now().timestamp(),
                        "semgrep_version": self._get_semgrep_version(),
                        "rules_hash": self._get_rules_hash(),
                        "findings": findings,
                    },
                    f,
                )
            logger.info(f"Cached results for {repo_hash[:8]}")
        except Exception as e:
            logger.warning(f"Failed to cache results: {e}")

    def run_parallel(self, repo_path: str, languages: set, force: bool = False) -> list[dict]:
        """Run multiple scanners in parallel."""
        findings = []

        repo_hash = self._get_file_hash(repo_path)
        if not force and not self.force_refresh:
            cached = self._get_cached_results(repo_hash)
            if cached is not None:
                return cached
        else:
            logger.info("Force refresh: ignoring cache")

        tasks = []

        if languages & {
            Language.C, Language.CPP, Language.PYTHON,
            Language.JAVASCRIPT, Language.TYPESCRIPT,
            Language.JAVA, Language.GO, Language.RUST,
        }:
            tasks.append(("semgrep", lambda: self._semgrep.run(repo_path, languages)))

        if Language.PYTHON in languages:
            tasks.append(("bandit", lambda: self._bandit.run(repo_path)))

        if Language.GO in languages:
            tasks.append(("gosec", lambda: self._gosec.run(repo_path)))

        if Language.JAVA in languages:
            tasks.append(("spotbugs", lambda: self._spotbugs.run(repo_path)))

        if Language.PHP in languages:
            tasks.append(("phpcs", lambda: self._phpcs.run(repo_path)))

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(task_func): name for name, task_func in tasks}
            for future in as_completed(futures):
                tool_name = futures[future]
                try:
                    result = future.result()
                    # FIX: s'assurer que result est bien une liste
                    if isinstance(result, list):
                        findings.extend(result)
                        logger.info(f"Scanner {tool_name} found {len(result)} issues")
                    else:
                        logger.warning(
                            f"Scanner {tool_name} returned unexpected type {type(result)}, skipping"
                        )
                except Exception as e:
                    logger.error(f"Scanner {tool_name} failed: {e}")

        self._cache_results(repo_hash, findings)
        return findings


# ---------------------------------------------------------------------------
# Helpers de normalisation
# ---------------------------------------------------------------------------

_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def _normalize_cwe(raw: Any) -> str:
    """Convertit n'importe quel type CWE en string 'CWE-XXX'."""
    if raw is None:
        return "CWE-Unknown"
    # FIX: si c'est un int, le convertir directement
    if isinstance(raw, int):
        return f"CWE-{raw}"
    s = str(raw).strip()
    if s.isdigit():
        return f"CWE-{s}"
    if not s.startswith("CWE-"):
        return f"CWE-{s}"
    return s


def _normalize_severity(raw: Any) -> str:
    """Convertit n'importe quel type sévérité en string valide.
    
    FIX principal : si raw est un int ou un type non-itérable,
    l'opérateur 'in' plantait avec 'argument of type int is not iterable'.
    On convertit systématiquement en str avant le test.
    """
    if raw is None:
        return "medium"
    # Convertir en str pour éviter 'int is not iterable'
    value = str(raw).lower().strip()
    return value if value in _VALID_SEVERITIES else "medium"


# ---------------------------------------------------------------------------
# Agent principal
# ---------------------------------------------------------------------------

class ScannerAgent(BaseAgent):
    """Wrapper for EnhancedScanner to work with the workflow."""

    name = "scanner"

    def __init__(self, cache_dir: str = ".scan_cache", force_refresh: bool = False):
        self._scanner = EnhancedScanner(cache_dir, force_refresh)

    def _extract_code_snippet(self, file_path: str, line_start: int, line_end: int) -> str:
        """Extract code snippet from file."""
        try:
            path = Path(file_path)
            if not path.exists():
                return "Code snippet not available"

            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            start = max(0, line_start - 3) if line_start > 0 else 0
            end = min(len(lines), line_end + 3) if line_end > 0 else len(lines)

            snippet_lines = []
            for i in range(start, end):
                prefix = "→ " if start + 1 <= line_start <= i + 1 else "  "
                snippet_lines.append(f"{prefix}{i+1}: {lines[i]}")

            return "\n".join(snippet_lines)
        except Exception as e:
            logger.warning(f"Failed to extract code snippet from {file_path}: {e}")
            return "Code snippet extraction failed"

    def _execute(self, state: AgentState) -> AgentState:
        """Execute scan and update state."""
        repo_path = state.repo_root
        languages = state.detected_languages

        logger.info(f"[scanner] Starting scan on {repo_path} with languages {languages}")

        try:
            findings = self._scanner.run_parallel(repo_path, languages)
        except Exception as e:
            logger.error(f"[scanner] run_parallel failed: {e}")
            findings = []

        vulnerabilities = []
        for f in findings:
            # FIX: normalisation robuste CWE et sévérité
            cwe_value = _normalize_cwe(f.get("cwe"))
            severity_value = _normalize_severity(f.get("severity"))

            # Extraire le snippet de code si disponible
            code_snippet = f.get("code_snippet", "")
            if not code_snippet and f.get("file") and f.get("line_start"):
                code_snippet = self._extract_code_snippet(
                    f.get("file", ""),
                    f.get("line_start", 0),
                    f.get("line_end", 0),
                )

            # FIX: s'assurer que cvss_score est un float valide
            try:
                cvss_score = float(f.get("cvss_score", 0.0))
            except (TypeError, ValueError):
                cvss_score = 0.0

            vuln = Vulnerability(
                id=f.get("id", str(uuid.uuid4())),
                title=f.get("title", "Unknown Vulnerability"),
                severity=Severity(severity_value),
                cwe_id=cwe_value,
                cve_id=f.get("cve"),
                file_path=f.get("file", ""),
                line_start=f.get("line_start", 0),
                line_end=f.get("line_end", 0),
                code_snippet=code_snippet,
                description=f.get("description", ""),
                cvss_score=cvss_score,
                is_exploitable=bool(f.get("is_exploitable", False)),
            )

            vuln.extra.update(
                {
                    "suggested_fix": f.get("suggested_fix", ""),
                    "confidence": f.get("confidence", "medium"),
                    "impact": f.get("impact", "medium"),
                    "scanner_type": f.get("tool", "static"),
                    "rule_id": f.get("rule_id", ""),
                }
            )

            vulnerabilities.append(vuln)

        state.vulnerabilities = vulnerabilities
        state.raw_findings = findings

        logger.info(f"[scanner] Found {len(vulnerabilities)} vulnerabilities")

        severity_counts = {
            "critical": sum(1 for v in vulnerabilities if v.severity == Severity.CRITICAL),
            "high":     sum(1 for v in vulnerabilities if v.severity == Severity.HIGH),
            "medium":   sum(1 for v in vulnerabilities if v.severity == Severity.MEDIUM),
            "low":      sum(1 for v in vulnerabilities if v.severity == Severity.LOW),
        }
        logger.info(f"[scanner] Severity breakdown: {severity_counts}")

        return state
    

# Ajouter ces méthodes à la fin de la classe ScannerAgent

    def _get_available_methods(self) -> list[str]:
        """Retourne les outils disponibles pour cet agent."""
        tools = ["semgrep"]
        if hasattr(self._scanner, '_bandit'):
            tools.append("bandit")
        if hasattr(self._scanner, '_gosec'):
            tools.append("gosec")
        if hasattr(self._scanner, '_spotbugs'):
            tools.append("spotbugs")
        if hasattr(self._scanner, '_phpcs'):
            tools.append("phpcs")
        return tools
    
    def _get_called_methods(self, state: AgentState) -> list[str]:
        """Retourne quels outils ont été exécutés."""
        called = []
        # Vérifier quels types de fichiers ont été scannés
        for vuln in state.vulnerabilities:
            if vuln.file_path.endswith(('.py')):
                called.append("bandit")
            if vuln.file_path.endswith(('.go')):
                called.append("gosec")
            if vuln.file_path.endswith(('.java')):
                called.append("spotbugs")
            if vuln.file_path.endswith(('.php')):
                called.append("phpcs")
        # Semgrep est toujours appelé
        if state.vulnerabilities:
            called.append("semgrep")
        return list(set(called))