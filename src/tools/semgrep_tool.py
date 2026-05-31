"""Semgrep wrapper — multi-language static analysis."""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

from graph.state import Language

logger = logging.getLogger(__name__)

# Règles par langage
LANG_RULESET: dict[Language, list[str]] = {
    Language.C:          ["p/c", "p/default"],
    Language.CPP:        ["p/cpp", "p/default"],
    Language.PYTHON:     ["p/python", "p/owasp-top-ten", "p/secrets"],
    Language.JAVASCRIPT: ["p/javascript", "p/nodejs", "p/owasp-top-ten"],
    Language.TYPESCRIPT: ["p/typescript", "p/nodejs", "p/owasp-top-ten"],
    Language.JAVA:       ["p/java", "p/owasp-top-ten"],
    Language.GO:         ["p/golang", "p/default"],
    Language.RUST:       ["p/rust"],
    Language.PHP:        ["p/php"],
}

# Règles communes à tous les langages
COMMON_RULESETS = [
    "p/default",
    "p/owasp-top-ten",
    "p/security-audit",
]

# Chemin vers les règles personnalisées
CUSTOM_RULES_PATH = Path(__file__).parent.parent / "rules" / "custom.yml"


class SemgrepTool:
    def run(self, repo_root: str, languages: set[Language]) -> list[dict]:
        """Exécute Semgrep sur le dépôt."""
        rulesets: set[str] = set()
        
        # Ajouter les règles communes
        for ruleset in COMMON_RULESETS:
            rulesets.add(ruleset)
        
        # Ajouter les règles spécifiques par langage
        for lang in languages:
            rulesets.update(LANG_RULESET.get(lang, []))
        
        # Ajouter les règles personnalisées si elles existent
        if CUSTOM_RULES_PATH.exists():
            rulesets.add(str(CUSTOM_RULES_PATH))
            logger.info(f"[semgrep] Using custom rules: {CUSTOM_RULES_PATH}")
        
        if not rulesets:
            logger.warning("[semgrep] No rulesets configured")
            return []
        
        # Construire la commande
        cmd = ["semgrep", "--json"]
        
        for ruleset in rulesets:
            cmd += ["--config", ruleset]
        
        cmd += ["--severity", "ERROR", "--severity", "WARNING"]
        cmd.append(repo_root)
        
        logger.info(f"[semgrep] Running with {len(rulesets)} rulesets on {repo_root}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                     encoding="utf-8", errors="replace", timeout=300)
            
            if result.returncode not in [0, 1]:
                logger.error(f"[semgrep] Error (code {result.returncode}): {result.stderr[:500]}")
                return []
            
            try:
                data = json.loads(result.stdout) if result.stdout else {"results": []}
            except json.JSONDecodeError as e:
                logger.error(f"[semgrep] JSON parse error: {e}")
                return []
            
            findings = self._normalize(data.get("results", []))
            logger.info(f"[semgrep] Found {len(findings)} vulnerabilities")
            
            return findings
            
        except subprocess.TimeoutExpired:
            logger.error(f"[semgrep] Timeout after 300s on {repo_root}")
            return []
        except FileNotFoundError:
            logger.error("[semgrep] Semgrep not found. Install: pip install semgrep")
            return []
        except Exception as e:
            logger.error(f"[semgrep] Unexpected error: {e}")
            return []
    
    def _normalize(self, results: list[dict]) -> list[dict]:
        """Normalise les résultats Semgrep."""
        findings = []
        
        for r in results:
            extra = r.get("extra", {})
            metadata = extra.get("metadata", {})
            
            # Extraire le CWE
            cwe = self._extract_cwe(r)
            
            # Extraire la sévérité
            severity = extra.get("severity", "WARNING").lower()
            severity_map = {
                "error": "high",
                "warning": "medium",
                "info": "low",
                "critical": "critical"
            }
            normalized_severity = severity_map.get(severity, "medium")
            
            # Extraire le message
            message = extra.get("message", "")
            message = message.replace("`", "").strip()
            
            # Extraire le snippet
            code_snippet = extra.get("lines", "")
            
            finding = {
                "tool": "semgrep",
                "rule_id": r.get("check_id", ""),
                "title": message[:80] if message else "Security Issue",
                "file": r.get("path", ""),
                "line_start": r.get("start", {}).get("line", 0),
                "line_end": r.get("end", {}).get("line", 0),
                "description": message,
                "severity": normalized_severity,
                "cwe": cwe,
                "cvss_score": self._get_default_cvss(cwe),
                "code_snippet": code_snippet,
                "suggested_fix": metadata.get("remediation", ""),
                "confidence": metadata.get("confidence", "medium"),
            }
            findings.append(finding)
        
        return findings
    
    def _extract_cwe(self, result: dict) -> str:
        """Extrait l'identifiant CWE."""
        metadata = result.get("extra", {}).get("metadata", {})
        cwe = metadata.get("cwe", [])
        
        if isinstance(cwe, list) and cwe:
            return cwe[0]
        if isinstance(cwe, str):
            return cwe
        return "CWE-Unknown"
    
    def _get_default_cvss(self, cwe: str) -> float:
        """Retourne un score CVSS par défaut."""
        scores = {
            "CWE-89": 8.5,
            "CWE-78": 9.0,
            "CWE-79": 6.5,
            "CWE-22": 7.5,
            "CWE-798": 9.0,
            "CWE-502": 8.0,
        }
        return scores.get(cwe, 5.0)