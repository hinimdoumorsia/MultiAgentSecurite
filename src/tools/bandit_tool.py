"""Bandit wrapper — Python-specific security linter."""

from __future__ import annotations

import json
import logging
import subprocess

logger = logging.getLogger(__name__)

SEVERITY_MAP = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


class BanditTool:
    def run(self, repo_root: str) -> list[dict]:
        try:
            result = subprocess.run(
                ["bandit", "-r", repo_root, "-f", "json", "-q"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
            )
            data = json.loads(result.stdout)
            return self._normalize(data.get("results", []))
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as exc:
            logger.warning("[bandit] error: %s", exc)
            return []

    def _normalize(self, results: list[dict]) -> list[dict]:
        findings = []
        for r in results:
            findings.append({
                "tool": "bandit",
                "rule_id": r.get("test_id", ""),
                "file": r.get("filename", ""),
                "line": r.get("line_number", 0),
                "message": r.get("issue_text", ""),
                "severity": SEVERITY_MAP.get(r.get("issue_severity", ""), "low"),
                "cwe": r.get("issue_cwe", {}).get("id", "CWE-Unknown"),
                "snippet": r.get("code", ""),
            })
        return findings
