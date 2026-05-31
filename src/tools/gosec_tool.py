"""Gosec wrapper — Go security scanner."""

from __future__ import annotations

import json
import logging
import subprocess

logger = logging.getLogger(__name__)


class GosecTool:
    def run(self, repo_root: str) -> list[dict]:
        try:
            result = subprocess.run(
                ["gosec", "-fmt=json", "-quiet", "./..."],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=repo_root,
                timeout=120,
            )
            data = json.loads(result.stdout)
            return self._normalize(data.get("Issues", []))
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as exc:
            logger.warning("[gosec] error: %s", exc)
            return []

    def _normalize(self, issues: list[dict]) -> list[dict]:
        findings = []
        for issue in issues:
            findings.append({
                "tool": "gosec",
                "rule_id": issue.get("rule_id", ""),
                "file": issue.get("file", ""),
                "line": int(issue.get("line", 0)),
                "message": issue.get("details", ""),
                "severity": issue.get("severity", "MEDIUM").lower(),
                "cwe": issue.get("cwe", {}).get("id", "CWE-Unknown"),
                "snippet": issue.get("code", ""),
            })
        return findings
