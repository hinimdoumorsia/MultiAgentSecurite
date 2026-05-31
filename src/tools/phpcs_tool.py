"""PHPCS Security Audit wrapper — PHP security scanner."""

from __future__ import annotations

import json
import logging
import subprocess

logger = logging.getLogger(__name__)


class PhpCsTool:
    def run(self, repo_root: str) -> list[dict]:
        try:
            result = subprocess.run(
                [
                    "phpcs",
                    "--standard=Security",
                    "--report=json",
                    repo_root,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
            )
            data = json.loads(result.stdout)
            return self._normalize(data.get("files", {}))
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as exc:
            logger.warning("[phpcs] error: %s", exc)
            return []

    def _normalize(self, files: dict) -> list[dict]:
        findings = []
        for filepath, info in files.items():
            for msg in info.get("messages", []):
                findings.append({
                    "tool": "phpcs",
                    "rule_id": msg.get("source", ""),
                    "file": filepath,
                    "line": msg.get("line", 0),
                    "message": msg.get("message", ""),
                    "severity": "high" if msg.get("type") == "ERROR" else "medium",
                    "cwe": "CWE-Unknown",
                    "snippet": "",
                })
        return findings
