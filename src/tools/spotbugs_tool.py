"""SpotBugs wrapper — Java security scanner."""

from __future__ import annotations

import logging
import subprocess
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)


class SpotBugsTool:
    def run(self, repo_root: str) -> list[dict]:
        try:
            result = subprocess.run(
                ["spotbugs", "-xml", "-output", "/tmp/spotbugs-out.xml", repo_root],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=180,
            )
            return self._parse_xml("/tmp/spotbugs-out.xml")
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            logger.warning("[spotbugs] error: %s", exc)
            return []

    def _parse_xml(self, path: str) -> list[dict]:
        findings = []
        try:
            tree = ET.parse(path)
            for bug in tree.getroot().findall(".//BugInstance"):
                source = bug.find("SourceLine")
                findings.append({
                    "tool": "spotbugs",
                    "rule_id": bug.get("type", ""),
                    "file": source.get("sourcepath", "") if source is not None else "",
                    "line": int(source.get("start", 0)) if source is not None else 0,
                    "message": (bug.find("LongMessage") or bug.find("ShortMessage") or ET.Element("x")).text or "",
                    "severity": _map_priority(bug.get("priority", "2")),
                    "cwe": "CWE-Unknown",
                    "snippet": "",
                })
        except Exception as exc:  # noqa: BLE001
            logger.warning("[spotbugs] parse error: %s", exc)
        return findings


def _map_priority(priority: str) -> str:
    return {"1": "high", "2": "medium", "3": "low"}.get(priority, "low")
