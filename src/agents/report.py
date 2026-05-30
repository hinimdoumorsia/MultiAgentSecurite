"""Report Agent: generates structured JSON + Markdown security report."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

from agents.base import BaseAgent
from graph.state import AgentState, Severity, Vulnerability

logger = logging.getLogger(__name__)

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


class ReportAgent(BaseAgent):
    name = "report"

    def _execute(self, state: AgentState) -> AgentState:
        all_vulns: list[Vulnerability] = (
            state.vulnerabilities
            + state.memory_safety_findings
            + state.semantic_findings
        )
        # Deduplicate by id
        seen: set[str] = set()
        unique_vulns: list[Vulnerability] = []
        for v in all_vulns:
            if v.id not in seen:
                seen.add(v.id)
                unique_vulns.append(v)

        unique_vulns.sort(key=lambda v: (SEVERITY_ORDER.index(v.severity), -v.cvss_score))

        stats = _compute_stats(unique_vulns)
        state.report = {
            "scan_id": state.scan_id,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "repo": state.repo_root,
            "languages": [lang.value for lang in state.detected_languages],
            "statistics": stats,
            "vulnerabilities": [_vuln_to_dict(v) for v in unique_vulns],
            "patches": {
                "applied": len(state.patches_validated),
                "rejected": len(state.patches_rejected),
            },
            "errors": state.errors,
        }

        logger.info(
            "[report] %d total findings | critical=%d high=%d medium=%d low=%d",
            stats["total"],
            stats["by_severity"].get("critical", 0),
            stats["by_severity"].get("high", 0),
            stats["by_severity"].get("medium", 0),
            stats["by_severity"].get("low", 0),
        )
        return state


def _compute_stats(vulns: list[Vulnerability]) -> dict:
    by_severity: dict[str, int] = {}
    by_cwe: dict[str, int] = {}
    exploitable = 0

    for v in vulns:
        by_severity[v.severity.value] = by_severity.get(v.severity.value, 0) + 1
        by_cwe[v.cwe_id] = by_cwe.get(v.cwe_id, 0) + 1
        if v.is_exploitable:
            exploitable += 1

    return {
        "total": len(vulns),
        "exploitable": exploitable,
        "by_severity": by_severity,
        "top_cwes": sorted(by_cwe.items(), key=lambda x: -x[1])[:5],
    }


def _vuln_to_dict(v: Vulnerability) -> dict:
    return {
        "id": v.id,
        "title": v.title,
        "severity": v.severity.value,
        "cwe_id": v.cwe_id,
        "cve_id": v.cve_id,
        "file": v.file_path,
        "lines": [v.line_start, v.line_end],
        "cvss_score": round(v.cvss_score, 1),
        "exploitable": v.is_exploitable,
        "memory_safety": v.memory_safety_issue,
        "description": v.description,
        "patch_applied": v.patch_applied,
        "patch_diff": v.patch_diff,
        "attack_vector": v.extra.get("attack_vector", ""),
    }




# Ajouter ces méthodes à la fin de la classe ReportAgent

    def _get_available_methods(self) -> list[str]:
        return ["json", "markdown"]
    
    def _get_called_methods(self, state: AgentState) -> list[str]:
        called = []
        if hasattr(state, 'report') and state.report:
            called.append("json")
            # Si on ajoute le support Markdown plus tard
            if state.report.get("format") == "markdown":
                called.append("markdown")
        return called