"""Adapter du mini-dataset synthetique (validation bout-en-bout, sans API).

Structure attendue :
  datasets/synthetic/
    cases.json            -> liste de labels (voir schema GroundTruthLabel)
    <case_id>/            -> dossier scanne par l'agent (contient le code + _mock_findings.json)

cases.json permet de definir a la main des TP/FP/FN/TN connus pour verifier
que matching + metriques tombent juste (etape 1 de la verification du plan).
"""

from __future__ import annotations

import json
from pathlib import Path

from harness.schema import GroundTruthLabel


def load(cfg: dict) -> list[GroundTruthLabel]:
    base = Path(cfg["_repo_root"]) / cfg["path"]
    cases_file = base / "cases.json"
    if not cases_file.exists():
        return []
    raw = json.loads(cases_file.read_text(encoding="utf-8"))
    labels: list[GroundTruthLabel] = []
    for c in raw:
        labels.append(
            GroundTruthLabel(
                case_id=c["case_id"],
                dataset="synthetic",
                language=c["language"],
                repo_path=str(base / c["case_id"]),
                is_vulnerable=c["is_vulnerable"],
                file=c.get("file"),
                line_start=c.get("line_start"),
                line_end=c.get("line_end"),
                cwe_id=c.get("cwe_id"),
                vuln_test_cmd=c.get("vuln_test_cmd"),
                functional_test_cmd=c.get("functional_test_cmd"),
            )
        )
    return labels
