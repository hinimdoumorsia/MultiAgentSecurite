"""Action 4 : score CodeQL sur OWASP avec le MÊME harness que l'agent (comparaison équitable).

Parse results.sarif -> AgentFinding (fichier, ligne, CWE) -> classify_case (mêmes cas, même
matching family + scoring category) -> P/R/F1/FPR/Youden + IC Wilson. Écrit un JSON.

  python -m MultiAgentSecurite.benchmark.codeql_owasp_score <results.sarif>
"""
from __future__ import annotations
import json, re, sys, math
from pathlib import Path

_BM = Path(__file__).resolve().parents[1] / "benchmark"
sys.path.insert(0, str(_BM))
from MultiAgentSecurite.benchmark.harness.runner import load_config, collect_labels
from MultiAgentSecurite.benchmark.harness.match import classify_case
from MultiAgentSecurite.benchmark.harness.detection_metrics import DetectionReport
from MultiAgentSecurite.benchmark.harness.schema import AgentFinding


def wilson(k, n, z=1.96):
    if n == 0:
        return [0.0, 0.0]
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0, c - h), 3), round(min(1, c + h), 3)]


def parse_sarif(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    findings = []
    for run in data.get("runs", []):
        # ruleId -> CWE (depuis les tags external/cwe/cwe-NNN)
        rule_cwe = {}
        for r in run.get("tool", {}).get("driver", {}).get("rules", []):
            tags = r.get("properties", {}).get("tags", [])
            cwes = [t.split("/")[-1].upper().replace("CWE-", "CWE-") for t in tags if "external/cwe/cwe-" in t]
            if cwes:
                rule_cwe[r["id"]] = "CWE-" + re.sub(r"\D", "", cwes[0])
        for res in run.get("results", []):
            rid = res.get("ruleId", "")
            cwe = rule_cwe.get(rid, "CWE-Unknown")
            for loc in res.get("locations", []):
                pl = loc.get("physicalLocation", {})
                uri = pl.get("artifactLocation", {}).get("uri", "")
                reg = pl.get("region", {})
                ls = int(reg.get("startLine", 0) or 0); le = int(reg.get("endLine", ls) or ls)
                if uri:
                    findings.append(AgentFinding(file=uri, line_start=ls, line_end=le, cwe_id=cwe,
                                                 title=rid, raw={"rule": rid}))
    return findings


def main():
    sarif = sys.argv[1] if len(sys.argv) > 1 else str(_BM / "results" / "codeql_owasp.sarif")
    cfg = load_config("benchmark/config.yaml")
    labels = collect_labels(cfg, "owasp")
    findings = parse_sarif(sarif)
    print(f"labels OWASP={len(labels)}  findings CodeQL={len(findings)}", flush=True)
    line_tol = cfg["matching"]["line_tolerance"]
    det = DetectionReport()
    for lab in labels:
        outcome = classify_case(lab, findings, line_tol, cfg["matching"]["cwe_mode"],
                                scoring=lab.extra.get("_scoring", "category"))
        det.record(lab.language, outcome, dataset=lab.dataset)
    g = det.global_micro().as_dict()
    ci = wilson(g["tp"], g["tp"] + g["fn"])
    out = {"tool": "CodeQL", "dataset": "owasp", "global_micro": g, "recall_wilson": ci,
           "n_findings": len(findings), "n_labels": len(labels), "sarif": sarif}
    (_BM / "results" / "codeql_owasp_summary.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"CodeQL OWASP : TP={g['tp']} FP={g['fp']} FN={g['fn']} TN={g['tn']} | "
          f"P={g['precision']} R={g['recall']} F1={g['f1']} FPR={g['fpr']} J={g['youden_j']} "
          f"| Wilson(R)={ci}")
    print("écrit:", _BM / "results" / "codeql_owasp_summary.json")


if __name__ == "__main__":
    main()
