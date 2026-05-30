"""Runner principal du benchmark.

    python -m benchmark.harness.runner --config benchmark/config.yaml
    python -m benchmark.harness.runner --mock          # sans API, runner factice
    python -m benchmark.harness.runner --dataset synthetic --mock

Pipeline : config -> adapters (labels) -> runner agent (findings, cache par
repo_path) -> matching (detection) + verify (repair) -> metriques par langage
et globales -> ecriture CSV + Markdown + JSON brut.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

import yaml

# Permet `python -m benchmark.harness.runner` ET `python runner.py`.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT / "benchmark") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "benchmark"))

from harness.adapters import get_adapter
from harness.detection_metrics import DetectionReport
from harness.match import classify_case, _same_file
from harness.repair_metrics import RepairReport
from harness.repair_verify import verify_repair
from harness.run_agent import AgentRunner, MockRunner
from harness.schema import CaseResult, GroundTruthLabel


def load_config(path: str) -> dict:
    cfg = yaml.safe_load((_REPO_ROOT / path).read_text(encoding="utf-8"))
    cfg["_repo_root"] = str(_REPO_ROOT)
    return cfg


def collect_labels(cfg: dict, only: str | None) -> list[GroundTruthLabel]:
    labels: list[GroundTruthLabel] = []
    for name, dcfg in cfg["datasets"].items():
        if only and name != only:
            continue
        if not dcfg.get("enabled", False) and not only:
            continue
        dcfg = {**dcfg, "_repo_root": cfg["_repo_root"]}
        adapter = get_adapter(dcfg["adapter"])
        loaded = adapter(dcfg)
        for lab in loaded:
            lab.extra["_track"] = dcfg.get("track", "detection")
            lab.extra["_scoring"] = dcfg.get("scoring", "presence")
        print(f"  [{name}] {len(loaded)} cas charges")
        labels.extend(loaded)
    return labels


def run(cfg: dict, runner, only: str | None) -> dict:
    labels = collect_labels(cfg, only)
    if not labels:
        print("Aucun cas a evaluer (verifier 'enabled' dans config.yaml).")
        return {}

    line_tol = cfg["matching"]["line_tolerance"]
    cwe_mode = cfg["matching"]["cwe_mode"]
    k = cfg["agent"].get("runs_per_case", 1)

    detection = DetectionReport()
    repair = RepairReport()
    raw_records: list[dict] = []

    # Cache des findings par repo_path : un projet scanne une seule fois
    # (essentiel pour OWASP : 2740 labels partagent 1 repo_path = 1 seul scan).
    findings_cache: dict[tuple[str, int], CaseResult] = {}

    for i, label in enumerate(labels, 1):
        track = label.extra.get("_track", "detection")
        for run_idx in range(k):
            key = (label.repo_path, run_idx)
            cached = findings_cache.get(key)
            if cached is not None:
                result = CaseResult(
                    case_id=label.case_id, dataset=label.dataset,
                    language=label.language, run_index=run_idx,
                    findings=cached.findings, duration_sec=cached.duration_sec,
                    error=cached.error,
                )
            else:
                result = runner.run(label, run_idx)
                findings_cache[key] = result

            # --- Detection ---
            if track in ("detection", "both"):
                outcome = classify_case(
                    label, result.findings, line_tol, cwe_mode,
                    scoring=label.extra.get("_scoring", "presence"),
                )
                detection.record(label.language, outcome)
                result.flagged = len(result.findings) > 0
                result.is_true_positive = (outcome == "TP")
            else:
                outcome = None

            # --- Repair ---
            if track in ("repair", "both"):
                result = verify_repair(label, result.findings, result,
                                       cfg["agent"].get("timeout_sec", 600))
                repair.record(label.language, result)

            raw_records.append({
                "case_id": label.case_id, "dataset": label.dataset,
                "language": label.language, "run": run_idx,
                "track": track, "outcome": outcome,
                "label_file": label.file, "label_cwe": label.cwe_id,
                "is_vulnerable": label.is_vulnerable,
                "n_findings": len(result.findings),
                # Findings tombant dans le fichier du cas (pour re-tester le matching
                # hors-ligne sans relancer l'agent).
                "findings_in_file": [
                    {"file": f.file, "lines": [f.line_start, f.line_end], "cwe": f.cwe_id}
                    for f in result.findings
                    if label.file is None or _same_file(label.file, f.file)
                ],
                "patch_valid_diff": result.patch_valid_diff,
                "patch_fixes": result.patch_fixes,
                "patch_regresses": result.patch_regresses,
                "duration_sec": result.duration_sec,
                "error": result.error,
            })
        if i % 50 == 0:
            print(f"  ... {i}/{len(labels)} cas traites")

    summary = {
        "generated_at": _utcnow().isoformat(),
        "runner": runner.name,
        "n_cases": len(labels),
        "runs_per_case": k,
        "detection": detection.summary(cfg["output"].get("bootstrap_samples", 1000)),
        "repair": repair.summary(),
    }
    _write_outputs(cfg, summary, raw_records)
    return summary


def _write_outputs(cfg: dict, summary: dict, raw: list[dict]) -> None:
    out_dir = _REPO_ROOT / cfg["output"]["dir"]
    (out_dir / "raw").mkdir(parents=True, exist_ok=True)
    stamp = _utcnow().strftime("%Y%m%d-%H%M%S")

    (out_dir / "raw" / f"records_{stamp}.json").write_text(
        json.dumps(raw, indent=2), encoding="utf-8")
    (out_dir / f"summary_{stamp}.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8")

    # CSV detection : une ligne par langue + GLOBAL.
    det = summary["detection"]
    with (out_dir / f"detection_{stamp}.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["language", "tp", "fp", "fn", "tn", "precision", "recall", "f1", "fpr", "youden_j"])
        for lang, m in det["by_language"].items():
            w.writerow([lang, m["tp"], m["fp"], m["fn"], m["tn"],
                        m["precision"], m["recall"], m["f1"], m["fpr"], m["youden_j"]])
        g = det["global_micro"]
        w.writerow(["GLOBAL(micro)", g["tp"], g["fp"], g["fn"], g["tn"],
                    g["precision"], g["recall"], g["f1"], g["fpr"], g["youden_j"]])

    _write_markdown(out_dir / f"summary_{stamp}.md", summary)
    print(f"\nResultats ecrits dans {out_dir} (stamp {stamp})")


def _write_markdown(path: Path, summary: dict) -> None:
    det = summary["detection"]
    rep = summary["repair"]
    lines = [
        f"# Benchmark MultiAgentSecurite - {summary['generated_at']}",
        "",
        f"- Runner : `{summary['runner']}`  |  cas : {summary['n_cases']}  |  runs/cas : {summary['runs_per_case']}",
        "",
        "## Detection (par langage)",
        "",
        "| Langage | TP | FP | FN | TN | Precision | Rappel | F1 | FPR | Youden J |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for lang, m in det["by_language"].items():
        lines.append(f"| {lang} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} | "
                     f"{m['precision']} | {m['recall']} | {m['f1']} | {m['fpr']} | {m['youden_j']} |")
    g = det["global_micro"]
    lines.append(f"| **GLOBAL (micro)** | {g['tp']} | {g['fp']} | {g['fn']} | {g['tn']} | "
                 f"**{g['precision']}** | **{g['recall']}** | **{g['f1']}** | {g['fpr']} | **{g['youden_j']}** |")
    mac = det["global_macro"]
    ci = det["f1_ci95"]
    lines += [
        "",
        f"- **Macro-moyenne** : precision={mac['precision']} rappel={mac['recall']} F1={mac['f1']} Youden={mac['youden_j']}",
        f"- **IC 95% du F1 (micro, bootstrap)** : [{ci[0]}, {ci[1]}]",
        "",
        "## Correction (repair)",
        "",
        "| Langage | Tentes | Diff valide | Taux fix | Taux regression |",
        "|---|---|---|---|---|",
    ]
    for lang, m in rep["by_language"].items():
        lines.append(f"| {lang} | {m['attempted']} | {m['valid_diff_rate']} | "
                     f"{m['fix_rate']} | {m['regression_rate']} |")
    rg = rep["global"]
    lines.append(f"| **GLOBAL** | {rg['attempted']} | {rg['valid_diff_rate']} | "
                 f"**{rg['fix_rate']}** | **{rg['regression_rate']}** |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description="Benchmark MultiAgentSecurite")
    ap.add_argument("--config", default="benchmark/config.yaml")
    ap.add_argument("--dataset", default=None, help="ne lancer qu'un dataset (par nom)")
    ap.add_argument("--mock", action="store_true", help="MockRunner (sans API ni agent)")
    args = ap.parse_args()

    cfg = load_config(args.config)
    if args.mock:
        runner = MockRunner()
    else:
        runner = AgentRunner(
            max_iterations=cfg["agent"].get("max_iterations", 3),
            timeout_sec=cfg["agent"].get("timeout_sec", 600),
            detection_only=cfg["agent"].get("detection_only", False),
        )
    print(f"== Benchmark | runner={runner.name} ==")
    summary = run(cfg, runner, args.dataset)
    if summary:
        g = summary["detection"]["global_micro"]
        print(f"\nGLOBAL detection : P={g['precision']} R={g['recall']} "
              f"F1={g['f1']} FPR={g['fpr']} YoudenJ={g['youden_j']}")


if __name__ == "__main__":
    main()
