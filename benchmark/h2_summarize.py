"""Synthèse H2 : Rust vs LLM sur Juliet (global + sous-ensemble CWE-mémoire). Écrit un JSON."""
import json, math
from pathlib import Path

R = Path("MultiAgentSecurite/benchmark/results")
MEM = {"CWE-121", "CWE-122", "CWE-123", "CWE-124", "CWE-126", "CWE-127", "CWE-415",
       "CWE-416", "CWE-476", "CWE-401", "CWE-404", "CWE-190", "CWE-191", "CWE-457",
       "CWE-562", "CWE-690", "CWE-786", "CWE-787", "CWE-788", "CWE-805", "CWE-822", "CWE-824"}
RUNS = {"rust": "run_20260607-135301_juliet_rust", "llm": "run_20260607-151245_juliet_llm",
        "complet": "run_20260531-191017"}


def wilson(k, n, z=1.96):
    if n == 0:
        return [0.0, 0.0]
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0, c - h), 3), round(min(1, c + h), 3)]


out = {}
for cfg, run in RUNS.items():
    g = json.loads((R / run / "summary.json").read_text(encoding="utf-8"))["detection"]["global_micro"]
    rec = json.loads((R / run / "raw_records.json").read_text(encoding="utf-8"))
    memv = [r for r in rec if r.get("is_vulnerable") and r.get("label_cwe") in MEM]
    memtp = sum(1 for r in memv if r["outcome"] == "TP")
    out[cfg] = {
        "global": {k: g[k] for k in ("tp", "fp", "fn", "tn", "recall", "precision", "fpr", "f1", "youden_j")},
        "recall_wilson": wilson(g["tp"], g["tp"] + g["fn"]),
        "memory_cwe": {"tp": memtp, "n": len(memv),
                       "recall": round(memtp / len(memv), 3) if memv else 0,
                       "wilson": wilson(memtp, len(memv))},
        "run": run,
    }
(R / "h2_juliet_summary.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
print(json.dumps(out, indent=2))
print("écrit:", R / "h2_juliet_summary.json")
