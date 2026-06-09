"""Audit : recoupe les chiffres clés du rapport avec les fichiers results/ réels."""
import json, glob
from pathlib import Path

R = Path("MultiAgentSecurite/benchmark/results")
ok = bad = 0


def det(run):
    return json.load(open(R / run / "summary.json", encoding="utf-8"))["detection"]


def chk(label, claimed, actual, tol=0.006):  # 0.006 = arrondi 2 décimales (.x25/.x75)
    global ok, bad
    good = abs(claimed - actual) <= tol
    print(f"  [{'OK ' if good else 'BAD'}] {label}: rapport={claimed}  source={round(actual,4)}")
    ok += good; bad += (not good)


print("== DÉTECTION ==")
g = det("run_20260531-172004")["global_micro"]
chk("OWASP full R", 0.96, g["recall"]); chk("OWASP full P", 0.66, g["precision"])
chk("OWASP full F1", 0.78, g["f1"]); chk("OWASP full J", 0.44, g["youden_j"])
g = det("run_20260531-163500")["global_micro"]
chk("OWASP Semgrep R", 0.79, g["recall"]); chk("OWASP Semgrep F1", 0.72, g["f1"]); chk("OWASP Semgrep J", 0.37, g["youden_j"])
g = det("run_20260531-191017")["global_micro"]
chk("Juliet P", 0.52, g["precision"]); chk("Juliet R", 0.81, g["recall"]); chk("Juliet F1", 0.64, g["f1"]); chk("Juliet FPR", 0.74, g["fpr"])
g = det("run_20260531-152036")["global_micro"]
chk("CVEfixes R", 0.24, g["recall"]); chk("CVEfixes F1", 0.24, g["f1"], 0.01); chk("CVEfixes J", -0.55, g["youden_j"])

print("== IC 95% (f1_ci95) ==")
for run, lo, hi in [("run_20260531-163500", 0.707, 0.742), ("run_20260531-172004", 0.770, 0.799),
                    ("run_20260531-191017", 0.566, 0.701), ("run_20260531-152036", 0.198, 0.273)]:
    ci = det(run)["f1_ci95"]; chk(f"{run} CI_lo", lo, ci[0]); chk(f"{run} CI_hi", hi, ci[1])

print("== ABLATION ==")
gn = det("run_20260606-212559_owasp_nosem")["global_micro"]
chk("OWASP nosem R", 0.96, gn["recall"])
gc = det("run_20260606-230943_cvefixes_nosem")["global_micro"]
chk("CVEfixes nosem R", 0.002, gc["recall"], 0.003)
full = json.load(open(R / "run_20260531-172004/raw_records.json", encoding="utf-8"))
nos = json.load(open(R / "run_20260606-212559_owasp_nosem/raw_records.json", encoding="utf-8"))
diff = max(r["n_findings"] for r in full) - max(r["n_findings"] for r in nos)
chk("OWASP findings sémantiques retirés (59)", 59, diff, 0)

print("== VUL4J patch localisé (n=30) ==")
fs = json.load(open(R / "vul4j_func_summary.json", encoding="utf-8"))
exp = {"deepseek-v4-flash": 5, "qwen3-coder": 4, "gpt-oss-120b": 3,
       "llama-4-maverick": 1, "llama-3.3-nemotron-super-49b-v1.5": 1, "llama-3.3-70b-instruct": 1}
for m, fx in exp.items():
    chk(f"Vul4J(loc) FIX {m}", fx, fs["per_model"][m]["fix_eval"], 0)
chk("Vul4J(loc) évaluables (24)", 24, fs["n_evaluable"], 0)
chk("Vul4J(loc) global fixed (15)", 15, fs["global_eval"]["fixed"], 0)
chk("Vul4J(loc) global n (134)", 134, fs["global_eval"]["n"], 0)
chk("Vul4J(loc) global rate (0.11)", 0.112, fs["global_eval"]["rate"])
pb = json.load(open(R / "vul4j_probe.json", encoding="utf-8"))
chk("Vul4J reproductibles (30)", 30, len(pb["valid"]), 0)

print("== SIMILARITÉ (correction, par langue) ==")
import csv as _csv
sim = {r["language"]: float(r["avg_similarity"]) for r in
       _csv.DictReader(open(R / "correction_20260531-213154/correction_by_language.csv", encoding="utf-8"))}
for lang, v in [("c", 0.533), ("php", 0.464), ("java", 0.384), ("javascript", 0.196), ("GLOBAL", 0.332)]:
    chk(f"similarité {lang}", v, sim[lang])

print("== COMPARAISON LLM — DÉTECTION ==")
DDIR = {"llama-3.3-70b": "nvidia-llama70b", "gpt-oss-120b": "nvidia-gptoss",
        "deepseek-v4-flash": "deepseek-v4", "llama-4-maverick": "nvidia-maverick",
        "qwen3-coder-480b": "nvidia-qwencoder", "nemotron-super-49b": "nvidia-nemotron"}
det_claim = {"llama-3.3-70b": (0.50, 0.38, 0.12), "gpt-oss-120b": (0.69, 0.81, -0.12),
             "deepseek-v4-flash": (0.56, 0.75, -0.19), "llama-4-maverick": (0.44, 0.62, -0.19),
             "qwen3-coder-480b": (0.38, 0.56, -0.19), "nemotron-super-49b": (0.31, 0.69, -0.38)}
for m, (r, fpr, j) in det_claim.items():
    raw = json.load(open(R / "llm_comparison" / DDIR[m] / "detection_cvefixes.json", encoding="utf-8"))
    s = raw.get("summary", raw)
    chk(f"det {m} R", r, s["recall"]); chk(f"det {m} FPR", fpr, s["fpr"]); chk(f"det {m} J", j, s["youden"])

print("== COMPARAISON LLM — CORRECTION (similarité) ==")
cor_claim = {"llama-4-maverick": 0.37, "qwen3-coder-480b": 0.34, "llama-3.3-70b": 0.33,
             "nemotron-super-49b": 0.28, "deepseek-v4-flash": 0.27, "gpt-oss-120b": 0.15}
for m, v in cor_claim.items():
    raw = json.load(open(R / "llm_comparison" / DDIR[m] / "correction_cvefixes.json", encoding="utf-8"))
    s = raw.get("summary", raw)
    chk(f"corr-sim {m}", v, s["avg_similarity"])

print("== H2 (Juliet : Rust vs LLM) ==")
h2 = json.load(open(R / "h2_juliet_summary.json", encoding="utf-8"))
chk("H2 rust R global", 0.05, h2["rust"]["global"]["recall"])
chk("H2 llm R global", 0.83, h2["llm"]["global"]["recall"])
chk("H2 rust R mémoire (4/21)", 0.19, h2["rust"]["memory_cwe"]["recall"])
chk("H2 llm R mémoire (21/21)", 1.0, h2["llm"]["memory_cwe"]["recall"])
chk("H2 rust FPR global", 0.04, h2["rust"]["global"]["fpr"])
chk("H2 llm FPR global", 0.77, h2["llm"]["global"]["fpr"])

print("== CodeQL (OWASP) ==")
cq = json.load(open(R / "codeql_owasp_summary.json", encoding="utf-8"))["global_micro"]
chk("CodeQL R", 0.43, cq["recall"]); chk("CodeQL P", 0.87, cq["precision"])
chk("CodeQL F1", 0.58, cq["f1"]); chk("CodeQL FPR", 0.07, cq["fpr"], 0.005)
chk("CodeQL Youden", 0.36, cq["youden_j"]); chk("CodeQL TP", 611, cq["tp"], 0)
chk("CodeQL FN", 804, cq["fn"], 0)

print("== Holdout temporel (contamination) ==")
ho = json.load(open(R / "holdout_year_summary.json", encoding="utf-8"))
chk("Holdout R 2024 (0.72)", 0.719, ho["recent_2024"]["recall"])
chk("Holdout R <=2022 (0.21)", 0.214, ho["old_le2022"]["recall"])

print("== H3 (introduction de failles, deepseek) ==")
try:
    h3 = json.load(open(R / "vul4j_h3.json", encoding="utf-8"))
    chk("H3 n_patches (24)", 24, h3["n_patches"], 0)
    chk("H3 taux introduction (0.0)", 0.0, h3["introduction_rate"] or 0.0, 0)
except FileNotFoundError:
    print("  (vul4j_h3.json absent)")

print(f"\n=== AUDIT : {ok} OK / {bad} BAD ===")
