"""Benchmark DÉTECTION multi-LLM (agent sémantique sur CVEfixes).

Sur CVEfixes, Semgrep ne trouve rien (fichiers partiels) -> c'est l'agent SÉMANTIQUE
(LLM) qui porte la détection. On isole donc le LLM : pour chaque modèle, on envoie
le fichier avec le prompt sémantique de l'agent, on parse les findings, et on matche
le CWE (famille) au label. Mesure : rappel (cas vuln) + taux de flag (cas sains).

  python -m MultiAgentSecurite.benchmark.detection_runner --models groq-llama70b ...

Sorties : results/llm_comparison/<slug>/detection_cvefixes.json + DETECTION_COMPARISON.md
"""
from __future__ import annotations
import argparse, json, re, sys
from datetime import datetime, timezone
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "benchmark"))
sys.path.insert(0, str(_REPO / "src"))
import time  # noqa: E402
from MultiAgentSecurite.benchmark.llm_models import MODELS, client_for, INPUT_CHARS  # noqa: E402
from MultiAgentSecurite.benchmark.harness.cwe_map import cwe_matches  # noqa: E402

_CASES = _REPO / "benchmark" / "datasets" / "cvefixes" / "_cases"
_DET_RAW = _REPO / "benchmark" / "results" / "run_20260531-152036" / "raw_records.json"
_OUT = _REPO / "benchmark" / "results" / "llm_comparison"

SYS_PROMPT = """You are an expert security code reviewer. Analyze the code for vulnerabilities
(injection, auth bypass, IDOR, crypto, deserialization, race conditions, path traversal, etc.).
Respond ONLY with a JSON array of objects with keys: title, severity, cwe_id, description.
Example: [{"title":"SQL Injection","severity":"high","cwe_id":"CWE-89","description":"..."}]
Return ONLY valid JSON, nothing else."""


def parse_findings(raw):
    s = (raw or "").strip()
    if "```" in s:
        m = re.search(r"```(?:json)?\s*(\[.*?\]|\{.*?\})\s*```", s, re.DOTALL)
        if m:
            s = m.group(1)
    i, j = s.find("["), s.rfind("]")
    if i != -1 and j > i:
        s = s[i:j + 1]
    try:
        d = json.loads(s)
        return d if isinstance(d, list) else d.get("findings", []) if isinstance(d, dict) else []
    except Exception:
        return []


def select(per_lang):
    recs = json.loads(_DET_RAW.read_text(encoding="utf-8"))
    by = {}
    for r in recs:
        if (_CASES / r["case_id"]).exists():
            by.setdefault((r["language"], r["is_vulnerable"]), []).append(r)
    out = []
    for (lang, vuln), items in by.items():
        out.extend(items[:per_lang])
    return out


def run_model(slug, cases):
    cli, model, desc, maxtok = client_for(slug)
    print(f"\n### MODELE {slug} ({model}) — {desc}")
    # confusion par langage (TP/FN sur vuln, FP/TN sur sain), scoring family
    lang = {}
    errors = 0
    for i, c in enumerate(cases, 1):
        cid = c["case_id"]
        content = (_CASES / cid / c["label_file"]).read_text(errors="replace")
        try:
            r = cli.chat.completions.create(model=model,
                messages=[{"role": "system", "content": SYS_PROMPT},
                          {"role": "user", "content": f"```\n{content[:INPUT_CHARS]}\n```"}],
                temperature=0.2, max_tokens=min(maxtok, 4096))
            finds = parse_findings(r.choices[0].message.content or "")
        except Exception as e:
            errors += 1; finds = []
            if errors <= 3:
                print(f"   err {cid}: {str(e)[:60]}")
        time.sleep(0.3)
        # matche CWE famille au label
        match = any(cwe_matches(c["label_cwe"], (f or {}).get("cwe_id", ""), mode="family")
                    for f in finds if isinstance(f, dict))
        t = lang.setdefault(c["language"], {"tp": 0, "fn": 0, "fp": 0, "tn": 0})
        if c["is_vulnerable"]:
            t["tp" if match else "fn"] += 1
        else:
            t["fp" if match else "tn"] += 1
        if i % 30 == 0:
            print(f"   ... {i}/{len(cases)}")
    TP = sum(t["tp"] for t in lang.values()); FN = sum(t["fn"] for t in lang.values())
    FP = sum(t["fp"] for t in lang.values()); TN = sum(t["tn"] for t in lang.values())
    rec = TP / (TP + FN) if TP + FN else 0
    prec = TP / (TP + FP) if TP + FP else 0
    fpr = FP / (FP + TN) if FP + TN else 0
    g = {"model": model, "TP": TP, "FN": FN, "FP": FP, "TN": TN,
         "recall": round(rec, 4), "precision": round(prec, 4), "fpr": round(fpr, 4),
         "youden": round(rec - fpr, 4), "errors": errors}
    if TP + FN > 0 and rec == 0 and TP == 0:
        print(f"   [ALERTE] {slug}: rappel 0 -> modèle KO ou JSON non parsé ?")
    d = _OUT / slug; d.mkdir(parents=True, exist_ok=True)
    (d / "detection_cvefixes.json").write_text(json.dumps({"summary": g, "by_language": lang}, indent=2), encoding="utf-8")
    print(f"   => R={rec:.2f} P={prec:.2f} FPR={fpr:.2f} Youden={rec-fpr:.2f} | err {errors}")
    return g


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", default=list(MODELS))
    ap.add_argument("--per-lang", type=int, default=10)  # par (langage, vuln/sain)
    args = ap.parse_args()
    cases = select(args.per_lang)
    print(f"== Comparaison DÉTECTION | {len(args.models)} modèles | {len(cases)} cas ==")
    results = []
    for slug in args.models:
        try:
            results.append((slug, run_model(slug, cases)))
        except Exception as e:
            print(f"### {slug}: ECHEC {str(e)[:100]}")
            results.append((slug, {"recall": 0, "precision": 0, "fpr": 0, "youden": 0, "errors": "?"}))
    _OUT.mkdir(parents=True, exist_ok=True)
    lines = ["# Comparaison LLM — Détection sémantique (CVEfixes)", "",
             f"_{datetime.now(timezone.utc).isoformat()} | {len(cases)} cas_", "",
             "| Modèle | Rappel | Précision | FPR | Youden J |",
             "|---|---|---|---|---|"]
    for slug, g in results:
        lines.append(f"| {slug} | {g.get('recall',0):.2f} | {g.get('precision',0):.2f} | {g.get('fpr',0):.2f} | {g.get('youden',0):.2f} |")
    (_OUT / "DETECTION_COMPARISON.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\n=== Tableau écrit : {_OUT / 'DETECTION_COMPARISON.md'} ===")


if __name__ == "__main__":
    main()
