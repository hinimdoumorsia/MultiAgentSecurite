"""Benchmark CORRECTION multi-LLM (mode B : faille connue -> Patcher).

Compare plusieurs LLM sur la MÊME tâche : patcher (fichier complet) les cas
vulnérables CVEfixes, et mesurer le taux de patch produit + la similarité au fix
humain. Un modèle = un run (attribution propre).

  python -m MultiAgentSecurite.benchmark.correction_runner --models groq-llama70b deepseek-v4 ...
  (sans --models : tous les modèles du registre)

Sorties : results/llm_comparison/<slug>/correction_cvefixes.json + CORRECTION_COMPARISON.md
"""
from __future__ import annotations
import argparse, difflib, json, sys
from datetime import datetime, timezone
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "benchmark"))
import time  # noqa: E402
from MultiAgentSecurite.benchmark.llm_models import MODELS, client_for, INPUT_CHARS  # noqa: E402

_CASES = _REPO / "benchmark" / "datasets" / "cvefixes" / "_cases"
_DET_RAW = _REPO / "benchmark" / "results" / "run_20260531-152036" / "raw_records.json"
_OUT = _REPO / "benchmark" / "results" / "llm_comparison"
SYS_PROMPT = ("You are a security engineer. Fix ONLY the vulnerability in this file. "
              "Preserve package, imports, all other code and behaviour. "
              "Return the COMPLETE corrected file, no markdown fences, no explanation.")


def clean(raw):
    s = (raw or "").strip()
    if s.startswith("```"):
        s = s.split("\n", 1)[1] if "\n" in s else s
        s = s.rsplit("```", 1)[0] if "```" in s else s
    return s.strip("\n")


def select(per_lang):
    recs = json.loads(_DET_RAW.read_text(encoding="utf-8"))
    by = {}
    for r in recs:
        if r["is_vulnerable"] and (_CASES / r["case_id"]).exists():
            by.setdefault(r["language"], []).append(r)
    out = []
    for lang, items in by.items():
        out.extend(items[:per_lang])
    return out


def run_model(slug, cases):
    cli, model, desc, maxtok = client_for(slug)
    print(f"\n### MODELE {slug} ({model}) — {desc}")
    by_lang, recs, tin, tout, errors = {}, [], 0, 0, 0
    for i, c in enumerate(cases, 1):
        cid, lang, fn = c["case_id"], c["language"], c["label_file"]
        before = (_CASES / cid / fn).read_text(errors="replace")
        gp = _CASES / cid.replace("_bad", "_good") / fn
        after = gp.read_text(errors="replace") if gp.exists() else ""
        produced, sim = False, 0.0
        try:
            r = cli.chat.completions.create(model=model,
                messages=[{"role": "system", "content": SYS_PROMPT},
                          {"role": "user", "content": f"Vulnerability {c['label_cwe']}.\n```\n{before[:INPUT_CHARS]}\n```"}],
                temperature=0.2, max_tokens=maxtok)
            corr = clean(r.choices[0].message.content or "")
            tin += r.usage.prompt_tokens; tout += r.usage.completion_tokens
            produced = len(corr) > 20
            if produced and after:
                sim = difflib.SequenceMatcher(None, corr, after).ratio()
        except Exception as e:
            errors += 1
            if errors <= 3:
                print(f"   err {cid}: {str(e)[:70]}")
        t = by_lang.setdefault(lang, {"n": 0, "prod": 0, "sim": []})
        t["n"] += 1
        if produced:
            t["prod"] += 1; t["sim"].append(sim)
        recs.append({"case_id": cid, "lang": lang, "produced": produced, "sim": round(sim, 4)})
        time.sleep(0.3)  # pacing pour respecter les limites/minute
        if i % 20 == 0:
            print(f"   ... {i}/{len(cases)}")
    n = len(cases); prod = sum(t["prod"] for t in by_lang.values())
    sims = [s for t in by_lang.values() for s in t["sim"]]
    g = {"model": model, "n": n, "produced_rate": round(prod / n, 4) if n else 0,
         "avg_similarity": round(sum(sims) / len(sims), 4) if sims else 0,
         "errors": errors, "tokens_out": tout}
    # contrôle cohérence
    if g["produced_rate"] == 0:
        print(f"   [ALERTE] {slug}: 0 patch produit -> modèle KO ?")
    d = _OUT / slug; d.mkdir(parents=True, exist_ok=True)
    (d / "correction_cvefixes.json").write_text(json.dumps(
        {"summary": g, "by_language": {k: {"n": v["n"], "produced": v["prod"],
         "avg_sim": round(sum(v["sim"]) / len(v["sim"]), 4) if v["sim"] else 0} for k, v in by_lang.items()},
         "records": recs}, indent=2), encoding="utf-8")
    print(f"   => produit {g['produced_rate']:.0%} | sim {g['avg_similarity']:.2f} | err {errors} | out_tok {tout}")
    return g


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", default=list(MODELS))
    ap.add_argument("--per-lang", type=int, default=10)
    args = ap.parse_args()
    cases = select(args.per_lang)
    print(f"== Comparaison CORRECTION | {len(args.models)} modèles | {len(cases)} cas ==")
    results = []
    for slug in args.models:
        try:
            results.append(run_model(slug, cases))
        except Exception as e:
            print(f"### {slug}: ECHEC GLOBAL {str(e)[:100]}")
            results.append({"model": slug, "produced_rate": 0, "avg_similarity": 0, "error": str(e)[:100]})
    # tableau comparatif
    _OUT.mkdir(parents=True, exist_ok=True)
    lines = ["# Comparaison LLM — Correction (CVEfixes, mode B)", "",
             f"_{datetime.now(timezone.utc).isoformat()} | {len(cases)} cas_", "",
             "| Modèle | Taux patch produit | Similarité moy. au fix humain | Erreurs |",
             "|---|---|---|---|"]
    for slug, g in zip(args.models, results):
        lines.append(f"| {slug} | {g.get('produced_rate',0):.0%} | {g.get('avg_similarity',0):.3f} | {g.get('errors','?')} |")
    (_OUT / "CORRECTION_COMPARISON.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\n=== Tableau écrit : {_OUT / 'CORRECTION_COMPARISON.md'} ===")
    for slug, g in zip(args.models, results):
        print(f"  {slug:18s} produit={g.get('produced_rate',0):.0%} sim={g.get('avg_similarity',0):.3f}")


if __name__ == "__main__":
    main()
