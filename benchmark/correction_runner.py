"""Benchmark de CORRECTION (mode B : faille connue -> Patcher), multi-langages.

Pour chaque cas vulnerable CVEfixes, on donne la faille au modele de patch et on
lui demande le FICHIER CORRIGE COMPLET (plus fiable que les diffs unifies, que
git apply rejette). On mesure :

  - patch_produced  : un fichier corrige non vide est-il produit ?
  - similarity      : similarite (difflib) au vrai fix humain (fixed_code de CVEfixes).

Le taux de fix RIGOUREUX (tests qui passent) releve de Vul4J (tests executables) ;
ici la similarite est un signal INDICATIF multi-langages.

Modele de patch : DeepSeek V4 (un seul modele -> attribution propre).

  python -m MultiAgentSecurite.benchmark.correction_runner --per-lang 10
"""

from __future__ import annotations

import argparse
import csv
import difflib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from llm.client import LLMClient  # noqa: E402

_CASES = _REPO / "benchmark" / "datasets" / "cvefixes" / "_cases"
_DET_RAW = _REPO / "benchmark" / "results" / "run_20260531-152036" / "raw_records.json"
_OUT = _REPO / "benchmark" / "results"
_MODEL = "deepseek-v4-flash"

FULLFILE_PROMPT = """You are a security engineer. Fix ONLY the described vulnerability in the file.
Preserve all other code, formatting and behaviour. Do NOT explain.
Return the COMPLETE corrected file content and nothing else (no markdown fences)."""


def _clean(raw: str) -> str:
    s = (raw or "").strip()
    if s.startswith("```"):
        s = s.split("\n", 1)[1] if "\n" in s else s
        if s.rstrip().endswith("```"):
            s = s.rstrip()[:-3]
    return s.strip("\n")


def _select(per_lang: int) -> list[dict]:
    recs = json.loads(_DET_RAW.read_text(encoding="utf-8"))
    by_lang: dict[str, list[dict]] = {}
    for r in recs:
        if r["is_vulnerable"] and (_CASES / r["case_id"]).exists():
            by_lang.setdefault(r["language"], []).append(r)
    out = []
    for lang, items in by_lang.items():
        out.extend(items[:per_lang])
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-lang", type=int, default=10)
    args = ap.parse_args()

    llm = LLMClient()
    ds = next((e for e in llm._strong if "deepseek" in e.label), llm._strong[0])
    print(f"== Correction (mode B) | modele patch : {_MODEL} ==")

    cases = _select(args.per_lang)
    print(f"{len(cases)} cas selectionnes\n")

    by_lang: dict[str, dict] = {}
    records = []
    tot_in = tot_out = 0

    for i, c in enumerate(cases, 1):
        lang, cid, fname = c["language"], c["case_id"], c["label_file"]
        before = (_CASES / cid / fname).read_text(errors="replace")
        good = _CASES / cid.replace("_bad", "_good") / fname
        after = good.read_text(errors="replace") if good.exists() else ""

        user = f"Vulnerability type: {c['label_cwe']}\nFile: {fname}\n\nVulnerable file:\n```\n{before[:6000]}\n```"
        try:
            r = ds.client.chat.completions.create(
                model=_MODEL,
                messages=[{"role": "system", "content": FULLFILE_PROMPT},
                          {"role": "user", "content": user}],
                temperature=0.2, max_tokens=8192)
            corrected = _clean(r.choices[0].message.content or "")
            tot_in += r.usage.prompt_tokens
            tot_out += r.usage.completion_tokens
            err = None
        except Exception as exc:  # noqa: BLE001
            corrected, err = "", str(exc)[:120]

        produced = len(corrected) > 0
        sim = difflib.SequenceMatcher(None, corrected, after).ratio() if (produced and after) else 0.0

        t = by_lang.setdefault(lang, {"n": 0, "produced": 0, "sim": []})
        t["n"] += 1
        if produced:
            t["produced"] += 1
            t["sim"].append(sim)
        records.append({"case_id": cid, "language": lang, "cwe": c["label_cwe"],
                        "produced": produced, "similarity": round(sim, 4), "error": err})
        if i % 10 == 0 or i == len(cases):
            print(f"  ... {i}/{len(cases)}")

    # --- agregation + ecriture ---
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    run_dir = _OUT / f"correction_{stamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    def lang_row(t):
        pr = round(t["produced"] / t["n"], 4) if t["n"] else 0.0
        sm = round(sum(t["sim"]) / len(t["sim"]), 4) if t["sim"] else 0.0
        return t["n"], pr, sm

    lines = [f"# Benchmark CORRECTION (mode B) - {datetime.now(timezone.utc).isoformat()}",
             "",
             f"- Modele de patch : `{_MODEL}` (modele unique)  |  cas : {len(cases)}",
             "- Mode B : faille connue donnee au Patcher (qualite de correction pure).",
             "- Approche fichier-complet (application fiable). Similarite = vs vrai fix humain (CVEfixes).",
             "- ⚠️ Taux de fix rigoureux (tests) = Vul4J (a part) ; ici la similarite est INDICATIVE.",
             "",
             "| Langage | Cas | Taux patch produit | Similarite moy. au fix humain |",
             "|---|---|---|---|"]
    g_n = g_prod = 0
    g_sim = []
    with (run_dir / "correction_by_language.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(["language", "n", "produced_rate", "avg_similarity"])
        for lang, t in sorted(by_lang.items()):
            n, pr, sm = lang_row(t)
            lines.append(f"| {lang} | {n} | {pr} | {sm} |")
            w.writerow([lang, n, pr, sm])
            g_n += t["n"]; g_prod += t["produced"]; g_sim += t["sim"]
        g_pr = round(g_prod / g_n, 4) if g_n else 0.0
        g_sm = round(sum(g_sim) / len(g_sim), 4) if g_sim else 0.0
        lines.append(f"| **GLOBAL** | {g_n} | **{g_pr}** | **{g_sm}** |")
        w.writerow(["GLOBAL", g_n, g_pr, g_sm])

    lines += ["", f"- Tokens : entree={tot_in}, sortie={tot_out} (modele {_MODEL})."]
    (run_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (run_dir / "raw_records.json").write_text(json.dumps(records, indent=2), encoding="utf-8")

    print(f"\nGLOBAL: patch produit={g_pr} | similarite moy={g_sm} | tokens out={tot_out}")
    print(f"Resultats: {run_dir}")


if __name__ == "__main__":
    main()
