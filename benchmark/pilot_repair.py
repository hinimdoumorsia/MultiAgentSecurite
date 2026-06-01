"""Pilote correction (mode B : faille connue -> Patcher) sur quelques cas CVEfixes.

But : valider la chaine patch -> git apply -> re-scan -> similarite, ET mesurer le
COUT REEL (tokens) du modele de patch (DeepSeek V4). Autonome, n'industrialise rien.

Lancer depuis le dossier parent (projetagentc/) :
  python -m MultiAgentSecurite.benchmark.pilot_repair --n 5
"""

from __future__ import annotations

import argparse
import difflib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]          # MultiAgentSecurite/
sys.path.insert(0, str(_REPO / "src"))

from llm.client import LLMClient                       # noqa: E402
from tools.semgrep_tool import SemgrepTool             # noqa: E402
from graph.state import Language                       # noqa: E402

# Approche "fichier complet" : plus fiable que les diffs unifies (que git apply
# rejette souvent). Le modele renvoie le fichier corrige ENTIER, on remplace.
FULLFILE_PROMPT = """You are a security engineer. Fix ONLY the described vulnerability in the file.
Preserve all other code, formatting and behaviour. Do NOT explain.
Return the COMPLETE corrected file content and nothing else (no markdown fences)."""

_CASES = _REPO / "benchmark" / "datasets" / "cvefixes" / "_cases"
_DET_RAW = _REPO / "benchmark" / "results" / "run_20260531-152036" / "raw_records.json"


def _pick_cases(n: int) -> list[dict]:
    """Prend n cas VULNERABLES de langages varies depuis le run de detection."""
    recs = json.loads(_DET_RAW.read_text(encoding="utf-8"))
    bad = [r for r in recs if r["is_vulnerable"]]
    out, seen_lang = [], set()
    for r in bad:                                       # 1 par langage d'abord
        if r["language"] not in seen_lang and (_CASES / r["case_id"]).exists():
            out.append(r); seen_lang.add(r["language"])
        if len(out) >= n:
            break
    for r in bad:                                       # complete si besoin
        if len(out) >= n:
            break
        if r not in out and (_CASES / r["case_id"]).exists():
            out.append(r)
    return out[:n]


def _clean_fullfile(raw: str) -> str:
    """Retire d'eventuelles barrieres markdown autour du fichier renvoye."""
    s = raw.strip()
    if s.startswith("```"):
        s = s.split("\n", 1)[1] if "\n" in s else s
        if s.rstrip().endswith("```"):
            s = s.rstrip()[:-3]
    return s.strip("\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=5)
    args = ap.parse_args()

    llm = LLMClient()
    # Acces direct DeepSeek pour capter l'usage tokens (le client n'expose pas usage).
    ds = llm._strong[0]
    print(f"Modele patch : {ds.label} / {ds.model}\n")

    semgrep = SemgrepTool()
    cases = _pick_cases(args.n)
    tot_in = tot_out = 0
    n_valid = n_fix = 0
    sims: list[float] = []

    for i, c in enumerate(cases, 1):
        cdir = _CASES / c["case_id"]
        gooddir = _CASES / c["case_id"].replace("_bad", "_good")
        fname = c["label_file"]
        before = (cdir / fname).read_text(errors="replace")
        after = (gooddir / fname).read_text(errors="replace") if (gooddir / fname).exists() else ""

        user = (f"Vulnerability type: {c['label_cwe']}\nFile: {fname}\n\n"
                f"Vulnerable file:\n```\n{before[:6000]}\n```")

        r = ds.client.chat.completions.create(
            model="deepseek-v4-flash",
            messages=[{"role": "system", "content": FULLFILE_PROMPT},
                      {"role": "user", "content": user}],
            temperature=0.2, max_tokens=8192)
        tot_in += r.usage.prompt_tokens
        tot_out += r.usage.completion_tokens
        corrected = _clean_fullfile(r.choices[0].message.content or "")

        produced = len(corrected) > 0
        fixed = None
        sim = 0.0
        try:
            lang_enum = {Language(c["language"])}
        except ValueError:
            lang_enum = set()
        if produced:
            before_n = len(semgrep.run(str(cdir), lang_enum))
            with tempfile.TemporaryDirectory() as tmp:
                (Path(tmp) / fname).write_text(corrected, encoding="utf-8", errors="replace")
                after_n = len(semgrep.run(tmp, lang_enum))
            fixed = after_n < before_n          # re-scan : moins de findings = faille corrigee
            sim = difflib.SequenceMatcher(None, corrected, after).ratio() if after else 0.0
            sims.append(sim)
        if produced:
            n_valid += 1
        if fixed:
            n_fix += 1
        print(f"[{i}] {c['language']:10s} {c['label_cwe']:10s} | fichier_corrige={'oui' if produced else 'NON'} "
              f"fix(re-scan)={fixed} sim={sim:.2f} | out_tok={r.usage.completion_tokens}")

    n = len(cases)
    avg_in, avg_out = tot_in / n, tot_out / n
    print(f"\n=== Pilote {n} cas (DeepSeek V4-flash, fichier complet) ===")
    print(f"fichier corrige produit : {n_valid}/{n} | fix (re-scan) : {n_fix}/{n} | "
          f"similarite moy au vrai fix : {sum(sims)/len(sims) if sims else 0:.2f}")
    print(f"tokens moyens/patch : in={avg_in:.0f} out={avg_out:.0f}")
    # Estimation cout (tarif a confirmer sur dashboard ; ordre de grandeur)
    print(f"total tokens : in={tot_in} out={tot_out}")
    print("-> verifie le cout reel sur https://platform.deepseek.com (Usage)")


if __name__ == "__main__":
    main()
