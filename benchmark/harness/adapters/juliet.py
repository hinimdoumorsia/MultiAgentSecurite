"""Adapter Juliet Test Suite (NIST SARD) C/C++ -> liste[GroundTruthLabel].

Dans Juliet, CHAQUE fichier testcase contient a la fois le code vulnerable et le
code corrige, separes par des gardes preprocesseur :

    #ifndef OMITBAD   ... #endif /* OMITBAD */    <- code VULNERABLE (fonction bad)
    #ifndef OMITGOOD  ... #endif /* OMITGOOD */    <- code SAIN (fonctions good)
    #ifdef  INCLUDEMAIN ...                         <- main() de test (ignore)

On exploite ces gardes pour materialiser DEUX fichiers PROPRES par cas :
  - <id>_bad  : fichier sans le bloc OMITGOOD  -> is_vulnerable=True
  - <id>_good : fichier sans le bloc OMITBAD   -> is_vulnerable=False (negatif PROPRE)

C'est ce qui donne a Juliet sa valeur : des negatifs construits (precision/FPR
fiables). Le CWE vient du nom (CWEnnn). Scoring 'presence' (fichier + CWE famille).

Seuls les fichiers AUTONOMES (contenant les deux gardes) sont traites ; les
variantes multi-fichiers (_01a.c/_01b.c, _51a.c...) sont ignorees.
"""

from __future__ import annotations

import re
from pathlib import Path

from MultiAgentSecurite.benchmark.harness.schema import GroundTruthLabel

_EXT_LANG = {".c": "c", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp"}
_CWE_RE = re.compile(r"CWE[-_]?(\d+)", re.IGNORECASE)
_FLAW_RE = re.compile(r"/\*\s*POTENTIAL\s+FLAW", re.IGNORECASE)


def _cwe_of(path: Path) -> str:
    m = _CWE_RE.search(str(path))
    return f"CWE-{m.group(1)}" if m else "CWE-Unknown"


def _guard_region(lines: list[str], guard: str) -> tuple[int, int] | None:
    """Indices (debut, fin) inclusifs de la 1ere region `#ifndef <guard> .. #endif /* <guard> */`.

    On matche le #endif ETIQUETE (commentaire contenant le nom du guard) -> robuste
    a l'imbrication (#ifndef _WIN32, etc.).
    """
    start = None
    for i, ln in enumerate(lines):
        if start is None:
            if f"#ifndef {guard}" in ln:
                start = i
        elif "#endif" in ln and guard in ln:
            return (start, i)
    return None


def load(cfg: dict) -> list[GroundTruthLabel]:
    base = Path(cfg["_repo_root"]) / cfg["path"]
    if not base.exists():
        raise FileNotFoundError(
            f"Dataset Juliet introuvable : {base}\n"
            f"Telecharger Juliet C/C++ (NIST SARD) et l'extraire la d'abord."
        )

    per_lang = int(cfg.get("per_language_limit", 50) or 50)
    cases_dir = base / "_cases"
    cases_dir.mkdir(parents=True, exist_ok=True)

    counts: dict[str, int] = {}
    labels: list[GroundTruthLabel] = []
    target_langs = set(_EXT_LANG.values())

    for src in sorted(base.rglob("*")):
        if not src.is_file() or "_cases" in src.parts:
            continue
        lang = _EXT_LANG.get(src.suffix.lower())
        if lang is None:
            continue
        if counts.get(lang, 0) >= per_lang:
            if all(counts.get(l, 0) >= per_lang for l in target_langs):
                break
            continue

        try:
            lines = src.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            continue

        bad_r = _guard_region(lines, "OMITBAD")
        good_r = _guard_region(lines, "OMITGOOD")
        if bad_r is None or good_r is None:
            continue  # fichier non autonome (variante multi-fichiers) -> ignore

        # On coupe la zone INCLUDEMAIN (main de test) jusqu'a la fin.
        main_i = next((i for i, ln in enumerate(lines) if "#ifdef INCLUDEMAIN" in ln), len(lines))
        core = range(0, main_i)
        bad_set = set(range(bad_r[0], bad_r[1] + 1))
        good_set = set(range(good_r[0], good_r[1] + 1))

        bad_lines = [lines[i] for i in core if i not in good_set]   # vulnerable (sans le good)
        good_lines = [lines[i] for i in core if i not in bad_set]   # sain (sans le bad)

        cwe = _cwe_of(src)
        counts[lang] = counts.get(lang, 0) + 1
        cid = f"{cwe}_{src.stem}_{counts[lang]}"
        fname = src.name

        flaw = next((n for n, ln in enumerate(bad_lines, 1) if _FLAW_RE.search(ln)), None)

        d_bad = cases_dir / f"{cid}_bad"
        d_bad.mkdir(parents=True, exist_ok=True)
        (d_bad / fname).write_text("\n".join(bad_lines), encoding="utf-8", errors="replace")
        labels.append(GroundTruthLabel(
            case_id=f"{cid}_bad", dataset="juliet", language=lang,
            repo_path=str(d_bad), is_vulnerable=True,
            file=fname, line_start=flaw, line_end=flaw, cwe_id=cwe,
            extra={"source": str(src)},
        ))

        d_good = cases_dir / f"{cid}_good"
        d_good.mkdir(parents=True, exist_ok=True)
        (d_good / fname).write_text("\n".join(good_lines), encoding="utf-8", errors="replace")
        labels.append(GroundTruthLabel(
            case_id=f"{cid}_good", dataset="juliet", language=lang,
            repo_path=str(d_good), is_vulnerable=False,
            file=fname, line_start=None, line_end=None, cwe_id=cwe,
            extra={"source": str(src)},
        ))

    print(f"  [juliet] cas vuln par langage : {counts}")
    return labels
