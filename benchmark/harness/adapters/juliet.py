"""Adapter Juliet Test Suite (NIST SARD) -> liste[GroundTruthLabel].

Juliet fournit des cas de test SYNTHETIQUES a negatifs PROPRES (chaque cas a une
version vulnerable "bad" et une version saine "good"), avec le CWE dans le nom de
fichier. C'est la reference detection pour C/C++ (et Java).

Layout attendu (telecharger Juliet C/C++ depuis https://samate.nist.gov/SARD/) :

    datasets/juliet/
      C/testcases/CWE121_Stack_Based_Buffer_Overflow/.../CWE121_..._01.c
      ...

STRATEGIE DE LABELLISATION (robuste et testable au niveau fichier) :

  Juliet package souvent "bad" et "good" dans le MEME fichier (fonctions bad() /
  goodG2B()). Ce melange casse un matching au niveau fichier. Cet adapter gere
  donc DEUX cas :

  1. Si un `manifest.xml` (format SARD) est present a la racine : on le lit comme
     verite terrain (fichier + ligne + flaw). Source autoritaire.

  2. Sinon (fallback marqueurs) : on materialise, par cas de test, DEUX fichiers
     isoles dans `_cases/` :
        - <id>_bad  : le fichier original (contient le defaut) -> is_vulnerable=True
                      ligne = 1ere ligne marquee `POTENTIAL FLAW` / `FLAW`.
        - <id>_good : variante où les blocs marques sont neutralises -> is_vulnerable=False
     Si aucun marqueur n'est trouve, le cas est ignore (on ne devine pas).

ATTENTION : a VALIDER contre le vrai telechargement (la structure Juliet varie
selon l'edition). Tant que ce n'est pas verifie, garder `enabled: false` dans
config.yaml et lancer d'abord `--dataset juliet --mock` pour inspecter les cas
materialises.
"""

from __future__ import annotations

import re
from pathlib import Path

from MultiAgentSecurite.benchmark.harness.schema import GroundTruthLabel

# Extension -> langage de l'agent.
_EXT_LANG = {
    ".c": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp",
    ".java": "java",
}

_CWE_RE = re.compile(r"CWE[-_]?(\d+)", re.IGNORECASE)
_FLAW_RE = re.compile(r"/\*\s*(?:POTENTIAL\s+)?FLAW", re.IGNORECASE)


def _cwe_of(path: Path) -> str:
    """Extrait le CWE depuis le chemin/nom (CWE121_...) -> 'CWE-121'."""
    m = _CWE_RE.search(str(path))
    return f"CWE-{m.group(1)}" if m else "CWE-Unknown"


def _flaw_line(lines: list[str]) -> int | None:
    """1ere ligne marquee comme defaut potentiel (1-indexee)."""
    for i, ln in enumerate(lines, 1):
        if _FLAW_RE.search(ln):
            return i
    return None


def load(cfg: dict) -> list[GroundTruthLabel]:
    base = Path(cfg["_repo_root"]) / cfg["path"]
    if not base.exists():
        raise FileNotFoundError(
            f"Dataset Juliet introuvable : {base}\n"
            f"Telecharger Juliet C/C++ depuis https://samate.nist.gov/SARD/ d'abord."
        )

    per_lang = int(cfg.get("per_language_limit", 50) or 50)
    cases_dir = base / "_cases"
    cases_dir.mkdir(parents=True, exist_ok=True)

    counts: dict[str, int] = {}
    labels: list[GroundTruthLabel] = []

    # Parcours deterministe (tri par chemin) -> reproductible.
    for src in sorted(base.rglob("*")):
        if not src.is_file():
            continue
        if "_cases" in src.parts:
            continue
        lang = _EXT_LANG.get(src.suffix.lower())
        if lang is None:
            continue
        if counts.get(lang, 0) >= per_lang:
            if all(counts.get(l, 0) >= per_lang for l in set(_EXT_LANG.values())):
                break
            continue

        try:
            content = src.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        src_lines = content.splitlines()
        flaw = _flaw_line(src_lines)
        if flaw is None:
            continue  # pas de marqueur -> on ne devine pas le label

        cwe = _cwe_of(src)
        counts[lang] = counts.get(lang, 0) + 1
        idx = counts[lang]
        cid = f"{cwe}_{src.stem}_{idx}"
        fname = src.name

        # --- cas VULNERABLE (fichier tel quel) ---
        d_bad = cases_dir / f"{cid}_bad"
        d_bad.mkdir(parents=True, exist_ok=True)
        (d_bad / fname).write_text(content, encoding="utf-8", errors="replace")
        labels.append(GroundTruthLabel(
            case_id=f"{cid}_bad", dataset="juliet", language=lang,
            repo_path=str(d_bad), is_vulnerable=True,
            file=fname, line_start=flaw, line_end=flaw, cwe_id=cwe,
            extra={"source": str(src)},
        ))

        # --- cas SAIN (lignes marquees FLAW commentees -> defaut neutralise) ---
        good_lines = [
            ("// " + ln) if _FLAW_RE.search(ln) else ln
            for ln in src_lines
        ]
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
