"""Adapter CVEfixes via HuggingFace (hitoshura25/cvefixes) -> liste[GroundTruthLabel].

Vraies CVE multi-langage. On lit le dataset HF en STREAMING (pas de 12 Go a DL) et
on materialise, par langage, un echantillon :
  - vulnerable_code -> fichier VULNERABLE (is_vulnerable=True)
  - fixed_code      -> fichier SAIN (negatif), optionnel

Colonnes HF utilisees : language, cwe_id, vulnerable_code, fixed_code, file_paths,
cve_id, hash.

NOTE : le code est au niveau du diff/region modifiee (pas tout le depot). On matche
donc au niveau FICHIER (pas de ligne precise) -> scoring 'presence'. Les negatifs
(fixed_code) sont imparfaits -> rappel fiable, precision/FPR bruitees.
"""

from __future__ import annotations

from pathlib import Path

from harness.schema import GroundTruthLabel

# language HF -> (valeur Language de l'agent, extension)
_LANG_MAP = {
    "c": ("c", ".c"),
    "c++": ("cpp", ".cpp"),
    "cpp": ("cpp", ".cpp"),
    "java": ("java", ".java"),
    "python": ("python", ".py"),
    "javascript": ("javascript", ".js"),
    "typescript": ("typescript", ".ts"),
    "php": ("php", ".php"),
    "go": ("go", ".go"),
}

_HF_NAME = "hitoshura25/cvefixes"


def _norm_cwe(raw) -> str:
    if not raw:
        return "CWE-Unknown"
    s = str(raw).strip()
    if s.upper().startswith("CWE-"):
        return s.upper()
    if s.isdigit():
        return f"CWE-{s}"
    return "CWE-Unknown"


def _valid_code(code) -> bool:
    return isinstance(code, str) and len(code.strip()) > 0 and code.strip().lower() != "nan"


def load(cfg: dict) -> list[GroundTruthLabel]:
    from datasets import load_dataset  # import tardif (lib lourde)

    base = Path(cfg["_repo_root"]) / cfg["path"]
    cases_dir = base / "_cases"
    cases_dir.mkdir(parents=True, exist_ok=True)

    per_lang = int(cfg.get("per_language_limit", 25) or 25)   # nb de CVE vuln / langage
    include_neg = bool(cfg.get("include_negatives", True))
    max_scan = int(cfg.get("max_scan", 20000) or 20000)        # garde-fou streaming
    hf_name = cfg.get("hf_dataset", _HF_NAME)

    ds = load_dataset(hf_name, split="train", streaming=True)

    counts: dict[str, int] = {}
    labels: list[GroundTruthLabel] = []
    scanned = 0

    for row in ds:
        scanned += 1
        if scanned > max_scan:
            break

        lang_raw = str(row.get("language", "")).strip().lower()
        if lang_raw not in _LANG_MAP:
            continue
        lang, ext = _LANG_MAP[lang_raw]
        if counts.get(lang, 0) >= per_lang:
            # Tous les langages cibles sont-ils satisfaits ? si oui on arrete.
            if all(counts.get(l, 0) >= per_lang for (l, _e) in _LANG_MAP.values()):
                break
            continue

        vuln_code = row.get("vulnerable_code")
        if not _valid_code(vuln_code):
            continue
        counts[lang] = counts.get(lang, 0) + 1

        cve = str(row.get("cve_id", "cve"))
        h = str(row.get("hash", ""))[:8]
        cwe = _norm_cwe(row.get("cwe_id"))
        paths = row.get("file_paths") or []
        fname = Path(paths[0]).name if paths else f"vuln{ext}"
        if not Path(fname).suffix:
            fname += ext
        cid = f"{cve}_{h}_{counts[lang]}"

        # --- cas VULNERABLE ---
        d = cases_dir / f"{cid}_bad"
        d.mkdir(parents=True, exist_ok=True)
        (d / fname).write_text(vuln_code, encoding="utf-8", errors="replace")
        labels.append(GroundTruthLabel(
            case_id=f"{cid}_bad", dataset="cvefixes", language=lang,
            repo_path=str(d), is_vulnerable=True,
            file=fname, line_start=None, line_end=None, cwe_id=cwe,
            extra={"cve": cve},
        ))

        # --- cas SAIN (fixed_code) ---
        if include_neg and _valid_code(row.get("fixed_code")):
            d2 = cases_dir / f"{cid}_good"
            d2.mkdir(parents=True, exist_ok=True)
            (d2 / fname).write_text(row["fixed_code"], encoding="utf-8", errors="replace")
            labels.append(GroundTruthLabel(
                case_id=f"{cid}_good", dataset="cvefixes", language=lang,
                repo_path=str(d2), is_vulnerable=False,
                file=fname, line_start=None, line_end=None, cwe_id=cwe,
                extra={"cve": cve},
            ))

    print(f"  [cvefixes] cas vuln par langage : {counts}")
    return labels
