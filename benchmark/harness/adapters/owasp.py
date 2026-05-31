"""Adapter OWASP Benchmark (Java) — la reference detection SAST.

Le projet (OWASP/BenchmarkJava) est UN gros projet Maven : on ne scanne pas
chaque test isolement, on scanne tout le projet UNE fois puis on classe chaque
cas via expectedresults-1.2.csv. Tous les labels partagent donc le meme
`repo_path` ; le runner ne lance l'agent qu'une seule fois par repo_path et
reutilise les findings (voir runner.py, cache par repo_path).

CSV attendu (1 ligne par cas) :
    name, category, real vulnerability, cwe
    BenchmarkTest00001, pathtraver, true, 22

`real vulnerability` = true  -> cas vulnerable
                     = false -> cas sain (sert a mesurer les faux positifs)
La localisation precise (ligne) n'est pas fournie -> matching au niveau fichier.
"""

from __future__ import annotations

import csv
import os
import shutil
from pathlib import Path

from MultiAgentSecurite.benchmark.harness.schema import GroundTruthLabel

_TESTCODE_REL = "src/main/java/org/owasp/benchmark/testcode"
_CLASSES_REL = "target/classes/org/owasp/benchmark/testcode"


def _parse_rows(csv_path: Path) -> list[tuple[str, str, bool, str]]:
    """Renvoie (name, category, is_vulnerable, cwe_id) pour chaque cas du CSV."""
    rows: list[tuple[str, str, bool, str]] = []
    with csv_path.open(encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if not row or row[0].strip().startswith("#"):
                continue
            if row[0].strip().lower() == "name":
                continue
            if len(row) < 4:
                continue
            name = row[0].strip()
            category = row[1].strip()
            real = row[2].strip().lower() in ("true", "1", "yes")
            cwe_raw = row[3].strip()
            cwe_id = f"CWE-{cwe_raw}" if cwe_raw.isdigit() else cwe_raw
            rows.append((name, category, real, cwe_id))
    return rows


def _build_subset(base: Path, rows: list, limit: int) -> tuple[Path, list]:
    """Selectionne un sous-ensemble EQUILIBRE (moitie vuln / moitie sain) et copie
    les .java correspondants dans un dossier dedie, scanne en isolation.

    Selection deterministe (tri par nom) -> reproductible sans graine.
    """
    vuln = [r for r in rows if r[2]]
    safe = [r for r in rows if not r[2]]
    vuln.sort(key=lambda r: r[0])
    safe.sort(key=lambda r: r[0])
    half = max(1, limit // 2)
    chosen = vuln[:half] + safe[: limit - len(vuln[:half])]

    subset = base.parent / f"_subset_{limit}"
    dest_dir = subset / _TESTCODE_REL
    if dest_dir.exists():
        shutil.rmtree(subset)
    dest_dir.mkdir(parents=True, exist_ok=True)

    src_dir = base / _TESTCODE_REL
    # .class compiles (pour SpotBugs) : copies si le projet a ete build (mvn compile).
    src_classes = base / _CLASSES_REL
    dest_classes = subset / _CLASSES_REL
    classes_available = src_classes.exists()
    if classes_available:
        dest_classes.mkdir(parents=True, exist_ok=True)

    kept = []
    for name, category, real, cwe_id in chosen:
        src_file = src_dir / f"{name}.java"
        if not src_file.exists():
            continue
        shutil.copy2(src_file, dest_dir / f"{name}.java")
        # Copie .class + classes internes (Name$1.class, etc.) pour SpotBugs.
        if classes_available:
            for cls in src_classes.glob(f"{name}.class"):
                shutil.copy2(cls, dest_classes / cls.name)
            for cls in src_classes.glob(f"{name}$*.class"):
                shutil.copy2(cls, dest_classes / cls.name)
        kept.append((name, category, real, cwe_id))

    # auxclasspath = toutes les classes compilees (helpers, deps) pour une analyse
    # complete par SpotBugs sans les analyser comme cibles. Lu par SpotBugsTool.
    if classes_available:
        os.environ["SPOTBUGS_AUXCLASSPATH"] = str(base / "target" / "classes")

    return subset, kept


def load(cfg: dict) -> list[GroundTruthLabel]:
    base = Path(cfg["_repo_root"]) / cfg["path"]
    csv_name = cfg.get("expected_results", "expectedresults-1.2.csv")
    csv_path = base / csv_name
    if not csv_path.exists():
        raise FileNotFoundError(
            f"OWASP expected results introuvable : {csv_path}\n"
            f"Cloner OWASP/BenchmarkJava dans {base} d'abord."
        )

    rows = _parse_rows(csv_path)

    # Echantillonnage optionnel : config datasets.owasp.limit = N (0/absent -> tout).
    limit = int(cfg.get("limit", 0) or 0)
    if limit and limit < len(rows):
        repo_root, rows = _build_subset(base, rows, limit)
    else:
        repo_root = base

    labels: list[GroundTruthLabel] = []
    for name, category, real, cwe_id in rows:
        test_file = f"{_TESTCODE_REL}/{name}.java"
        labels.append(
            GroundTruthLabel(
                case_id=name,
                dataset="owasp",
                language="java",
                repo_path=str(repo_root),       # subset ou projet complet
                is_vulnerable=real,
                file=test_file,
                line_start=None,                # pas de ligne fournie -> match fichier
                line_end=None,
                cwe_id=cwe_id,                  # CWE de categorie, meme pour les cas sains
                extra={"category": category},
            )
        )
    return labels
