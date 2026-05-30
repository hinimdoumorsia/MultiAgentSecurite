"""Appariement findings <-> verite terrain (piste detection).

Logique par CAS (et non par finding individuel), car les datasets type OWASP
Benchmark fournissent un label par cas (vulnerable / sain). Pour chaque cas :

  - cas VULNERABLE  -> TP si au moins un finding matche la region vuln, sinon FN
  - cas SAIN        -> FP si au moins un finding est remonte, sinon TN

Un finding "matche" un label vulnerable si :
  meme fichier  ET  chevauchement de lignes (+/- tolerance)  ET  CWE compatible.
"""

from __future__ import annotations

from pathlib import PurePosixPath, PureWindowsPath

from harness.schema import AgentFinding, GroundTruthLabel
from harness.cwe_map import cwe_matches


def _norm_path(p: str | None) -> str:
    """Normalise un chemin pour comparaison (separateurs, casse-neutre sur le nom)."""
    if not p:
        return ""
    # Gere les deux types de separateurs quelle que soit la plateforme.
    s = str(p).replace("\\", "/")
    # Compare sur le suffixe le plus parlant (le scanner peut prefixer un chemin absolu).
    return PurePosixPath(s).as_posix().lstrip("./").lower()


def _same_file(label_file: str | None, finding_file: str | None) -> bool:
    lf, ff = _norm_path(label_file), _norm_path(finding_file)
    if not lf or not ff:
        return False
    # Egalite, ou l'un est suffixe de l'autre (chemin absolu vs relatif).
    return lf == ff or lf.endswith("/" + ff) or ff.endswith("/" + lf) or PurePosixPath(lf).name == PurePosixPath(ff).name


def _lines_overlap(
    ls: int | None, le: int | None, fs: int, fe: int, tol: int
) -> bool:
    if ls is None:
        return True  # label sans ligne precise : on matche au niveau fichier
    le = le if le is not None else ls
    fe = fe if fe >= fs else fs
    return (fs - tol) <= le and (fe + tol) >= ls


def finding_matches_label(
    finding: AgentFinding,
    label: GroundTruthLabel,
    line_tol: int = 5,
    cwe_mode: str = "family",
    unknown_ok: bool = True,
) -> bool:
    """True si ce finding couvre la vulnerabilite decrite par le label."""
    if not _same_file(label.file, finding.file):
        return False
    if not _lines_overlap(
        label.line_start, label.line_end, finding.line_start, finding.line_end, line_tol
    ):
        return False
    return cwe_matches(label.cwe_id, finding.cwe_id, mode=cwe_mode, unknown_ok=unknown_ok)


def classify_case(
    label: GroundTruthLabel,
    findings: list[AgentFinding],
    line_tol: int = 5,
    cwe_mode: str = "family",
    scoring: str = "presence",
) -> str:
    """Renvoie 'TP' | 'FP' | 'FN' | 'TN' pour un cas donne.

    IMPORTANT (datasets a depot partage, ex. OWASP) : `findings` peut contenir
    TOUS les findings du projet entier. On ne raisonne donc QUE sur les findings
    qui tombent dans le fichier du cas.

    scoring='presence' (defaut) : un finding securite dans le fichier (de la bonne
        zone/ligne) suffit. CWE inconnu accepte (la garde est fichier/ligne).
    scoring='category' (officiel OWASP) : un finding ne compte que s'il est du
        MEME CWE de categorie que le cas. CWE inconnu => ne compte pas. C'est la
        methode des scorecards OWASP, comparable a la litterature.
    """
    if label.file is not None:
        relevant = [f for f in findings if _same_file(label.file, f.file)]
    else:
        # Cas a depot dedie (ex. synthetique) : tout le depot appartient au cas.
        relevant = findings

    if scoring == "category":
        # Un finding "compte" pour ce cas seulement s'il matche le CWE de categorie.
        counts = any(
            finding_matches_label(f, label, line_tol, cwe_mode, unknown_ok=False)
            if label.is_vulnerable
            else cwe_matches_category(f, label, cwe_mode)
            for f in relevant
        )
    else:  # presence
        if label.is_vulnerable:
            counts = any(
                finding_matches_label(f, label, line_tol, cwe_mode) for f in relevant
            )
        else:
            counts = bool(relevant)

    if label.is_vulnerable:
        return "TP" if counts else "FN"
    return "FP" if counts else "TN"


def cwe_matches_category(finding: AgentFinding, label: GroundTruthLabel, cwe_mode: str) -> bool:
    """Pour un cas sain en scoring 'category' : le finding est-il de la categorie du cas ?"""
    return cwe_matches(label.cwe_id, finding.cwe_id, mode=cwe_mode, unknown_ok=False)
