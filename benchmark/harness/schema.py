"""Schemas normalises partages par tous les datasets et toutes les metriques.

Toute la chaine (adapters -> agent -> matching -> metriques) parle ces 3 objets,
ce qui permet de brancher n'importe quel dataset ou n'importe quel outil concurrent
(Copilot, Claude Code, Semgrep nu...) sans toucher au coeur du harness.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class GroundTruthLabel:
    """Une verite terrain : un cas etiquete provenant d'un dataset.

    Un cas peut etre vulnerable (is_vulnerable=True, avec localisation + CWE)
    ou un negatif propre (is_vulnerable=False) pour mesurer les faux positifs.
    """
    case_id: str                 # identifiant unique du cas dans le dataset
    dataset: str                 # nom du dataset source (owasp, juliet, vul4j...)
    language: str                # python, java, c, cpp, go, php, javascript, typescript...
    repo_path: str               # dossier a scanner (ce qu'on passe a l'agent comme repo_root)
    is_vulnerable: bool          # True = vuln connue ; False = cas sain (negatif)

    # Localisation (uniquement si is_vulnerable=True)
    file: str | None = None              # chemin relatif a repo_path
    line_start: int | None = None
    line_end: int | None = None
    cwe_id: str | None = None            # ex: "CWE-89"

    # Piste correction (repair) : commandes de test executables
    vuln_test_cmd: str | None = None         # test qui ECHOUE si la vuln est presente (PoC)
    functional_test_cmd: str | None = None   # tests fonctionnels qui doivent rester verts

    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentFinding:
    """Une vulnerabilite remontee par l'agent (extraite de report['vulnerabilities']).

    Le meme schema sert pour un outil concurrent : il suffit qu'un run_<tool>.py
    ressorte une liste[AgentFinding].
    """
    file: str                    # chemin relatif a repo_path
    line_start: int
    line_end: int
    cwe_id: str                  # ex: "CWE-89" ou "CWE-Unknown"
    severity: str = "medium"
    cvss: float = 0.0
    patch_applied: bool = False
    patch_diff: str | None = None
    title: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_report_dict(cls, d: dict[str, Any]) -> "AgentFinding":
        """Construit depuis le format de report.py (_vuln_to_dict)."""
        lines = d.get("lines", [0, 0]) or [0, 0]
        line_start = lines[0] if len(lines) > 0 else 0
        line_end = lines[1] if len(lines) > 1 else line_start
        return cls(
            file=d.get("file", "") or "",
            line_start=int(line_start or 0),
            line_end=int(line_end or 0),
            cwe_id=d.get("cwe_id", "CWE-Unknown") or "CWE-Unknown",
            severity=d.get("severity", "medium") or "medium",
            cvss=float(d.get("cvss_score", 0.0) or 0.0),
            patch_applied=bool(d.get("patch_applied", False)),
            patch_diff=d.get("patch_diff"),
            title=d.get("title", "") or "",
            raw=d,
        )


@dataclass
class CaseResult:
    """Resultat de l'agent sur UN cas, pour UNE repetition (run)."""
    case_id: str
    dataset: str
    language: str
    run_index: int
    findings: list[AgentFinding] = field(default_factory=list)
    duration_sec: float = 0.0
    llm_calls: int = 0
    error: str | None = None

    # Renseignes apres matching (detection)
    is_true_positive: bool | None = None    # pour un cas vulnerable : la vuln a-t-elle ete trouvee ?
    flagged: bool | None = None             # le cas a-t-il ete flagge (>=1 finding) ?

    # Renseignes apres verification (repair)
    patch_fixes: bool | None = None         # le patch fait disparaitre la vuln (test vuln passe)
    patch_regresses: bool | None = None     # le patch casse un test fonctionnel
    patch_valid_diff: bool | None = None    # le diff s'applique proprement
