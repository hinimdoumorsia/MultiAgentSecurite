"""Carte de hierarchie CWE pour un matching tolerant.

Probleme : un scanner peut remonter CWE-89 (SQL Injection) la ou le dataset
etiquette CWE-943 (Improper Neutralization in Data Query Logic), son parent.
Penaliser ce cas comme un faux positif serait injuste. On accepte donc un match
si les deux CWE sont identiques OU lies par une relation parent/enfant connue,
OU appartiennent a la meme famille (meme racine).

La table ci-dessous n'est pas exhaustive : elle couvre les CWE les plus frequents
des datasets vises (OWASP Benchmark, Juliet, CVEfixes). Elle est facile a etendre.
"""

from __future__ import annotations

import re

# Parent -> enfants directs (relation "ParentOf" du MITRE, simplifiee).
# Un match est accepte si l'un est ancetre/descendant de l'autre.
_CWE_PARENTS: dict[str, set[str]] = {
    "CWE-74": {"CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-90", "CWE-91", "CWE-94", "CWE-643", "CWE-917", "CWE-943"},
    "CWE-77": {"CWE-78", "CWE-88"},                     # Command Injection
    "CWE-89": {"CWE-564"},                              # SQL Injection
    "CWE-943": {"CWE-89", "CWE-90", "CWE-91", "CWE-643"},  # Data query logic
    "CWE-79": {"CWE-80", "CWE-83", "CWE-87"},           # XSS
    "CWE-22": {"CWE-23", "CWE-36"},                     # Path Traversal
    "CWE-119": {"CWE-120", "CWE-125", "CWE-787", "CWE-416", "CWE-415", "CWE-824"},  # Memory
    "CWE-787": {"CWE-121", "CWE-122", "CWE-124"},       # Out-of-bounds Write
    "CWE-125": {"CWE-126", "CWE-127"},                  # Out-of-bounds Read
    "CWE-310": {"CWE-326", "CWE-327", "CWE-328", "CWE-330"},  # Crypto issues
    "CWE-327": {"CWE-328"},                             # Broken/risky crypto
    "CWE-330": {"CWE-338", "CWE-336", "CWE-337"},       # Weak randomness
    "CWE-200": {"CWE-209", "CWE-532"},                  # Info exposure
    "CWE-345": {"CWE-352", "CWE-918"},                  # Insufficient verif (CSRF, SSRF)
    "CWE-20": {"CWE-22", "CWE-78", "CWE-89", "CWE-79", "CWE-90", "CWE-918"},  # Improper Input Validation (large)
}

# Construit la table enfant -> ancetres (transitive) une seule fois.
def _build_ancestors() -> dict[str, set[str]]:
    ancestors: dict[str, set[str]] = {}

    def collect(node: str, acc: set[str]) -> None:
        for parent, children in _CWE_PARENTS.items():
            if node in children:
                if parent not in acc:
                    acc.add(parent)
                    collect(parent, acc)

    all_nodes = set(_CWE_PARENTS.keys())
    for kids in _CWE_PARENTS.values():
        all_nodes |= kids
    for node in all_nodes:
        acc: set[str] = set()
        collect(node, acc)
        ancestors[node] = acc
    return ancestors


_ANCESTORS = _build_ancestors()


def normalize_cwe(raw: str | int | None) -> str:
    """Normalise vers 'CWE-XXX'. Renvoie 'CWE-Unknown' si non identifiable."""
    if raw is None:
        return "CWE-Unknown"
    if isinstance(raw, int):
        return f"CWE-{raw}"
    s = str(raw).strip().upper()
    m = re.search(r"(\d+)", s)
    if not m:
        return "CWE-Unknown"
    return f"CWE-{m.group(1)}"


def cwe_matches(
    a: str | int | None,
    b: str | int | None,
    mode: str = "family",
    unknown_ok: bool = True,
) -> bool:
    """True si deux CWE sont compatibles.

    mode='exact'  : egalite stricte (apres normalisation).
    mode='family' : egalite OU relation ancetre/descendant connue.
    unknown_ok    : si True, un CWE inconnu d'un cote matche tout (utile quand le
                    matching ligne/fichier est la garde principale). Si False
                    (scoring par categorie type OWASP), un CWE inconnu ne matche pas.
    """
    na, nb = normalize_cwe(a), normalize_cwe(b)
    if na == "CWE-Unknown" or nb == "CWE-Unknown":
        return unknown_ok
    if na == nb:
        return True
    if mode == "exact":
        return False
    # family : l'un est-il ancetre de l'autre ?
    if nb in _ANCESTORS.get(na, set()):
        return True
    if na in _ANCESTORS.get(nb, set()):
        return True
    return False
