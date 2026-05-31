"""Adapters de datasets : chacun charge un dataset -> liste[GroundTruthLabel].

Pour ajouter un dataset : creer un module exposant `load(cfg: dict) -> list[GroundTruthLabel]`
et l'enregistrer dans ADAPTERS ci-dessous (clef = champ `adapter` du config.yaml).
"""

from __future__ import annotations

from MultiAgentSecurite.benchmark.harness.adapters import cvefixes, owasp
from MultiAgentSecurite.benchmark.harness.adapters import synthetic

ADAPTERS = {
    "synthetic": synthetic.load,
    "owasp": owasp.load,
    "cvefixes": cvefixes.load,
    # "juliet": juliet.load,      # a implementer
    # "vul4j": vul4j.load,        # a implementer
}


def get_adapter(name: str):
    if name not in ADAPTERS:
        raise KeyError(
            f"Adapter '{name}' inconnu. Disponibles : {sorted(ADAPTERS)}"
        )
    return ADAPTERS[name]
