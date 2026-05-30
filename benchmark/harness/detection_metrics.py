"""Metriques de detection : precision, rappel, F1, FPR, Youden's J.

Agregation par langage + global (micro = pondere par nb de cas ; macro = moyenne
des langages). IC 95% sur le F1 par bootstrap.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field


@dataclass
class Confusion:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    def add(self, outcome: str) -> None:
        setattr(self, outcome.lower(), getattr(self, outcome.lower()) + 1)

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:  # = TPR = sensibilite
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def fpr(self) -> float:
        d = self.fp + self.tn
        return self.fp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def youden_j(self) -> float:
        """Score officiel OWASP Benchmark : TPR - FPR (dans [-1, 1])."""
        return self.recall - self.fpr

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.fn + self.tn

    def as_dict(self) -> dict:
        return {
            "tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn,
            "total": self.total,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "fpr": round(self.fpr, 4),
            "youden_j": round(self.youden_j, 4),
        }


@dataclass
class DetectionReport:
    by_language: dict[str, Confusion] = field(default_factory=dict)
    # outcomes bruts pour le bootstrap : liste de tuples (langue, outcome)
    _outcomes: list[tuple[str, str]] = field(default_factory=list)

    def record(self, language: str, outcome: str) -> None:
        self.by_language.setdefault(language, Confusion()).add(outcome)
        self._outcomes.append((language, outcome))

    def global_micro(self) -> Confusion:
        g = Confusion()
        for c in self.by_language.values():
            g.tp += c.tp; g.fp += c.fp; g.fn += c.fn; g.tn += c.tn
        return g

    def global_macro(self) -> dict:
        langs = list(self.by_language.values())
        if not langs:
            return {"precision": 0.0, "recall": 0.0, "f1": 0.0, "fpr": 0.0, "youden_j": 0.0}
        n = len(langs)
        return {
            "precision": round(sum(c.precision for c in langs) / n, 4),
            "recall": round(sum(c.recall for c in langs) / n, 4),
            "f1": round(sum(c.f1 for c in langs) / n, 4),
            "fpr": round(sum(c.fpr for c in langs) / n, 4),
            "youden_j": round(sum(c.youden_j for c in langs) / n, 4),
        }

    def f1_confidence_interval(self, samples: int = 1000, seed: int = 0) -> tuple[float, float]:
        """IC 95% du F1 micro-global par bootstrap (reechantillonnage des cas)."""
        outcomes = self._outcomes
        if not outcomes:
            return (0.0, 0.0)
        rng = random.Random(seed)
        n = len(outcomes)
        f1s: list[float] = []
        for _ in range(samples):
            c = Confusion()
            for _ in range(n):
                _, outcome = outcomes[rng.randrange(n)]
                c.add(outcome)
            f1s.append(c.f1)
        f1s.sort()
        lo = f1s[int(0.025 * samples)]
        hi = f1s[int(0.975 * samples)]
        return (round(lo, 4), round(hi, 4))

    def summary(self, bootstrap_samples: int = 1000) -> dict:
        micro = self.global_micro()
        ci_lo, ci_hi = self.f1_confidence_interval(bootstrap_samples)
        return {
            "by_language": {lang: c.as_dict() for lang, c in self.by_language.items()},
            "global_micro": micro.as_dict(),
            "global_macro": self.global_macro(),
            "f1_ci95": [ci_lo, ci_hi],
        }
