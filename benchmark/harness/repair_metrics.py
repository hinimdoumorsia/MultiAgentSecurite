"""Agregation des metriques de correction (repair), par langage + global."""

from __future__ import annotations

from dataclasses import dataclass, field

from MultiAgentSecurite.benchmark.harness.schema import CaseResult


@dataclass
class RepairTally:
    attempted: int = 0        # cas ou l'agent a produit un patch
    valid_diff: int = 0       # diffs s'appliquant proprement
    fixed: int = 0            # vuln supprimee (test PoC passe)
    fixed_measurable: int = 0 # cas ou patch_fixes etait mesurable (PoC dispo)
    regressed: int = 0        # patch cassant un test fonctionnel
    regress_measurable: int = 0

    def add(self, r: CaseResult) -> None:
        if r.patch_valid_diff is None:
            return
        self.attempted += 1
        if r.patch_valid_diff:
            self.valid_diff += 1
        if r.patch_fixes is not None:
            self.fixed_measurable += 1
            if r.patch_fixes:
                self.fixed += 1
        if r.patch_regresses is not None:
            self.regress_measurable += 1
            if r.patch_regresses:
                self.regressed += 1

    def as_dict(self) -> dict:
        return {
            "attempted": self.attempted,
            "valid_diff_rate": _ratio(self.valid_diff, self.attempted),
            "fix_rate": _ratio(self.fixed, self.fixed_measurable),
            "regression_rate": _ratio(self.regressed, self.regress_measurable),
            "fixed": self.fixed,
            "fixed_measurable": self.fixed_measurable,
            "regressed": self.regressed,
        }


def _ratio(num: int, den: int) -> float:
    return round(num / den, 4) if den else 0.0


@dataclass
class RepairReport:
    by_language: dict[str, RepairTally] = field(default_factory=dict)

    def record(self, language: str, result: CaseResult) -> None:
        self.by_language.setdefault(language, RepairTally()).add(result)

    def global_tally(self) -> RepairTally:
        g = RepairTally()
        for t in self.by_language.values():
            g.attempted += t.attempted
            g.valid_diff += t.valid_diff
            g.fixed += t.fixed
            g.fixed_measurable += t.fixed_measurable
            g.regressed += t.regressed
            g.regress_measurable += t.regress_measurable
        return g

    def summary(self) -> dict:
        return {
            "by_language": {lang: t.as_dict() for lang, t in self.by_language.items()},
            "global": self.global_tally().as_dict(),
        }
