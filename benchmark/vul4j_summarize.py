"""Synthèse fix-rate Vul4J n=12 : matrice par cas + IC de Wilson (cas évaluables)."""
import json, glob, math

models = {}
for f in sorted(glob.glob("MultiAgentSecurite/benchmark/results/vul4j_llm/*.json")):
    g = json.load(open(f, encoding="utf-8"))
    if "results" in g:
        models[g["model"].split("/")[-1]] = g["results"]

vulns = [f"VUL4J-{i}" for i in range(1, 13)]
excluded = [v for v in vulns if all(models[m].get(v) == "patch_fail" for m in models)]
evaluable = [v for v in vulns if v not in excluded]


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0, c - h), min(1, c + h))


print("Exclus (gros fichiers, patch_fail pour tous):", excluded)
print("Evaluables n=%d:" % len(evaluable), evaluable)
print()
sym = {"FIXED": "F", "not_fixed": ".", "build_broken": "X", "patch_fail": "-"}
print("Matrice (F=fixed . =not_fixed X=build_broken - =patch_fail/exclu):")
print("%-34s " % "modele" + " ".join("%2d" % i for i in range(1, 13)))
for m, res in models.items():
    print("%-34s " % m + "  ".join(sym.get(res.get(v), "?") for v in vulns))
print()
print("%-34s %-7s %-9s %-18s" % ("modele", "FIX/12", "FIX/eval", "Wilson95(eval)"))
rows = []
for m, res in models.items():
    fx12 = sum(1 for v in vulns if res.get(v) == "FIXED")
    ev = [v for v in evaluable if res.get(v) != "patch_fail"]
    fxe = sum(1 for v in ev if res.get(v) == "FIXED")
    lo, hi = wilson(fxe, len(ev))
    rows.append((m, fx12, fxe, len(ev), lo, hi))
for m, fx12, fxe, nev, lo, hi in sorted(rows, key=lambda r: -r[1]):
    print("%-34s %-7s %-9s [%.2f; %.2f]" % (m, "%d/12" % fx12, "%d/%d" % (fxe, nev), lo, hi))

# agrégat global : taux de réussite par tentative évaluable (tous modèles)
tot_fix = sum(r[2] for r in rows)
tot_att = sum(r[3] for r in rows)
lo, hi = wilson(tot_fix, tot_att)
print()
print("GLOBAL (toutes tentatives evaluables): %d/%d = %.2f  Wilson95 [%.2f; %.2f]"
      % (tot_fix, tot_att, tot_fix / tot_att, lo, hi))
