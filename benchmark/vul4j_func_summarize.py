"""Résumé Action 1 (patch localisé n=30) : fix-rate /30, /évaluables, Wilson, global. Écrit JSON."""
import json, glob, math
from pathlib import Path

R = Path("MultiAgentSecurite/benchmark/results")
M = {}
for f in glob.glob(str(R / "vul4j_llm_func/*.json")):
    g = json.load(open(f, encoding="utf-8"))
    if "results" in g:
        M[g["model"].split("/")[-1]] = g["results"]
vulns = [f"VUL4J-{i}" for i in range(1, 31)]


def nontest(s):
    return s is None or s.startswith("patch_fail") or s in ("no_files", "no_hunk", "read_fail")


def wil(k, n, z=1.96):
    if n == 0:
        return [0, 0]
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0, c - h), 3), round(min(1, c + h), 3)]


excl = [v for v in vulns if all(nontest(M[m].get(v)) for m in M)]
evalset = [v for v in vulns if v not in excl]
out = {"n_models": len(M), "excluded_all": excl, "n_evaluable": len(evalset), "per_model": {}}
tot_fx = tot_ev = 0
for m in M:
    fx = sum(1 for v in vulns if M[m].get(v) == "FIXED")
    ev = [v for v in evalset if not nontest(M[m].get(v))]
    fxe = sum(1 for v in ev if M[m].get(v) == "FIXED")
    tot_fx += fxe; tot_ev += len(ev)
    out["per_model"][m] = {"fixed": fx, "total": 30, "fix_eval": fxe, "n_eval": len(ev),
                           "fix_rate_eval": round(fxe / len(ev), 3) if ev else 0, "wilson_eval": wil(fxe, len(ev))}
out["global_eval"] = {"fixed": tot_fx, "n": tot_ev, "rate": round(tot_fx / tot_ev, 3), "wilson": wil(tot_fx, tot_ev)}
out["fixed_by_any"] = [v for v in vulns if any(M[m].get(v) == "FIXED" for m in M)]
(R / "vul4j_func_summary.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
print(json.dumps(out["global_eval"]), "| évaluables:", out["n_evaluable"], "| exclus:", out["excluded_all"])
