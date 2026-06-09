"""Sonde de REPRODUCTIBILITÉ Vul4J (préalable à l'extension du fix-rate).

Pour chaque candidat : checkout -> compile -> test PoV au BASELINE (code vulnérable).
Un cas est REPRODUCTIBLE (valide) si les tests s'exécutent ET le PoV échoue
(la vulnérabilité est bien présente avant tout patch). Si le PoV passe déjà au
baseline, ou si le build casse, le cas est REJETÉ (on ne l'invente pas).

  python -m MultiAgentSecurite.benchmark.vul4j_probe 1 30      # sonde VUL4J-1..30

Sortie : results/vul4j_probe.json  (liste des cas valides + raison des rejets).
"""
from __future__ import annotations
import json, re, subprocess, sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_OUT = _REPO / "benchmark" / "results" / "vul4j_probe.json"
C = "vul4j"


def dexec(cmd, t=900):
    try:
        p = subprocess.run(["docker", "exec", C, "bash", "-lc", cmd], capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=t)
        return p.returncode, re.sub(r"\x1b\[[0-9;]*m", "", (p.stdout or "") + (p.stderr or ""))
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT"


def parse_test(out):
    """nr = nb de tests exécutés ; failing = le PoV échoue (vuln présente).
    Vul4J signale l'échec de DEUX façons : 'Tests with errors:' (exception) ET
    'Failing tests:' (assertion). Il faut détecter les deux (bug initial : seul
    le premier était capté -> sous-comptage massif)."""
    run = re.search(r"running tests:\s*(\d+)", out)
    nr = int(run.group(1)) if run else 0
    failing = ("Failing tests:" in out) or ("Tests with errors" in out) or ("Tests in error" in out)
    return nr, failing


def probe(vid: str) -> dict:
    d = f"/tmp/probe_{vid.replace('-', '_')}"
    rc, _ = dexec(f"rm -rf {d}; vul4j checkout --id {vid} -d {d}", t=300)
    if rc != 0:
        return {"vul_id": vid, "status": "checkout_fail"}
    rc, out = dexec(f"vul4j compile -d {d} 2>&1 | tail -2", t=900)
    if "Compile success" not in out and rc != 0:
        return {"vul_id": vid, "status": "compile_fail"}
    _, out = dexec(f"vul4j test -b povs -d {d} 2>&1 | tail -8", t=900)
    nr, err = parse_test(out)
    if nr == 0:
        st = "no_tests"           # impossible de juger -> rejeté
    elif err:
        st = "REPRODUCIBLE"        # PoV échoue au baseline = vuln présente = VALIDE
    else:
        st = "pov_passes_baseline" # déjà vert sans patch -> invalide
    return {"vul_id": vid, "status": st, "tests_run": nr, "pov_fails": err}


def main():
    lo = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    hi = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    cands = [f"VUL4J-{i}" for i in range(lo, hi + 1)]
    results, valid = [], []
    for vid in cands:
        r = probe(vid)
        results.append(r)
        flag = "OK VALIDE" if r["status"] == "REPRODUCIBLE" else r["status"]
        print(f"  {vid:10s} -> {flag}", flush=True)
        if r["status"] == "REPRODUCIBLE":
            valid.append(vid)
    _OUT.parent.mkdir(parents=True, exist_ok=True)
    _OUT.write_text(json.dumps({"valid": valid, "all": results}, indent=2), encoding="utf-8")
    print(f"\n=== {len(valid)} cas reproductibles : {valid} ===")
    print(f"écrit : {_OUT}")


if __name__ == "__main__":
    main()
