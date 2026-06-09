"""Classe la reproductibilité Vul4J de façon FIABLE via VUL4J/testing_results.json
(source officielle : overall_metrics), au lieu de parser stdout (ambigu).

Lit le JSON déjà écrit par le dernier `vul4j test` dans chaque /tmp/probe_VUL4J_N
(pas de re-test). Un cas est REPRODUCIBLE si, au baseline (code vulnérable),
des tests s'exécutent ET le PoV échoue (failing+error > 0, et pas tout passing).

  python -m MultiAgentSecurite.benchmark.vul4j_classify_json 1 30
"""
from __future__ import annotations
import json, subprocess, sys
from pathlib import Path

_OUT = Path(__file__).resolve().parents[1] / "benchmark" / "results" / "vul4j_probe.json"
C = "vul4j"


def read_metrics(i: int):
    p = f"/tmp/probe_VUL4J_{i}/VUL4J/testing_results.json"
    r = subprocess.run(["docker", "exec", C, "bash", "-lc", f"cat {p} 2>/dev/null"],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    if not r.stdout.strip():
        return None
    try:
        return json.loads(r.stdout)["tests"]["overall_metrics"]
    except Exception:
        return None


def main():
    lo = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    hi = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    valid, results = [], []
    for i in range(lo, hi + 1):
        vid = f"VUL4J-{i}"
        m = read_metrics(i)
        if not m:
            results.append({"vul_id": vid, "status": "no_results_json"}); print(f"  {vid:10s} -> no_results_json", flush=True); continue
        nr = m.get("number_running", 0); npass = m.get("number_passing", 0)
        nfail = m.get("number_failing", 0); nerr = m.get("number_error", 0)
        if nr == 0:
            st = "no_tests"
        elif (nfail + nerr) > 0:
            st = "REPRODUCIBLE"           # PoV échoue au baseline = vuln présente
        else:
            st = "pov_passes_baseline"     # tout passe sans patch -> invalide
        rec = {"vul_id": vid, "status": st, "running": nr, "passing": npass,
               "failing": nfail, "error": nerr}
        results.append(rec)
        print(f"  {vid:10s} -> {'OK VALIDE' if st=='REPRODUCIBLE' else st}"
              f"  (run={nr} pass={npass} fail={nfail} err={nerr})", flush=True)
        if st == "REPRODUCIBLE":
            valid.append(vid)
    _OUT.write_text(json.dumps({"valid": valid, "all": results, "method": "testing_results.json/overall_metrics"}, indent=2), encoding="utf-8")
    print(f"\n=== {len(valid)} cas reproductibles : {valid} ===")
    print(f"écrit : {_OUT}")


if __name__ == "__main__":
    main()
