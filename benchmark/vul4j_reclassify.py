"""Re-classe les cas Vul4J déjà checkout (/tmp/probe_VUL4J_N) avec le parseur CORRIGÉ.
Ne re-fait PAS checkout/compile : relance seulement le test PoV au baseline.

  python -m MultiAgentSecurite.benchmark.vul4j_reclassify 1 30
"""
from __future__ import annotations
import json, sys
from pathlib import Path
from MultiAgentSecurite.benchmark.vul4j_probe import dexec, parse_test

_OUT = Path(__file__).resolve().parents[1] / "benchmark" / "results" / "vul4j_probe.json"


def main():
    lo = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    hi = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    valid, results = [], []
    for i in range(lo, hi + 1):
        vid = f"VUL4J-{i}"
        d = f"/tmp/probe_VUL4J_{i}"
        rc, _ = dexec(f"test -d {d} && echo OK", t=30)
        if "OK" not in _:
            results.append({"vul_id": vid, "status": "dir_absent"}); print(f"  {vid:10s} -> dir_absent", flush=True); continue
        _, out = dexec(f"vul4j test -b povs -d {d} 2>&1 | tail -8", t=900)
        nr, failing = parse_test(out)
        if nr == 0:
            st = "no_tests"
        elif failing:
            st = "REPRODUCIBLE"
        else:
            st = "pov_passes_baseline"
        results.append({"vul_id": vid, "status": st, "tests_run": nr, "pov_fails": failing})
        print(f"  {vid:10s} -> {'OK VALIDE' if st=='REPRODUCIBLE' else st}", flush=True)
        if st == "REPRODUCIBLE":
            valid.append(vid)
    _OUT.write_text(json.dumps({"valid": valid, "all": results}, indent=2), encoding="utf-8")
    print(f"\n=== {len(valid)} cas reproductibles : {valid} ===")
    print(f"écrit : {_OUT}")


if __name__ == "__main__":
    main()
