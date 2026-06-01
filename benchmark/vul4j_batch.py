"""Benchmark CORRECTION rigoureux via Vul4J (tests exécutables, mode B).

Pour chaque vulnérabilité :
  1. checkout (version vulnérable) dans le conteneur Docker `vul4j`.
  2. baseline : compile + test -> confirme que la vuln se reproduit (test PoV échoue,
     build OK). Sinon le cas est ignoré (non reproductible / build cassé).
  3. récupère les fichiers SOURCE modifiés par le fix humain (API GitHub).
  4. notre agent (DeepSeek V4, fichier complet) patche chacun -> docker cp.
  5. compile + test -> classe : FIXED (PoV passe, build OK) / NOT_FIXED (PoV échoue
     encore) / BUILD_BROKEN (notre patch casse la compilation -> 0 test).

  python -m MultiAgentSecurite.benchmark.vul4j_batch --ids VUL4J-1 VUL4J-3 ...
"""
from __future__ import annotations
import argparse, csv, json, re, subprocess, sys, tempfile, os, urllib.request
from datetime import datetime, timezone
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))
from llm.client import LLMClient  # noqa: E402

C = "vul4j"
_MODEL = "deepseek-v4-flash"
_CSV = _REPO / "benchmark" / "datasets" / "vul4j" / "dataset" / "vul4j_dataset.csv"
_OUT = _REPO / "benchmark" / "results"
SYS_PROMPT = ("You are a security engineer. Fix ONLY the vulnerability in this Java file. "
              "Preserve package, imports, all other code, signatures and behaviour. "
              "Return the COMPLETE corrected file, no markdown fences, no explanation.")


def dexec(cmd, t=900):
    try:
        p = subprocess.run(["docker", "exec", C, "bash", "-lc", cmd], capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=t)
        return p.returncode, re.sub(r"\x1b\[[0-9;]*m", "", (p.stdout or "") + (p.stderr or ""))
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT"


def parse_test(out):
    run = re.search(r"running tests:\s*(\d+)", out)
    pas = re.search(r"passing tests:\s*(\d+)", out)
    nr = int(run.group(1)) if run else 0
    npass = int(pas.group(1)) if pas else 0
    has_err = "Tests with errors" in out
    return nr, npass, has_err


def src_files(human_patch):
    m = re.search(r"github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]+)", human_patch)
    if not m:
        return []
    owner, repo, sha = m.groups()
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "vul4j-bench"})
        data = json.load(urllib.request.urlopen(req, timeout=30))
        return [f["filename"] for f in data.get("files", [])
                if f["filename"].endswith(".java") and "/test" not in f["filename"]
                and ("src/main" in f["filename"] or "/main/" in f["filename"])]
    except Exception as e:
        print(f"    (github API KO: {e})")
        return []


def clean(raw):
    s = (raw or "").strip()
    if s.startswith("```"):
        s = s.split("\n", 1)[1] if "\n" in s else s
        s = s.rsplit("```", 1)[0] if "```" in s else s
    return s.strip("\n")


def patch_file(ds, path_in_container, cwe):
    rc, before = dexec(f"cat {path_in_container}")
    if rc != 0 or not before.strip():
        return False
    r = ds.client.chat.completions.create(
        model=_MODEL, messages=[{"role": "system", "content": SYS_PROMPT},
        {"role": "user", "content": f"Vulnerability {cwe}. Fix this file.\n```java\n{before[:13000]}\n```"}],
        temperature=0.2, max_tokens=8192)
    corr = clean(r.choices[0].message.content or "")
    if not corr:
        return False
    tf = tempfile.NamedTemporaryFile("w", suffix=".java", delete=False, encoding="utf-8")
    tf.write(corr); tf.close()
    subprocess.run(["docker", "cp", tf.name, f"{C}:{path_in_container}"], check=True, capture_output=True)
    os.unlink(tf.name)
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ids", nargs="+", required=True)
    args = ap.parse_args()
    rows = {r["vul_id"]: r for r in csv.DictReader(open(_CSV, encoding="utf-8"))}
    llm = LLMClient()
    ds = next(e for e in llm._strong if "deepseek" in e.label)
    print(f"== Vul4J batch | modele {_MODEL} | {len(args.ids)} vulns ==\n")

    records = []
    for vid in args.ids:
        r = rows.get(vid)
        if not r:
            print(f"{vid}: inconnu"); continue
        cwe = r["cwe_id"]; d = f"/tmp/b_{vid}"
        print(f"--- {vid} ({r['repo_slug']}, {cwe}) ---")
        dexec(f"rm -rf {d}; vul4j checkout --id {vid} -d {d}")
        # baseline
        _, out = dexec(f"vul4j compile -d {d} 2>&1 | tail -1 && echo X && vul4j test -b povs -d {d} 2>&1 | tail -6")
        nr, npass, err = parse_test(out)
        if nr == 0:
            print(f"  baseline: BUILD KO (projet ne compile pas) -> ignoré"); records.append({"id": vid, "status": "baseline_build_fail"}); continue
        if not err:
            print(f"  baseline: PoV passe déjà ({npass}/{nr}) -> non reproductible, ignoré"); records.append({"id": vid, "status": "no_reproduce"}); continue
        print(f"  baseline OK: vuln reproduite ({npass}/{nr}, PoV échoue)")
        # patch
        files = src_files(r["human_patch"])
        if not files:
            print(f"  pas de fichier source identifié -> ignoré"); records.append({"id": vid, "status": "no_src_file"}); continue
        print(f"  fichiers à patcher: {files}")
        ok = all(patch_file(ds, f"{d}/{f}", cwe) for f in files)
        if not ok:
            print(f"  patch non généré -> ignoré"); records.append({"id": vid, "status": "patch_fail"}); continue
        # re-test
        _, out2 = dexec(f"vul4j compile -d {d} 2>&1 | tail -1 && echo X && vul4j test -b povs -d {d} 2>&1 | tail -6")
        nr2, npass2, err2 = parse_test(out2)
        if nr2 == 0:
            status = "build_broken"
        elif not err2:
            status = "FIXED"
        else:
            status = "not_fixed"
        print(f"  APRÈS patch: {npass2}/{nr2} (erreurs={err2}) -> {status}")
        records.append({"id": vid, "status": status, "before": f"{npass}/{nr}", "after": f"{npass2}/{nr2}"})

    # synthèse
    repro = [r for r in records if r["status"] in ("FIXED", "not_fixed", "build_broken")]
    fixed = [r for r in records if r["status"] == "FIXED"]
    print(f"\n=== SYNTHÈSE Vul4J ===")
    print(f"vulns tentées: {len(args.ids)} | reproduites: {len(repro)} | FIXÉES: {len(fixed)}")
    if repro:
        print(f"TAUX DE FIX (sur reproduites): {len(fixed)}/{len(repro)} = {len(fixed)/len(repro):.0%}")
    from collections import Counter
    print("détail statuts:", dict(Counter(r["status"] for r in records)))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    outdir = _OUT / f"vul4j_{stamp}"; outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "results.json").write_text(json.dumps(records, indent=2), encoding="utf-8")
    print(f"-> {outdir}")


if __name__ == "__main__":
    main()
