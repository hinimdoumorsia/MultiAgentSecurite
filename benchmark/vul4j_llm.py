"""Comparaison RIGOUREUSE de correction par LLM via Vul4J (tests exécutables).

Pour chaque modèle, on patche les MÊMES vulnérabilités reproduites et on mesure le
taux de fix (le test PoV passe-t-il ?). C'est le vrai « qui corrige le mieux ? ».

  python -m MultiAgentSecurite.benchmark.vul4j_llm

Sorties : results/vul4j_llm/<slug>.json + VUL4J_LLM_COMPARISON.md
"""
from __future__ import annotations
import csv, json, re, subprocess, sys, tempfile, os
from datetime import datetime, timezone
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "benchmark"))
from llm_models import MODELS, client_for, INPUT_CHARS  # noqa: E402

C = "vul4j"
_CSV = _REPO / "benchmark" / "datasets" / "vul4j" / "dataset" / "vul4j_dataset.csv"
_OUT = _REPO / "benchmark" / "results" / "vul4j_llm"
# 12 cas reproductibles (PoV échoue au baseline), validés via VUL4J/testing_results.json
# (cf. vul4j_classify_json.py). Étend l'étude n=4 -> n=12.
VULNS = [f"VUL4J-{i}" for i in range(1, 13)]
# Vul4J = patch FICHIER COMPLET : il faut donner ET récupérer le fichier ENTIER.
# INPUT_CHARS (4000) servait à la compa détection/correction (petits extraits) ;
# ici tronquer casse la compilation (build_broken). On élargit largement.
FILE_CHARS = 26000      # entrée : fichier Java complet (couvre JpegDecoder ~20.7k)
OUT_TOKENS = 8192       # sortie : assez pour renvoyer le fichier entier
SYS = ("You are a security engineer. Fix ONLY the vulnerability in this Java file. "
       "Preserve package, imports, all other code, signatures and behaviour. "
       "Return the COMPLETE corrected file, no markdown fences, no explanation.")


def dexec(cmd, t=600):
    try:
        p = subprocess.run(["docker", "exec", C, "bash", "-lc", cmd], capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=t)
        return p.returncode, re.sub(r"\x1b\[[0-9;]*m", "", (p.stdout or "") + (p.stderr or ""))
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT"


def parse_test(out):
    """nr = nb de tests exécutés ; failing = le PoV échoue encore.
    Vul4J signale l'échec via 'Tests with errors:' (exception) OU 'Failing tests:'
    (assertion) : il faut détecter les deux (sinon faux 'FIXED' sur les échecs
    par assertion). Après patch : FIXED = nr>0 et NON failing."""
    run = re.search(r"running tests:\s*(\d+)", out)
    nr = int(run.group(1)) if run else 0
    failing = ("Failing tests:" in out) or ("Tests with errors" in out) or ("Tests in error" in out)
    return nr, failing


def src_files(human_patch):
    m = re.search(r"github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]+)", human_patch)
    if not m:
        return []
    import urllib.request
    owner, repo, sha = m.groups()
    try:
        req = urllib.request.Request(f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}",
                                     headers={"User-Agent": "vul4j"})
        data = json.load(urllib.request.urlopen(req, timeout=30))
        return [f["filename"] for f in data.get("files", [])
                if f["filename"].endswith(".java") and "/test" not in f["filename"]
                and ("src/main" in f["filename"] or "/main/" in f["filename"])]
    except Exception:
        return []


def clean(raw):
    s = (raw or "").strip()
    if s.startswith("```"):
        s = s.split("\n", 1)[1] if "\n" in s else s
        s = s.rsplit("```", 1)[0] if "```" in s else s
    return s.strip("\n")


def patch_one(cli, model, maxtok, fpath, cwe):
    rc, before = dexec(f"cat {fpath}")
    if rc != 0 or not before.strip():
        return False
    if len(before) > FILE_CHARS:   # ne pas tronquer un gros fichier (patch cassé garanti)
        print(f"      skip {Path(fpath).name}: {len(before)}c > {FILE_CHARS}"); return False
    try:
        r = cli.chat.completions.create(model=model, messages=[
            {"role": "system", "content": SYS},
            {"role": "user", "content": f"Vulnerability {cwe}.\n```java\n{before[:FILE_CHARS]}\n```"}],
            temperature=0.2, max_tokens=max(maxtok, OUT_TOKENS))
        corr = clean(r.choices[0].message.content or "")
    except Exception as e:
        print(f"      patch err: {str(e)[:60]}"); return False
    if not corr:
        return False
    tf = tempfile.NamedTemporaryFile("w", suffix=".java", delete=False, encoding="utf-8")
    tf.write(corr); tf.close()
    subprocess.run(["docker", "cp", tf.name, f"{C}:{fpath}"], check=True, capture_output=True)
    os.unlink(tf.name)
    return True


def main():
    rows = {r["vul_id"]: r for r in csv.DictReader(open(_CSV, encoding="utf-8"))}
    srcs = {v: src_files(rows[v]["human_patch"]) for v in VULNS}
    print("Fichiers source par vuln:", {v: len(f) for v, f in srcs.items()})
    _OUT.mkdir(parents=True, exist_ok=True)
    summary = {}
    for slug in MODELS:
        try:
            cli, model, desc, maxtok = client_for(slug)
        except Exception as e:
            print(f"### {slug}: clé KO {e}"); continue
        print(f"\n### {slug} ({model})")
        res = {}
        for vid in VULNS:
            d = f"/tmp/llm_{slug.replace('-', '_')}_{vid}"
            dexec(f"rm -rf {d}; vul4j checkout --id {vid} -d {d}", t=180)
            ok = all(patch_one(cli, model, maxtok, f"{d}/{f}", rows[vid]["cwe_id"]) for f in srcs[vid]) if srcs[vid] else False
            if not ok:
                res[vid] = "patch_fail"; print(f"   {vid}: patch_fail"); continue
            _, out = dexec(f"vul4j compile -d {d} 2>&1 | tail -1 && vul4j test -b povs -d {d} 2>&1 | tail -5")
            nr, err = parse_test(out)
            st = "build_broken" if nr == 0 else ("FIXED" if not err else "not_fixed")
            res[vid] = st
            print(f"   {vid}: {st}")
        fixed = sum(1 for s in res.values() if s == "FIXED")
        summary[slug] = {"model": model, "results": res, "fixed": fixed, "total": len(VULNS),
                         "fix_rate": round(fixed / len(VULNS), 2)}
        (_OUT / f"{slug}.json").write_text(json.dumps(summary[slug], indent=2), encoding="utf-8")
        print(f"   => FIX {fixed}/{len(VULNS)}")

    # tableau
    lines = ["# Comparaison LLM — Correction RIGOUREUSE (Vul4J, tests exécutables)", "",
             f"_{datetime.now(timezone.utc).isoformat()} | {len(VULNS)} vulns reproduites_", "",
             "| Modèle | Fix-rate | " + " | ".join(VULNS) + " |",
             "|---|---|" + "---|" * len(VULNS)]
    for slug, g in summary.items():
        cells = " | ".join("✅" if g["results"].get(v) == "FIXED" else
                           ("🔧" if g["results"].get(v) == "not_fixed" else "💥") for v in VULNS)
        lines.append(f"| {slug} | **{g['fixed']}/{g['total']}** | {cells} |")
    (_OUT / "VUL4J_LLM_COMPARISON.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\n=== Tableau : {_OUT / 'VUL4J_LLM_COMPARISON.md'} ===")
    for slug, g in summary.items():
        print(f"  {slug:18s} fix {g['fixed']}/{g['total']}")


if __name__ == "__main__":
    main()
