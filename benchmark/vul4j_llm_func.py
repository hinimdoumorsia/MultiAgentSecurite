"""Correction Vul4J par PATCH LOCALISÉ (fenêtre + re-splice) — Action 1.

Au lieu d'envoyer le fichier complet (qui dépasse le cap de contexte pour les gros
fichiers -> patch_fail), on envoie au LLM une FENÊTRE autour des lignes modifiées par
le human_patch, et on remplace la plage de lignes exacte par la sortie (déterministe,
pas de git apply, pas de diff LLM). Vérification du fix via VUL4J/testing_results.json.

  python -m MultiAgentSecurite.benchmark.vul4j_llm_func [lo] [hi]   # cases VUL4J-lo..hi

Sorties : results/vul4j_llm_func/<slug>.json + VUL4J_FUNC_COMPARISON.md
"""
from __future__ import annotations
import csv, json, re, subprocess, sys, tempfile, os, urllib.request
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "benchmark"))
from llm_models import MODELS, client_for  # noqa: E402

C = "vul4j"
_CSV = _REPO / "benchmark" / "datasets" / "vul4j" / "dataset" / "vul4j_dataset.csv"
_OUT = _REPO / "benchmark" / "results" / "vul4j_llm_func"
WIN = 40            # lignes de contexte de part et d'autre de la zone modifiée
MAX_WIN_CHARS = 14000
FULL_CAP = 26000    # <= ce seuil : patch FICHIER COMPLET (fiable) ; au-delà : FENÊTRE
SYS = ("You are a security engineer. The following is a contiguous REGION of a Java file "
       "containing a vulnerability. Return the CORRECTED version of THIS REGION only, with the "
       "same surrounding lines, no markdown fences, no explanation, no line numbers.")
SYS_FULL = ("You are a security engineer. Fix ONLY the vulnerability in this Java file. "
            "Preserve package, imports, all other code, signatures and behaviour. "
            "Return the COMPLETE corrected file, no markdown fences, no explanation.")


def dexec(cmd, t=900):
    try:
        p = subprocess.run(["docker", "exec", C, "bash", "-lc", cmd], capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=t)
        return p.returncode, re.sub(r"\x1b\[[0-9;]*m", "", (p.stdout or "") + (p.stderr or ""))
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT"


def commit_files(human_patch):
    """Retourne {filename: patch_text} des .java de src/main du commit de fix."""
    m = re.search(r"github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]+)", human_patch)
    if not m:
        return {}
    owner, repo, sha = m.groups()
    try:
        req = urllib.request.Request(f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}",
                                     headers={"User-Agent": "vul4j"})
        data = json.load(urllib.request.urlopen(req, timeout=30))
    except Exception:
        return {}
    out = {}
    for f in data.get("files", []):
        fn = f["filename"]
        if fn.endswith(".java") and "/test" not in fn and ("src/main" in fn or "/main/" in fn) and f.get("patch"):
            out[fn] = f["patch"]
    return out


def old_range(patch):
    """Plage de lignes (old side) couverte par les hunks : (min_start, max_end)."""
    starts, ends = [], []
    for mm in re.finditer(r"@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@", patch):
        a = int(mm.group(1)); b = int(mm.group(2) or "1")
        starts.append(a); ends.append(a + max(b, 1) - 1)
    if not starts:
        return None
    return (min(starts), max(ends))


def clean(raw):
    s = (raw or "").strip()
    if s.startswith("```"):
        s = s.split("\n", 1)[1] if "\n" in s else s
        s = s.rsplit("```", 1)[0] if "```" in s else s
    return s.strip("\n")


def _llm(cli, model, maxtok, system, user):
    r = cli.chat.completions.create(model=model, messages=[
        {"role": "system", "content": system}, {"role": "user", "content": user}],
        temperature=0.2, max_tokens=max(maxtok, 8192), seed=0)
    return clean(r.choices[0].message.content or "")


def patch_file(cli, model, maxtok, d, fpath, patch, cwe):
    """HYBRIDE : fichier complet si <= FULL_CAP (fiable), sinon fenêtre + re-splice."""
    rc, content = dexec(f"cat {d}/{fpath}")
    if rc != 0 or not content.strip():
        return False, "read_fail"
    # --- petit fichier : fichier complet (mode éprouvé) ---
    if len(content) <= FULL_CAP:
        try:
            corr = _llm(cli, model, maxtok, SYS_FULL,
                        f"Vulnerability {cwe}.\n```java\n{content}\n```")
        except Exception as e:
            return False, f"llm_err:{str(e)[:40]}"
        if not corr:
            return False, "empty"
        new_content = corr
        mode = "full"
    else:
        # --- gros fichier : fenêtre autour des lignes modifiées + re-splice ---
        rng = old_range(patch)
        if not rng:
            return False, "no_hunk"
        lines = content.split("\n"); n = len(lines)
        w0 = max(1, rng[0] - WIN); w1 = min(n, rng[1] + WIN)
        region = "\n".join(lines[w0 - 1:w1])
        if len(region) > MAX_WIN_CHARS:
            c0 = max(1, rng[0] - 10); c1 = min(n, rng[1] + 10)
            w0, w1 = c0, c1; region = "\n".join(lines[w0 - 1:w1])
            if len(region) > MAX_WIN_CHARS:
                return False, "region_too_big"
        try:
            corr = _llm(cli, model, maxtok, SYS,
                        f"Vulnerability {cwe}. Corrected region only:\n```java\n{region}\n```")
        except Exception as e:
            return False, f"llm_err:{str(e)[:40]}"
        if not corr:
            return False, "empty"
        new_content = "\n".join(lines[:w0 - 1] + corr.split("\n") + lines[w1:])
        mode = "window"
    tf = tempfile.NamedTemporaryFile("w", suffix=".java", delete=False, encoding="utf-8")
    tf.write(new_content); tf.close()
    subprocess.run(["docker", "cp", tf.name, f"{C}:{d}/{fpath}"], check=True, capture_output=True)
    os.unlink(tf.name)
    return True, mode


def verify(d):
    """Lit testing_results.json après compile+test. -> FIXED / not_fixed / build_broken."""
    dexec(f"vul4j compile -d {d} 2>&1 | tail -1 && vul4j test -b povs -d {d} 2>&1 | tail -3")
    rc, out = dexec(f"cat {d}/VUL4J/testing_results.json 2>/dev/null")
    try:
        m = json.loads(out)["tests"]["overall_metrics"]
    except Exception:
        return "build_broken"
    if m.get("number_running", 0) == 0:
        return "build_broken"
    return "FIXED" if (m.get("number_failing", 0) + m.get("number_error", 0)) == 0 else "not_fixed"


def main():
    lo = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    hi = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    vulns = [f"VUL4J-{i}" for i in range(lo, hi + 1)]
    rows = {r["vul_id"]: r for r in csv.DictReader(open(_CSV, encoding="utf-8"))}
    files = {v: commit_files(rows[v]["human_patch"]) for v in vulns if v in rows}
    print("fichiers/patch par vuln:", {v: len(f) for v, f in files.items()}, flush=True)
    _OUT.mkdir(parents=True, exist_ok=True)
    summary = {}
    for slug in MODELS:
        try:
            cli, model, desc, maxtok = client_for(slug)
        except Exception as e:
            print(f"### {slug}: clé KO {e}"); continue
        print(f"\n### {slug} ({model})", flush=True)
        res = {}
        for v in vulns:
            if not files.get(v):
                res[v] = "no_files"; print(f"   {v}: no_files", flush=True); continue
            d = f"/tmp/func_{slug.replace('-', '_')}_{v}"
            dexec(f"rm -rf {d}; vul4j checkout --id {v} -d {d}", t=300)
            okall = True
            for fn, patch in files[v].items():
                ok, why = patch_file(cli, model, maxtok, d, fn, patch, rows[v]["cwe_id"])
                if not ok:
                    okall = False; res[v] = f"patch_fail:{why}"; break
            if not okall:
                print(f"   {v}: {res[v]}", flush=True); continue
            res[v] = verify(d)
            print(f"   {v}: {res[v]}", flush=True)
        fixed = sum(1 for s in res.values() if s == "FIXED")
        summary[slug] = {"model": model, "results": res, "fixed": fixed, "total": len(vulns)}
        (_OUT / f"{slug}.json").write_text(json.dumps(summary[slug], indent=2), encoding="utf-8")
        print(f"   => FIX {fixed}/{len(vulns)}", flush=True)
    (_OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print("\n=== écrit:", _OUT / "summary.json", "===")


if __name__ == "__main__":
    main()
