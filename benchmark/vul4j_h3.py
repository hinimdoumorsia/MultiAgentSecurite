"""Action 3 (H3) : mesure des vulnérabilités INTRODUITES par les patches.

Pour chaque patch généré (run patch-localisé, sans ValidatorAgent), on re-scanne le
fichier ORIGINAL (baseline, /tmp/probe_VUL4J_N) et le fichier PATCHÉ (/tmp/func_<slug>_<vid>)
avec Semgrep ; `introduites` = règles présentes dans le patché mais absentes de l'original.
C'est le taux d'introduction SANS validateur (le ValidatorAgent est conçu pour rejeter
ces patches : effet by-design, non quantifié end-to-end ici).

  python -m MultiAgentSecurite.benchmark.vul4j_h3 [slug]
"""
from __future__ import annotations
import csv, json, subprocess, sys, tempfile, os, shutil, collections
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmark"))
from vul4j_llm_func import commit_files, _CSV, C  # noqa: E402

SEMGREP = shutil.which("semgrep")
_OUT = Path(__file__).resolve().parents[1] / "benchmark" / "results" / "vul4j_h3.json"


def cat(path):
    r = subprocess.run(["docker", "exec", C, "bash", "-lc", f"cat {path} 2>/dev/null"],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    return r.stdout


def semgrep_rules(code):
    """Retourne le multiset des check_id détectés par Semgrep sur un fichier Java."""
    if not code.strip():
        return collections.Counter()
    tf = tempfile.NamedTemporaryFile("w", suffix=".java", delete=False, encoding="utf-8")
    tf.write(code); tf.close()
    try:
        r = subprocess.run([SEMGREP, "--config", "auto", "--json", "--quiet", "--timeout", "60", tf.name],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
        data = json.loads(r.stdout or "{}")
        return collections.Counter(x.get("check_id", "?") for x in data.get("results", []))
    except Exception:
        return collections.Counter()
    finally:
        os.unlink(tf.name)


def main():
    slug = sys.argv[1] if len(sys.argv) > 1 else "deepseek-v4"
    fslug = slug.replace("-", "_")
    rows = {r["vul_id"]: r for r in csv.DictReader(open(_CSV, encoding="utf-8"))}
    res_file = Path(__file__).resolve().parents[1] / "benchmark" / "results" / "vul4j_llm_func" / f"{slug}.json"
    statuses = json.loads(res_file.read_text(encoding="utf-8"))["results"]
    n_patch = n_intro = total_intro = 0
    details = []
    for vid, st in statuses.items():
        if st is None or st.startswith("patch_fail") or st in ("no_files", "no_hunk", "read_fail"):
            continue  # pas de patch testable
        i = vid.split("-")[1]
        files = commit_files(rows[vid]["human_patch"])
        intro_here = 0
        for fpath in files:
            orig = cat(f"/tmp/probe_VUL4J_{i}/{fpath}")
            patched = cat(f"/tmp/func_{fslug}_{vid}/{fpath}")
            if not patched.strip():
                continue
            ro, rp = semgrep_rules(orig), semgrep_rules(patched)
            for cid, c in rp.items():
                if c > ro.get(cid, 0):
                    intro_here += c - ro.get(cid, 0)
        n_patch += 1
        if intro_here > 0:
            n_intro += 1
        total_intro += intro_here
        details.append({"vul": vid, "status": st, "introduced": intro_here})
        print(f"  {vid:10s} {st:14s} introduites={intro_here}", flush=True)
    out = {"model": slug, "n_patches": n_patch, "n_with_introduced": n_intro,
           "total_introduced": total_intro,
           "introduction_rate": round(n_intro / n_patch, 3) if n_patch else None,
           "note": "sans ValidatorAgent (patch direct) ; Semgrep --config auto sur Java",
           "details": details}
    _OUT.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"\n=> {slug}: {n_intro}/{n_patch} patches introduisent une alerte Semgrep "
          f"(taux {out['introduction_rate']}), total {total_intro} alertes introduites")
    print("écrit:", _OUT)


if __name__ == "__main__":
    main()
