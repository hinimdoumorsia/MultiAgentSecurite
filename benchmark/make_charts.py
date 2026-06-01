"""Génère les graphes du benchmark à partir des résultats RÉELS (results/).

Aucune donnée inventée : tout est lu depuis les summary.json / *.json produits par
les runs. Sortie : benchmark/images/*.png (régénérable à tout moment).

  python -m MultiAgentSecurite.benchmark.make_charts
"""
from __future__ import annotations
import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

_REPO = Path(__file__).resolve().parents[1]
_RES = _REPO / "benchmark" / "results"
_IMG = _REPO / "benchmark" / "images"
_IMG.mkdir(parents=True, exist_ok=True)

RUNS = {
    "CVEfixes\n(8 lang)":      _RES / "run_20260531-152036",
    "OWASP +SpotBugs\n(Java)": _RES / "run_20260531-172004",
    "Juliet\n(C/C++)":         _RES / "run_20260531-191017",
}


def _det(run):
    return json.loads((run / "summary.json").read_text(encoding="utf-8"))["detection"]


def chart_detection_by_dataset():
    labels, R, P, F1, Y = [], [], [], [], []
    for name, run in RUNS.items():
        g = _det(run)["global_micro"]
        labels.append(name); R.append(g["recall"]); P.append(g["precision"]); F1.append(g["f1"]); Y.append(g["youden_j"])
    x = range(len(labels)); w = 0.2
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar([i - 1.5 * w for i in x], R, w, label="Rappel")
    ax.bar([i - 0.5 * w for i in x], P, w, label="Précision")
    ax.bar([i + 0.5 * w for i in x], F1, w, label="F1")
    ax.bar([i + 1.5 * w for i in x], Y, w, label="Youden J")
    ax.set_xticks(list(x)); ax.set_xticklabels(labels)
    ax.axhline(0, color="grey", lw=0.7); ax.set_ylim(-0.7, 1.0)
    ax.set_title("Détection par dataset (métriques globales)")
    ax.legend(ncol=4, fontsize=8); ax.grid(axis="y", alpha=0.3)
    fig.tight_layout(); fig.savefig(_IMG / "detection_by_dataset.png", dpi=110); plt.close(fig)


def chart_spotbugs_impact():
    a = _det(_RES / "run_20260531-163500")["global_micro"]   # semgrep seul
    b = _det(_RES / "run_20260531-172004")["global_micro"]   # + spotbugs
    metrics = ["recall", "precision", "f1", "fpr", "youden_j"]
    names = ["Rappel", "Précision", "F1", "FPR", "Youden"]
    x = range(len(metrics)); w = 0.38
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar([i - w / 2 for i in x], [a[m] for m in metrics], w, label="Semgrep seul")
    ax.bar([i + w / 2 for i in x], [b[m] for m in metrics], w, label="Semgrep + SpotBugs")
    ax.set_xticks(list(x)); ax.set_xticklabels(names)
    ax.set_title("OWASP (Java) — impact de SpotBugs/FindSecBugs")
    ax.legend(); ax.grid(axis="y", alpha=0.3); ax.set_ylim(0, 1.0)
    fig.tight_layout(); fig.savefig(_IMG / "owasp_spotbugs_impact.png", dpi=110); plt.close(fig)


def chart_cvefixes_by_lang():
    bl = _det(RUNS["CVEfixes\n(8 lang)"])["by_language"]
    items = sorted(bl.items(), key=lambda kv: -kv[1]["recall"])
    langs = [k for k, _ in items]; rec = [v["recall"] for _, v in items]
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(langs, rec, color="#4285f4")
    ax.set_title("CVEfixes — rappel par langage (détection sémantique)")
    ax.set_ylabel("Rappel"); ax.grid(axis="y", alpha=0.3); ax.set_ylim(0, 0.5)
    for i, v in enumerate(rec):
        ax.text(i, v + 0.005, f"{v:.2f}", ha="center", fontsize=8)
    fig.tight_layout(); fig.savefig(_IMG / "cvefixes_recall_by_lang.png", dpi=110); plt.close(fig)


def _llm(slug, kind):
    p = _RES / "llm_comparison" / slug / f"{kind}_cvefixes.json"
    return json.loads(p.read_text(encoding="utf-8"))["summary"] if p.exists() else None


def chart_llm_correction():
    data = []
    for d in sorted((_RES / "llm_comparison").glob("*/")):
        s = _llm(d.name, "correction")
        if s:
            data.append((d.name, s["avg_similarity"]))
    data.sort(key=lambda x: -x[1])
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.barh([d[0] for d in data][::-1], [d[1] for d in data][::-1], color="#34a853")
    ax.set_title("Comparaison LLM — Correction (similarité au fix humain)")
    ax.set_xlabel("Similarité moyenne"); ax.grid(axis="x", alpha=0.3)
    fig.tight_layout(); fig.savefig(_IMG / "llm_correction.png", dpi=110); plt.close(fig)


def chart_llm_detection():
    data = []
    for d in sorted((_RES / "llm_comparison").glob("*/")):
        s = _llm(d.name, "detection")
        if s:
            data.append((d.name, s["recall"], s["youden"]))
    data.sort(key=lambda x: -x[1])
    labels = [d[0] for d in data]; R = [d[1] for d in data]; Y = [d[2] for d in data]
    x = range(len(labels)); w = 0.38
    fig, ax = plt.subplots(figsize=(9, 4.5))
    ax.bar([i - w / 2 for i in x], R, w, label="Rappel")
    ax.bar([i + w / 2 for i in x], Y, w, label="Youden J")
    ax.set_xticks(list(x)); ax.set_xticklabels(labels, rotation=20, ha="right", fontsize=8)
    ax.axhline(0, color="grey", lw=0.7)
    ax.set_title("Comparaison LLM — Détection sémantique (CVEfixes)")
    ax.legend(); ax.grid(axis="y", alpha=0.3)
    fig.tight_layout(); fig.savefig(_IMG / "llm_detection.png", dpi=110); plt.close(fig)


def main():
    for fn in (chart_detection_by_dataset, chart_spotbugs_impact, chart_cvefixes_by_lang,
               chart_llm_correction, chart_llm_detection):
        try:
            fn(); print(f"  OK {fn.__name__}")
        except Exception as e:
            print(f"  KO {fn.__name__}: {e}")
    print("Images:", sorted(p.name for p in _IMG.glob("*.png")))


if __name__ == "__main__":
    main()
