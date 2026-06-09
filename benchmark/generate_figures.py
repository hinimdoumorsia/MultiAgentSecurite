"""
Generate all 7 publication-quality figures for rapport_final.tex
Run from the project root:
    python -m MultiAgentSecurite.benchmark.generate_figures
Or directly:
    python MultiAgentSecurite/benchmark/generate_figures.py
Outputs go to MultiAgentSecurite/benchmark/images/
"""
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

plt.rcParams.update({
    'font.family': 'DejaVu Sans',
    'font.size': 10,
    'axes.labelsize': 10,
    'axes.titlesize': 10,
    'xtick.labelsize': 9,
    'ytick.labelsize': 9,
    'legend.fontsize': 9,
    'figure.dpi': 200,
    'savefig.dpi': 200,
    'savefig.bbox': 'tight',
    'savefig.pad_inches': 0.05,
})

_HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(_HERE, 'images') + os.sep
os.makedirs(OUT, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# FIGURE 1: Detection by dataset (summary)
# ─────────────────────────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(6.5, 3.5))
datasets = ['OWASP\n(synthetic)', 'Juliet\n(NIST)', 'CVEfixes\n(real)']
recall = [0.96, 0.81, 0.24]
youden = [0.44, 0.07, -0.55]
x = np.arange(len(datasets))
w = 0.35
b1 = ax.bar(x - w/2, recall, w, label='Recall', color='#2980b9', edgecolor='white')
b2 = ax.bar(x + w/2, youden, w, label='Youden J', color='#e67e22', edgecolor='white')
ax.axhline(0, color='black', linewidth=0.8, linestyle='--')
ax.set_xticks(x); ax.set_xticklabels(datasets)
ax.set_ylabel('Value'); ax.set_title('Detection performance by dataset (MAS full pipeline)')
ax.legend(loc='upper right')
ax.set_ylim(-0.8, 1.15)
for bar in b1:
    ax.annotate(f'{bar.get_height():.2f}', xy=(bar.get_x()+bar.get_width()/2, bar.get_height()+0.02), ha='center', fontsize=7)
for bar in b2:
    v = bar.get_height()
    ax.annotate(f'{v:.2f}', xy=(bar.get_x()+bar.get_width()/2, v + (0.02 if v >= 0 else -0.07)), ha='center', fontsize=7)
plt.tight_layout()
plt.savefig(OUT + 'detection_by_dataset.png')
plt.close()
print("Figure 1 done")

# ─────────────────────────────────────────────────────────────────────────────
# FIGURE 2: OWASP SpotBugs impact
# ─────────────────────────────────────────────────────────────────────────────
fig, axes = plt.subplots(1, 2, figsize=(6, 3))
metrics = ['Recall', 'Precision', 'F1', 'FPR', 'Youden J']
semgrep = [0.79, 0.67, 0.72, 0.42, 0.37]
mas = [0.96, 0.66, 0.78, 0.53, 0.44]
x = np.arange(len(metrics))
w = 0.35
ax = axes[0]
ax.bar(x - w/2, semgrep, w, label='Semgrep alone', color='#95a5a6')
ax.bar(x + w/2, mas, w, label='MAS full', color='#2980b9')
ax.set_xticks(x); ax.set_xticklabels(metrics, fontsize=7)
ax.set_title('OWASP: Semgrep vs MAS'); ax.legend(fontsize=7)
ax.set_ylim(0, 1.1)

ax2 = axes[1]
categories = ['TP\n+243', 'FN\n-243', 'FPR\n+11pts']
vals = [243, -243, 0.11]
colors = ['#27ae60', '#e74c3c', '#e67e22']
ax2.bar(categories, [abs(v) for v in vals], color=colors, edgecolor='white')
ax2.set_title("Delta from SpotBugs addition"); ax2.set_ylabel('Absolute value')
plt.tight_layout()
plt.savefig(OUT + 'owasp_spotbugs_impact.png')
plt.close()
print("Figure 2 done")

# ─────────────────────────────────────────────────────────────────────────────
# FIGURE 3: CVEfixes recall by language
# ─────────────────────────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(6.5, 3.5))
langs = ['Python', 'C', 'Go', 'Java', 'JavaScript']
recall_lang = [0.32, 0.30, 0.28, 0.26, 0.08]
colors_lang = ['#3498db', '#2ecc71', '#9b59b6', '#e74c3c', '#f39c12']
bars = ax.bar(langs, recall_lang, color=colors_lang, edgecolor='white', width=0.6)
ax.axhline(0.24, color='black', linestyle='--', linewidth=1, label='Global recall (0.24)')
for bar in bars:
    ax.annotate(f'{bar.get_height():.2f}', xy=(bar.get_x()+bar.get_width()/2, bar.get_height()+0.005), ha='center', fontsize=8)
ax.set_ylabel('Recall'); ax.set_title('CVEfixes — Recall by language (n=798 cases)')
ax.legend(); ax.set_ylim(0, 0.42)
plt.tight_layout()
plt.savefig(OUT + 'cvefixes_recall_by_lang.png')
plt.close()
print("Figure 3 done")

# ─────────────────────────────────────────────────────────────────────────────
# FIGURE 4: LLM semantic ablation
# ─────────────────────────────────────────────────────────────────────────────
fig, axes = plt.subplots(1, 2, figsize=(6, 3))
ax = axes[0]
configs_o = ['SAST+LLM', 'SAST only']
r_o = [0.96, 0.96]; f1_o = [0.78, 0.78]; j_o = [0.44, 0.44]
x = np.arange(2); w = 0.25
ax.bar(x - w, r_o, w, label='R', color='#3498db')
ax.bar(x, f1_o, w, label='F1', color='#2ecc71')
ax.bar(x + w, j_o, w, label='J', color='#e67e22')
ax.set_xticks(x); ax.set_xticklabels(configs_o, fontsize=8)
ax.set_title('LLM Ablation — OWASP'); ax.legend(fontsize=7); ax.set_ylim(0, 1.15)
ax.text(0.5, 0.5, 'LLM adds nothing\non synthetic data', ha='center', va='center',
        fontsize=7, color='gray', transform=ax.transAxes)

ax2 = axes[1]
configs_c = ['SAST+LLM', 'SAST only']
r_c = [0.24, 0.002]; f1_c = [0.24, 0.005]
ax2.bar(x - w, r_c, w, label='R', color='#3498db')
ax2.bar(x, f1_c, w, label='F1', color='#2ecc71')
ax2.set_xticks(x); ax2.set_xticklabels(configs_c, fontsize=8)
ax2.set_title('LLM Ablation — CVEfixes'); ax2.legend(fontsize=7)
ax2.annotate('0.002→0.24\n(x120)', xy=(0.5, 0.17), ha='center', fontsize=7,
             color='#2980b9', fontweight='bold')
plt.tight_layout()
plt.savefig(OUT + 'ablation_llm.png')
plt.close()
print("Figure 4 done")

# ─────────────────────────────────────────────────────────────────────────────
# FIGURE 5: LLM detection comparison — 6 primary models (Youden J, n=120)
# ─────────────────────────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(6, 3.2))
models = ['llama-3.3-70b', 'gpt-oss-120b', 'deepseek-v3', 'llama-4-maverick', 'qwen3-coder', 'nemotron-49b']
youden_vals = [0.15, -0.09, -0.15, -0.17, -0.17, -0.35]
colors_m = ['#27ae60' if v > 0 else '#e74c3c' for v in youden_vals]
bars = ax.barh(models, youden_vals, color=colors_m, edgecolor='white', height=0.6)
ax.axvline(0, color='black', linewidth=0.8)
for bar, v in zip(bars, youden_vals):
    ax.text(v + (0.01 if v >= 0 else -0.01), bar.get_y() + bar.get_height()/2,
            f'{v:+.2f}', va='center', ha='left' if v >= 0 else 'right', fontsize=8)
ax.set_xlabel('Youden J'); ax.set_title('Six-LLM comparison — Semantic detection (n=120 CVEfixes cases)')
ax.set_xlim(-0.5, 0.3)
green_p = mpatches.Patch(color='#27ae60', label='Youden > 0 (discriminant)')
red_p = mpatches.Patch(color='#e74c3c', label='Youden < 0 (non-discriminant)')
ax.legend(handles=[green_p, red_p], fontsize=7)
plt.tight_layout()
plt.savefig(OUT + 'llm_detection.png')
plt.close()
print("Figure 5 done")

# ─────────────────────────────────────────────────────────────────────────────
# FIGURE 6: LLM correction — textual similarity vs PoV fix-rate (n=183)
# ─────────────────────────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(6, 3.2))
models_s = ['deepseek-v3', 'qwen3-coder', 'llama-4-maverick', 'nemotron-49b', 'llama-3.3-70b', 'gpt-oss-120b']
similarity = [0.29, 0.35, 0.38, 0.27, 0.31, 0.16]
fixrate = [0.246, 0.175, 0.055, 0.045, 0.055, 0.149]
x = np.arange(len(models_s)); w = 0.35
ax.bar(x - w/2, similarity, w, label='Textual similarity', color='#95a5a6', alpha=0.8)
ax.bar(x + w/2, fixrate, w, label='PoV fix-rate (n=183)', color='#e74c3c', alpha=0.9)
ax.set_xticks(x); ax.set_xticklabels(models_s, fontsize=7, rotation=15, ha='right')
ax.set_ylabel('Score / rate'); ax.set_title('Repair: textual similarity vs. PoV executable tests')
ax.legend(fontsize=8)
ax.annotate('similarity overestimates\nreal repair capability', xy=(2, 0.38), fontsize=7,
            color='gray', ha='center')
plt.tight_layout()
plt.savefig(OUT + 'llm_correction.png')
plt.close()
print("Figure 6 done")

# ─────────────────────────────────────────────────────────────────────────────
# FIGURE 7: Vul4J fix-rate per LLM with Wilson 95% CI (n=183)
# ─────────────────────────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(6, 3.5))
models_v = ['deepseek-v3', 'qwen3-coder', 'gpt-oss-120b', 'llama-3.3-70b', 'llama-4-maverick', 'nemotron-49b']
n_fix = [45, 32, 23, 10, 10, 7]
n_eval = [183, 183, 154, 183, 183, 154]
rates = [f / n for f, n in zip(n_fix, n_eval)]


def wilson_ci(k, n, z=1.96):
    p = k / n
    denom = 1 + z**2 / n
    center = (p + z**2 / (2 * n)) / denom
    margin = z * np.sqrt(p * (1 - p) / n + z**2 / (4 * n**2)) / denom
    return max(0, center - margin), min(1, center + margin)


ci_low = []; ci_high = []
for k, n in zip(n_fix, n_eval):
    lo, hi = wilson_ci(k, n)
    ci_low.append(lo); ci_high.append(hi)

err_low = [r - lo for r, lo in zip(rates, ci_low)]
err_high = [hi - r for r, hi in zip(rates, ci_high)]

colors_v = ['#2980b9', '#27ae60', '#8e44ad', '#e67e22', '#e74c3c', '#7f8c8d']
bars = ax.bar(range(len(models_v)), rates, color=colors_v, edgecolor='white', width=0.65)
ax.errorbar(range(len(models_v)), rates, yerr=[err_low, err_high],
            fmt='none', color='black', capsize=5, linewidth=1.5)
ax.axhline(0.123, color='red', linestyle='--', linewidth=1.5,
           label='Global mean 12.3% [10.4%;14.4%]')
ax.set_xticks(range(len(models_v)))
ax.set_xticklabels(models_v, rotation=15, ha='right', fontsize=8)
ax.set_ylabel('PoV Fix-rate')
ax.set_title('PoV-verified fix-rate by LLM on Vul4J (n=183 evaluable cases, Wilson 95% CI)')
ax.legend(fontsize=8); ax.set_ylim(0, 0.38)
for i, (bar, k, n) in enumerate(zip(bars, n_fix, n_eval)):
    ax.text(i, bar.get_height() + err_high[i] + 0.005, f'{k}/{n}', ha='center', fontsize=7)
plt.tight_layout()
plt.savefig(OUT + 'vul4j_llm_fixrate.png')
plt.close()
print("Figure 7 done")

print(f"\nAll 7 figures saved to {OUT}")
