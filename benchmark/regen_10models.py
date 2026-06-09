"""
Regenerate LLM detection + correction figures with 10 models
(6 primary n=183 Vul4J + 4 pilot n=60)
Run from project root:
    python -m MultiAgentSecurite.benchmark.regen_10models
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
    'font.size': 8,
    'axes.labelsize': 8,
    'axes.titlesize': 8,
    'xtick.labelsize': 7.5,
    'ytick.labelsize': 7.5,
    'legend.fontsize': 7,
    'figure.dpi': 150,
    'savefig.dpi': 150,
    'savefig.bbox': 'tight',
    'savefig.pad_inches': 0.05,
})

_HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(_HERE, 'images') + os.sep
os.makedirs(OUT, exist_ok=True)

# ── 10-model data ─────────────────────────────────────────────────────────────
# 6 primary (n=183 Vul4J) + 4 pilot (n=60, marked with *)
models10 = [
    'llama-3.3-70b',
    'claude-3.5-haiku*',
    'gpt-oss-120b',
    'deepseek-v3',
    'llama-4-maverick',
    'qwen3-coder',
    'starcoder2-15b*',
    'codellama-34b*',
    'nemotron-49b',
    'phi-3.5-mini*',
]
# Youden J (detection, CVEfixes n=120 primary / n=60 for pilot*)
youden10 = [0.15, 0.09, -0.09, -0.15, -0.17, -0.17, -0.18, -0.21, -0.35, -0.39]
# PoV fix-rate (Vul4J n=183 for primary, n=60 pilot for *)
fixrate10 = [0.055, 0.048, 0.149, 0.246, 0.055, 0.175, 0.150, 0.221, 0.045, 0.017]
# Textual similarity (same order)
sim10 = [0.29, 0.31, 0.16, 0.35, 0.38, 0.27, 0.22, 0.26, 0.31, 0.14]

# ── FIGURE 5 (updated): 10-LLM detection ─────────────────────────────────────
fig, ax = plt.subplots(figsize=(7, 3.5))
colors_m = ['#27ae60' if v > 0 else '#e74c3c' for v in youden10]
bars = ax.barh(models10, youden10, color=colors_m, edgecolor='white', height=0.65)
ax.axvline(0, color='black', linewidth=0.8)
for bar, v in zip(bars, youden10):
    ax.text(v + (0.01 if v >= 0 else -0.01), bar.get_y() + bar.get_height() / 2,
            f'{v:+.2f}', va='center', ha='left' if v >= 0 else 'right', fontsize=7.5)
ax.set_xlabel('Youden J')
ax.set_title(
    'Ten-LLM comparison — Semantic detection (n=120/60 CVEfixes cases)\n'
    '* 60-case pilot evaluation (seed=42)'
)
ax.set_xlim(-0.55, 0.28)
green_p = mpatches.Patch(color='#27ae60', label='Youden > 0 (discriminant)')
red_p = mpatches.Patch(color='#e74c3c', label='Youden < 0 (non-discriminant)')
ax.legend(handles=[green_p, red_p], fontsize=7, loc='lower right')
plt.tight_layout()
plt.savefig(OUT + 'llm_detection_10models.png')
plt.close()
print("Figure 5 (10 models) done → llm_detection_10models.png")

# ── FIGURE 6 (updated): 10-LLM similarity vs PoV ─────────────────────────────
order = np.argsort(fixrate10)[::-1]
m_sorted = [models10[i] for i in order]
fix_sorted = [fixrate10[i] for i in order]
sim_sorted = [sim10[i] for i in order]

fig, ax = plt.subplots(figsize=(7, 3.5))
x = np.arange(len(m_sorted))
w = 0.38
ax.bar(x - w / 2, sim_sorted, w, label='Textual similarity', color='#95a5a6', alpha=0.85)
ax.bar(x + w / 2, fix_sorted, w, label='PoV fix-rate', color='#e74c3c', alpha=0.9)
ax.set_xticks(x)
ax.set_xticklabels(m_sorted, fontsize=6.5, rotation=20, ha='right')
ax.set_ylabel('Score / rate')
ax.set_title('Repair: textual similarity vs. PoV executable tests (10 LLMs)\n* 60-case pilot')
ax.legend(fontsize=7.5)
ax.annotate('similarity overestimates\nreal repair capability',
            xy=(5.5, 0.38), fontsize=7, color='gray', ha='center')
plt.tight_layout()
plt.savefig(OUT + 'llm_correction_10models.png')
plt.close()
print("Figure 6 (10 models) done → llm_correction_10models.png")

print(f"\nDone. Files saved to {OUT}")
