"""
Generate all 6 architecture figures for MultiAgentSecurite paper.
Run from the project root:
    python -m MultiAgentSecurite.scripts.generate_architecture
Or directly:
    python MultiAgentSecurite/scripts/generate_architecture.py
Outputs go to MultiAgentSecurite/image/
"""
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch
import numpy as np

DPI = 150
LIGHT_BLUE = '#E8E8F8'
BORDER_BLUE = '#9999CC'
LIGHT_YELLOW = '#FFFDE8'
BORDER_YELLOW = '#CCCC66'

_HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(_HERE, '..', 'image') + os.sep
os.makedirs(OUT, exist_ok=True)


def box(ax, x, y, w, h, label, sublabel=None, color=LIGHT_BLUE, border=BORDER_BLUE,
        fontsize=9, bold=False, italic=False, center_y=None):
    rect = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02",
                          facecolor=color, edgecolor=border, linewidth=1)
    ax.add_patch(rect)
    cy = center_y if center_y else y + h / 2
    ax.text(x + w / 2, cy, label, ha='center', va='center',
            fontsize=fontsize, fontweight='bold' if bold else 'normal',
            fontstyle='italic' if italic else 'normal', multialignment='center')
    if sublabel:
        ax.text(x + w / 2, y + h / 2 - 0.18, sublabel, ha='center', va='center',
                fontsize=fontsize - 1.5, color='#555555', multialignment='center')


def diamond(ax, cx, cy, w, h, label, color=LIGHT_BLUE, border=BORDER_BLUE, fontsize=8):
    pts = np.array([[cx, cy + h / 2], [cx + w / 2, cy], [cx, cy - h / 2], [cx - w / 2, cy]])
    ax.add_patch(plt.Polygon(pts, closed=True, facecolor=color, edgecolor=border, linewidth=1))
    ax.text(cx, cy, label, ha='center', va='center', fontsize=fontsize, multialignment='center')


def oval(ax, cx, cy, rx, ry, label, color=LIGHT_BLUE, border=BORDER_BLUE, fontsize=9):
    ax.add_patch(mpatches.Ellipse((cx, cy), 2 * rx, 2 * ry,
                                  facecolor=color, edgecolor=border, linewidth=1))
    ax.text(cx, cy, label, ha='center', va='center', fontsize=fontsize)


def section_box(ax, x, y, w, h, label, color=LIGHT_YELLOW, border=BORDER_YELLOW, fontsize=8):
    rect = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.03",
                          facecolor=color, edgecolor=border, linewidth=1.2,
                          linestyle='--' if color == LIGHT_YELLOW else '-')
    ax.add_patch(rect)
    ax.text(x + w / 2, y + h - 0.1, label, ha='center', va='top',
            fontsize=fontsize, color='#666622', style='italic')


def dashed_arrow(ax, x1, y1, x2, y2, label=''):
    ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle='->', color='#666666', lw=0.8,
                                linestyle='dashed', connectionstyle='arc3,rad=0'))
    if label:
        ax.text((x1 + x2) / 2 + 0.05, (y1 + y2) / 2, label,
                fontsize=6.5, color='#666666', fontstyle='italic')


# ─────────────────────────────────────────────────────────
# Figure 1: Architecture_SecureCodeAgent.png
# ─────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(10, 9))
ax.set_xlim(0, 10); ax.set_ylim(0, 9); ax.axis('off'); ax.set_aspect('equal')

section_box(ax, 0.1, 6.0, 2.0, 2.7, 'INPUT', color='#FFFDE8', border='#AAAA44')
box(ax, 0.3, 7.8, 1.6, 0.6, 'GitHub Repository\nou code source local',
    color=LIGHT_BLUE, border=BORDER_BLUE, fontsize=7.5)

section_box(ax, 2.5, 4.5, 5.0, 4.2, '', color='#FFFDE8', border='#AAAA44')
ax.text(5.0, 8.65, 'Orchestrateur Central (LangGraph)', ha='center', va='center',
        fontsize=8.5, style='italic', color='#555522')
box(ax, 3.5, 7.9, 2.0, 0.55, 'AgentState\n(état partagé)', color='#DDDDF8',
    border=BORDER_BLUE, fontsize=8, bold=True)
box(ax, 6.2, 7.9, 1.8, 0.55, 'Routeur\nconditionnel', color=LIGHT_BLUE,
    border=BORDER_BLUE, fontsize=7.5)

section_box(ax, 2.8, 4.7, 4.4, 3.0, '8 Agents Spécialisés', color='#FFFDE8',
            border='#BBBB55')
agents = [
    ('1. TriageAgent', 'Détection langages/fichiers'),
    ('2. ScannerAgent', 'Scan statique SAST'),
    ('3. MemorySafetyAgent', 'Moteur Rust (C/C++/Rust)'),
    ('4. SemanticAnalystAgent', 'LLM + RAG (failles logiques)'),
    ('5. ExploitScorerAgent', 'CVSS + exploitabilité'),
    ('6. PatcherAgent', 'Génération correctifs'),
    ('7. ValidatorAgent', 'Validation + régression'),
    ('8. ReportAgent', 'JSON / Markdown'),
]
y_start = 7.45
for i, (name, role) in enumerate(agents):
    box(ax, 3.0, y_start - i * 0.36 - 0.17, 4.0, 0.33,
        f'{name} — {role}', color=LIGHT_BLUE, border=BORDER_BLUE, fontsize=7)

section_box(ax, 7.8, 4.5, 2.0, 2.7, 'OUTPUT', color='#FFFDE8', border='#AAAA44')
box(ax, 8.0, 5.8, 1.6, 0.8, 'Rapport de sécurité\n+ Correctifs validés',
    color=LIGHT_BLUE, border=BORDER_BLUE, fontsize=7.5)

ax.annotate('', xy=(2.5, 7.6), xytext=(1.9, 7.6),
            arrowprops=dict(arrowstyle='->', color='#333333', lw=1.2))
ax.annotate('', xy=(7.8, 6.2), xytext=(7.2, 6.2),
            arrowprops=dict(arrowstyle='->', color='#333333', lw=1.2))

plt.tight_layout(pad=0.2)
plt.savefig(OUT + 'Architecture_SecureCodeAgent.png', dpi=DPI, bbox_inches='tight', facecolor='white')
plt.close()
print("Fig 1 done: Architecture_SecureCodeAgent.png")

# ─────────────────────────────────────────────────────────
# Figure 2: Workflow_routage.png
# ─────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(5, 14))
ax.set_xlim(0, 5); ax.set_ylim(0, 14); ax.axis('off')
cx = 2.5
steps = [
    ('oval',    13.4, 'Début'),
    ('box',     12.7, 'TriageAgent\nDétection langages'),
    ('diamond', 11.9, 'Erreur?'),
    ('box',     11.1, 'ScannerAgent\nSemgrep/Bandit/Gosec/SpotBugs'),
    ('box',     10.3, 'MemorySafetyAgent\nMoteur Rust'),
    ('box',      9.5, 'SemanticAnalystAgent\nLLM + RAG'),
    ('diamond',  8.7, 'Vuln\ntrouvées?'),
    ('box',      7.9, 'ExploitScorerAgent\nCVSS + exploitabilité'),
    ('diamond',  7.1, 'Exploitables?'),
    ('box',      6.3, 'PatcherAgent\nGénération patch diff'),
    ('diamond',  5.5, 'Patchs en\nattente?'),
    ('box',      4.7, 'ValidatorAgent\nApplication + re-scan'),
    ('diamond',  3.9, 'Rejetés &&\nitération < max?'),
    ('box',      2.9, 'ReportAgent'),
    ('oval',     2.1, 'Fin'),
]
for kind, y, label in steps:
    if kind == 'oval':
        oval(ax, cx, y, 0.7, 0.3, label, fontsize=9)
    elif kind == 'box':
        box(ax, cx - 1.2, y - 0.3, 2.4, 0.55, label, fontsize=8)
    elif kind == 'diamond':
        diamond(ax, cx, y, 1.6, 0.55, label, fontsize=8)

prev_y = None
ptype = None
for kind, y, label in steps:
    if prev_y is not None:
        top_y = y + (0.3 if kind == 'oval' else 0.28)
        bot_prev = prev_y - (0.3 if ptype == 'oval' else 0.28)
        ax.annotate('', xy=(cx, top_y), xytext=(cx, bot_prev),
                    arrowprops=dict(arrowstyle='->', color='#333333', lw=1))
    prev_y = y; ptype = kind

# Erreur? Oui → bypass to ReportAgent
ax.annotate('', xy=(0.8, 11.9), xytext=(cx - 0.8, 11.9),
            arrowprops=dict(arrowstyle='->', color='#333333', lw=0.8))
ax.annotate('', xy=(0.8, 2.9), xytext=(0.8, 11.9),
            arrowprops=dict(arrowstyle='->', color='#333333', lw=0.8))
ax.annotate('', xy=(cx - 1.2, 2.9), xytext=(0.8, 2.9),
            arrowprops=dict(arrowstyle='->', color='#333333', lw=0.8))
ax.text(0.65, 12.2, 'Oui', fontsize=7, color='#333333')

# Vuln trouvées? Non → ReportAgent
ax.annotate('', xy=(0.4, 8.7), xytext=(cx - 0.8, 8.7),
            arrowprops=dict(arrowstyle='->', color='#333333', lw=0.8))
ax.annotate('', xy=(0.4, 2.9), xytext=(0.4, 8.7),
            arrowprops=dict(arrowstyle='->', color='#333333', lw=0.8))
ax.annotate('', xy=(cx - 1.2, 2.9), xytext=(0.4, 2.9),
            arrowprops=dict(arrowstyle='->', color='#333333', lw=0.8))
ax.text(0.25, 9.0, 'Non', fontsize=7)

ax.text(cx + 0.85, 7.1, 'Non', fontsize=7)

# Loop back (iteration < max)
ax.annotate('', xy=(4.2, 6.3), xytext=(cx + 0.8, 3.9),
            arrowprops=dict(arrowstyle='->', color='#333333', lw=0.8))
ax.annotate('', xy=(cx + 1.2, 6.3), xytext=(4.2, 6.3),
            arrowprops=dict(arrowstyle='->', color='#333333', lw=0.8))
ax.text(4.3, 5.1, 'iteration\n< max', fontsize=7, ha='center')

ax.text(cx + 0.1, 12.35, 'Non', fontsize=7)
ax.text(cx + 0.1, 8.35, 'Oui', fontsize=7)
ax.text(cx + 0.1, 7.45, 'Oui', fontsize=7)
ax.text(cx + 0.1, 4.25, 'Non', fontsize=7)

plt.tight_layout(pad=0.2)
plt.savefig(OUT + 'Workflow_routage.png', dpi=DPI, bbox_inches='tight', facecolor='white')
plt.close()
print("Fig 2 done: Workflow_routage.png")

# ─────────────────────────────────────────────────────────
# Figure 3: ScantAgent_outilsSAST.png
# ─────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(12, 6))
ax.set_xlim(0, 12); ax.set_ylim(0, 6); ax.axis('off')

section_box(ax, 0.2, 0.5, 2.2, 5.0, 'Entrée', color=LIGHT_YELLOW, border=BORDER_YELLOW)
box(ax, 0.4, 3.8, 1.8, 0.8, 'Langages\ndétectés', fontsize=8.5)
box(ax, 0.4, 2.5, 1.8, 0.8, 'Dépôt\nsource', fontsize=8.5)

section_box(ax, 2.7, 0.3, 7.0, 5.4, 'ScannerAgent (EnhancedScannerAgent)',
            color=LIGHT_YELLOW, border=BORDER_YELLOW, fontsize=8)
box(ax, 3.0, 3.3, 2.0, 0.9, 'Cache\n(SHA256 + règles)', fontsize=8)
section_box(ax, 5.3, 0.5, 3.8, 4.8, 'Exécution parallèle\n(ThreadPoolExecutor)',
            color='#F8F8E8', border=BORDER_YELLOW, fontsize=7.5)
tools = ['SemgrepTool\n(multi-langages)', 'BanditTool\n(Python)',
         'GosecTool\n(Go)', 'SpotBugsTool\n(Java)', 'PhpCsTool\n(PHP)']
ty_start = 4.5
for i, t in enumerate(tools):
    box(ax, 5.5, ty_start - i * 0.85, 3.4, 0.72, t, fontsize=7.5)

section_box(ax, 10.0, 0.5, 1.8, 5.0, 'Sortie', color=LIGHT_YELLOW, border=BORDER_YELLOW)
box(ax, 10.1, 2.5, 1.6, 1.0, 'raw_findings\n+ vulnerabilities',
    color=LIGHT_BLUE, border=BORDER_BLUE, fontsize=8, bold=True)

ax.annotate('', xy=(2.7, 4.1), xytext=(2.2, 4.1), arrowprops=dict(arrowstyle='->', color='#333', lw=1))
ax.annotate('', xy=(3.0, 3.7), xytext=(2.2, 2.85), arrowprops=dict(arrowstyle='->', color='#333', lw=1))
ax.annotate('', xy=(5.3, 3.75), xytext=(5.0, 3.75), arrowprops=dict(arrowstyle='->', color='#333', lw=1))
for i in range(5):
    ty = ty_start - i * 0.85 + 0.36
    ax.annotate('', xy=(10.0, 2.9), xytext=(8.9, ty),
                arrowprops=dict(arrowstyle='->', color='#555', lw=0.7, connectionstyle='arc3,rad=0.05'))

plt.tight_layout(pad=0.3)
plt.savefig(OUT + 'ScantAgent_outilsSAST.png', dpi=DPI, bbox_inches='tight', facecolor='white')
plt.close()
print("Fig 3 done: ScantAgent_outilsSAST.png")

# ─────────────────────────────────────────────────────────
# Figure 4: Structure_agentState.png (UML)
# ─────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(7, 13))
ax.set_xlim(0, 7); ax.set_ylim(0, 13); ax.axis('off')


def uml_class(ax, x, y, w, title, attrs, stereo=None, color=LIGHT_BLUE):
    h_title = 0.55
    h_attrs = len(attrs) * 0.32 + 0.15
    h_total = h_title + h_attrs
    ax.add_patch(FancyBboxPatch((x, y), w, h_total, boxstyle="square,pad=0",
                                facecolor=color, edgecolor=BORDER_BLUE, linewidth=1.2))
    ax.add_patch(FancyBboxPatch((x, y + h_attrs), w, h_title, boxstyle="square,pad=0",
                                facecolor='#D0D0F0', edgecolor=BORDER_BLUE, linewidth=1.2))
    if stereo:
        ax.text(x + w / 2, y + h_attrs + h_title * 0.72, f'«{stereo}»',
                ha='center', va='center', fontsize=7.5, style='italic')
        ax.text(x + w / 2, y + h_attrs + h_title * 0.28, title,
                ha='center', va='center', fontsize=9, fontweight='bold')
    else:
        ax.text(x + w / 2, y + h_attrs + h_title / 2, title,
                ha='center', va='center', fontsize=9, fontweight='bold')
    for i, attr in enumerate(attrs):
        ay = y + h_attrs - (i + 1) * 0.32 + 0.08
        ax.text(x + 0.12, ay, attr, ha='left', va='center', fontsize=7.5, fontfamily='monospace')
    return x + w / 2, y + h_total


agent_attrs = [
    '+str repo_root', '+str scan_id', '+set<Language> detected_languages',
    '+bool needs_memory_safety', '+list<ScanTarget> targets',
    '+list<dict> raw_findings', '+list<Vulnerability> vulnerabilities',
    '+list<Vulnerability> memory_safety_findings',
    '+list<Vulnerability> semantic_findings',
    '+list<Vulnerability> patches_pending',
    '+list<Vulnerability> patches_validated',
    '+list<Vulnerability> patches_rejected',
    '+dict report', '+list<str> errors',
    '+int iteration', '+int max_patch_iterations',
]
scan_attrs = ['+str path', '+Language language', '+str content', '+str file_hash']
vuln_attrs = [
    '+str id', '+str title', '+Severity severity', '+str cwe_id', '+str cve_id',
    '+str file_path', '+int line_start', '+int line_end', '+str code_snippet',
    '+str description', '+bool is_exploitable', '+float cvss_score',
    '+bool patch_applied', '+str patch_diff', '+bool memory_safety_issue', '+dict extra',
]
lang_vals = ['C', 'CPP', 'PYTHON', 'JAVASCRIPT', 'TYPESCRIPT', 'RUST', 'JAVA', 'GO', 'PHP']
sev_vals = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

cx_a, top_a = uml_class(ax, 0.5, 7.2, 6.0, 'AgentState', agent_attrs)
cx_s, top_s = uml_class(ax, 0.3, 4.1, 2.8, 'ScanTarget', scan_attrs)
cx_v, top_v = uml_class(ax, 3.9, 3.1, 2.8, 'Vulnerability', vuln_attrs)
cx_l, top_l = uml_class(ax, 0.3, 0.5, 2.4, 'Language', lang_vals, stereo='enumeration')
cx_sv, top_sv = uml_class(ax, 4.1, 0.5, 2.2, 'Severity', sev_vals, stereo='enumeration')

ax.annotate('', xy=(cx_s, top_s), xytext=(0.5 + 6.0 * 0.25, 7.2),
            arrowprops=dict(arrowstyle='->', color='#444', lw=1.2))
ax.annotate('', xy=(cx_v, top_v), xytext=(0.5 + 6.0 * 0.7, 7.2),
            arrowprops=dict(arrowstyle='->', color='#444', lw=1.2))
ax.annotate('', xy=(cx_l, top_l), xytext=(cx_s, 4.1),
            arrowprops=dict(arrowstyle='->', color='#444', lw=1.2))
ax.annotate('', xy=(cx_sv, top_sv), xytext=(cx_v, 3.1),
            arrowprops=dict(arrowstyle='->', color='#444', lw=1.2))

plt.tight_layout(pad=0.2)
plt.savefig(OUT + 'Structure_agentState.png', dpi=DPI, bbox_inches='tight', facecolor='white')
plt.close()
print("Fig 4 done: Structure_agentState.png")

# ─────────────────────────────────────────────────────────
# Figure 5: Patcher_validator_Agent_pipline.png
# ─────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(6, 14))
ax.set_xlim(0, 6); ax.set_ylim(0, 14); ax.axis('off')

box(ax, 1.5, 12.8, 3.0, 0.9,
    'Vulnerability\ncvss_score >= 7.0\nis_exploitable = true',
    color='#E8F8E8', border='#66AA66', fontsize=8)

section_box(ax, 0.5, 7.5, 5.0, 5.0, 'PatcherAgent', color=LIGHT_YELLOW, border=BORDER_YELLOW)
patcher_steps = [
    ('_read_file()\nLecture du fichier', 11.8),
    ('_memory.retrieve_patches()\nPatches similaires (RAG)', 10.9),
    ('_llm.query()\nDeepSeek-V3 / Llama-3.3-70B', 10.0),
    ('Extraction du patch\nformat unified diff', 9.1),
]
for label, y in patcher_steps:
    box(ax, 1.0, y - 0.35, 4.0, 0.65, label, fontsize=8)
for i in range(len(patcher_steps) - 1):
    y1 = patcher_steps[i][1] - 0.35
    y2 = patcher_steps[i + 1][1] + 0.30
    ax.annotate('', xy=(3.0, y2), xytext=(3.0, y1),
                arrowprops=dict(arrowstyle='->', color='#333', lw=1))

ax.annotate('', xy=(3.0, 11.8), xytext=(3.0, 12.7),
            arrowprops=dict(arrowstyle='->', color='#333', lw=1.2))
ax.annotate('', xy=(3.0, 7.5), xytext=(3.0, 8.75),
            arrowprops=dict(arrowstyle='->', color='#333', lw=1.2))
ax.text(3.15, 8.1, 'patch_diff', fontsize=7.5, color='#555')

section_box(ax, 0.5, 2.5, 5.0, 4.8, 'ValidatorAgent', color=LIGHT_YELLOW, border=BORDER_YELLOW)
val_steps = [
    ("_apply_diff()\nApplication via 'patch'", 6.9),
    ('Copie temporaire', 6.1),
    ('Re-scan Semgrep', 5.3),
    ('Vérification:\n- Vulnérabilité corrigée?\n- Nouvelles vulnérabilités?', 4.4),
]
for label, y in val_steps:
    box(ax, 1.0, y - 0.35, 4.0, 0.65, label, fontsize=7.5)
for i in range(len(val_steps) - 1):
    y1 = val_steps[i][1] - 0.35
    y2 = val_steps[i + 1][1] + 0.30
    ax.annotate('', xy=(3.0, y2), xytext=(3.0, y1),
                arrowprops=dict(arrowstyle='->', color='#333', lw=1))

ax.annotate('', xy=(1.5, 2.0), xytext=(1.8, 4.05),
            arrowprops=dict(arrowstyle='->', color='#333', lw=1))
box(ax, 0.3, 1.2, 2.3, 0.75, 'patches_validated\nRapport final',
    color='#E8FFE8', border='#44AA44', fontsize=8)
ax.text(1.45, 2.15, 'OK & pas\nde régression', fontsize=6.5, ha='center', color='#225522')

ax.annotate('', xy=(4.5, 2.0), xytext=(4.2, 4.05),
            arrowprops=dict(arrowstyle='->', color='#333', lw=1))
box(ax, 3.5, 1.2, 2.2, 0.75, 'patches_rejected', color='#FFE8E8', border='#AA4444', fontsize=8)
ax.text(4.5, 2.15, 'KO ou\nrégression', fontsize=6.5, ha='center', color='#552222')

ax.annotate('', xy=(5.3, 9.5), xytext=(5.3, 1.55),
            arrowprops=dict(arrowstyle='->', color='#555', lw=1))
ax.annotate('', xy=(5.0, 9.5), xytext=(5.3, 9.5),
            arrowprops=dict(arrowstyle='->', color='#555', lw=1))
ax.text(5.45, 5.5, 'iteration\n< max', fontsize=7, ha='center', color='#555')

plt.tight_layout(pad=0.2)
plt.savefig(OUT + 'Patcher_validator_Agent_pipline.png', dpi=DPI, bbox_inches='tight', facecolor='white')
plt.close()
print("Fig 5 done: Patcher_validator_Agent_pipline.png")

# ─────────────────────────────────────────────────────────
# Figure 6: memoirePersistance.png
# ─────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(12, 7))
ax.set_xlim(0, 12); ax.set_ylim(0, 7); ax.axis('off')

ops = [
    ('retrieve_similar_patterns()\nRAG pour\nSemanticAnalystAgent', 0.3),
    ('store_pattern()\nMémorisation\npatterns', 3.2),
    ('retrieve_patches()\nRAG pour\nPatcherAgent', 6.1),
    ('store_patch()\nMémorisation\npatches validés', 9.0),
]
section_box(ax, 0.1, 5.2, 11.8, 1.5, 'Opérations', color='#FFFDE8', border=BORDER_YELLOW)
for label, x in ops:
    box(ax, x, 5.35, 2.6, 1.2, label, fontsize=7.5)

section_box(ax, 0.2, 1.8, 11.6, 3.2, 'PersistentMemory — SQLite (backend par défaut)',
            color='#F8F8FF', border='#7777BB', fontsize=8)
box(ax, 0.5, 2.2, 3.5, 1.8,
    'patterns table\nid, description,\ncode_snippet, cwe_id',
    color=LIGHT_BLUE, border=BORDER_BLUE, fontsize=8)
box(ax, 4.5, 2.2, 3.5, 1.8,
    'patches table\nid, cwe_id,\npatch_diff',
    color=LIGHT_BLUE, border=BORDER_BLUE, fontsize=8)
box(ax, 8.3, 2.2, 3.2, 1.8,
    'patterns_fts (FTS5)\nfull-text search',
    color=LIGHT_BLUE, border=BORDER_BLUE, fontsize=8)

section_box(ax, 0.2, 0.1, 11.6, 1.5, 'Qdrant (optionnel)',
            color='#F5F5FF', border='#9999DD', fontsize=8)
box(ax, 0.7, 0.25, 4.5, 1.1, 'Collection: vuln_patterns\n384 dim (MiniLM)',
    color='#EEEEFF', border='#9999CC', fontsize=8)
box(ax, 6.5, 0.25, 4.5, 1.1, 'Collection: patches\n384 dim (MiniLM)',
    color='#EEEEFF', border='#9999CC', fontsize=8)

ax.annotate('', xy=(2.25, 5.0), xytext=(1.6, 5.35),
            arrowprops=dict(arrowstyle='->', color='#444', lw=1))
ax.annotate('', xy=(2.25, 4.0), xytext=(4.5, 5.35),
            arrowprops=dict(arrowstyle='->', color='#444', lw=1))
ax.annotate('', xy=(6.25, 4.0), xytext=(7.35, 5.35),
            arrowprops=dict(arrowstyle='->', color='#444', lw=1))
ax.annotate('', xy=(6.25, 4.0), xytext=(10.25, 5.35),
            arrowprops=dict(arrowstyle='->', color='#444', lw=1))
dashed_arrow(ax, 2.25, 2.2, 2.95, 1.35, 'optionnel')
dashed_arrow(ax, 6.25, 2.2, 8.75, 1.35, 'optionnel')

plt.tight_layout(pad=0.3)
plt.savefig(OUT + 'memoirePersistance.png', dpi=DPI, bbox_inches='tight', facecolor='white')
plt.close()
print("Fig 6 done: memoirePersistance.png")

print(f"\nAll 6 architecture figures saved to {OUT}")
