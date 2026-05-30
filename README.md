<div align="center">

<img src="logo/dark.svg" alt="MAS Logo" width="280"/>

# Multi-Agent Security Scanner

**Plateforme d'analyse sécurité orchestrée par 8 agents IA spécialisés**

[![Python](https://img.shields.io/badge/Python-3.9+-3776ab?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.136-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![LangGraph](https://img.shields.io/badge/LangGraph-1.2-1e3a8a)](https://langchain-ai.github.io/langgraph/)
[![Rust](https://img.shields.io/badge/Memory_Engine-Rust-ce422b?logo=rust&logoColor=white)](https://www.rust-lang.org)
[![Semgrep](https://img.shields.io/badge/Semgrep-1.163-20b2aa)](https://semgrep.dev)
[![License](https://img.shields.io/badge/License-MIT-22c55e)](LICENSE)

[Documentation](docs/) · [API Swagger](http://localhost:8000/docs) · [GitHub](https://github.com/AbdoulayeCSMN/MAS-ENSAM-2026)

</div>

---

## Résumé

Les agents IA autonomes capables de comprendre, réviser et réparer du code en production représentent une opportunité transformatrice pour la productivité et la sécurité du génie logiciel.

**Multi-Agent Security Scanner** est une architecture multi-agents spécialement conçue pour la révision de code orientée sécurité et la correction automatique des vulnérabilités. Elle combine :

- **Analyse statique multi-outil** — Semgrep, Bandit, Gosec, SpotBugs, PHPCS en parallèle
- **Moteur mémoire en Rust** — 20 règles C/C++/Rust (buffer overflow, UAF, format string…)
- **Analyse sémantique LLM** — détection de failles logiques via Llama-3.1-70B + RAG Qdrant
- **Scoring CVSS 3.1** automatique et **génération de patches** validés

---

## Architecture

<div align="center">
  <img src="image/secure_code_agent_architecture.svg" alt="Architecture Multi-Agent Security Scanner" width="100%" />
</div>

### Les 8 agents

| # | Agent | LLM | Rôle |
|---|-------|-----|------|
| 1 | **TriageAgent** | — | Détection langages, construction des cibles |
| 2 | **ScannerAgent** | — | Semgrep + Bandit + Gosec + SpotBugs + PHPCS |
| 3 | **MemorySafetyAgent** | — | Moteur Rust — 20 règles C/C++/Rust |
| 4 | **SemanticAnalystAgent** | 70B | Failles logiques (IDOR, auth bypass, race cond.) |
| 5 | **ExploitScorerAgent** | 8B | Score CVSS 3.1 + exploitabilité |
| 6 | **PatcherAgent** | 70B | Génération unified diffs |
| 7 | **ValidatorAgent** | — | Application patch + re-scan + détection régressions |
| 8 | **ReportAgent** | — | Rapport JSON structuré |

---

## Structure du projet

```
MAS-ENSAM-2026/
├── src/
│   ├── api.py                  # Application FastAPI (20+ endpoints)
│   ├── mcp_server.py           # Serveur MCP JSON-RPC 2.0
│   ├── github_client.py        # Clone / nettoyage dépôts GitHub
│   ├── agents/                 # 8 agents IA
│   │   ├── base.py
│   │   ├── triage.py
│   │   ├── scanner.py
│   │   ├── memory_safety.py
│   │   ├── semantic.py
│   │   ├── exploit_scorer.py
│   │   ├── patcher.py
│   │   ├── validator.py
│   │   └── report.py
│   ├── graph/                  # Orchestrateur LangGraph
│   │   ├── state.py            # AgentState, Vulnerability, ScanTarget
│   │   ├── workflow.py         # build_workflow()
│   │   └── router.py           # Routage conditionnel
│   ├── memory/                 # Mémoire persistante
│   │   ├── persistent.py       # Qdrant + Sentence Transformers
│   │   ├── session.py          # Mémoire RAM par run
│   │   └── sqlite_memory.py    # Backend SQLite alternatif
│   ├── llm/
│   │   └── client.py           # Groq (8B) + NVIDIA (70B)
│   ├── tools/                  # Wrappers outils sécurité
│   │   ├── semgrep_tool.py
│   │   ├── bandit_tool.py
│   │   ├── gosec_tool.py
│   │   ├── spotbugs_tool.py
│   │   └── phpcs_tool.py
│   └── rules/
│       └── custom.yml          # Règles Semgrep personnalisées
│
├── memory-engine/              # Moteur d'analyse mémoire (Rust)
│   ├── Cargo.toml
│   ├── build.ps1               # Build Windows
│   ├── build.sh                # Build Linux/macOS
│   └── src/
│       ├── main.rs             # CLI + JSON output
│       ├── models.rs           # Finding, ScanOutput, Severity
│       ├── rules.rs            # 20 règles de sécurité mémoire
│       └── analyzer.rs         # Walkdir + regex engine
│
├── docs/                       # Documentation Mintlify
│   ├── index.mdx
│   ├── getting-started.mdx
│   ├── architecture.mdx
│   ├── workflow.mdx
│   ├── models.mdx
│   ├── agents.mdx
│   ├── llm.mdx
│   ├── tools.mdx
│   ├── memory.mdx
│   ├── api.mdx
│   └── mcp.mdx
│
├── image/                      # Diagrammes
├── logo/                       # Logos SVG (light/dark)
├── styles/custom.css           # CSS Mintlify
├── docs.json                   # Config Mintlify
├── requirements.txt
└── .env                        # (non versionné) Clés API
```

---

## Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/AbdoulayeCSMN/MAS-ENSAM-2026.git
cd MAS-ENSAM-2026
```

### 2. Environnement virtuel Python

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate
```

### 3. Dépendances Python

```bash
pip install -r requirements.txt
```

### 4. Compiler le moteur mémoire Rust

> Prérequis : [Rust toolchain](https://rustup.rs/)

```bash
# Windows
cd memory-engine && .\build.ps1

# Linux / macOS
cd memory-engine && ./build.sh
```

### 5. Configurer les variables d'environnement

Créez `src/.env` :

```env
# Obligatoire — au moins un des deux
GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxxxxxx
NVIDIA_API_KEY=nvapi_xxxxxxxxxxxxxxxxxxxxxxxx

# Optionnel — dépôts privés GitHub
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxx

# Optionnel — mémoire sémantique Qdrant
QDRANT_HOST=localhost
QDRANT_PORT=6333
```

| Provider | Lien | Notes |
|----------|------|-------|
| Groq | [console.groq.com](https://console.groq.com) | Gratuit — Llama-3.1-8B |
| NVIDIA | [build.nvidia.com](https://build.nvidia.com) | Crédits gratuits — Llama-3.1-70B |
| GitHub | [github.com/settings/tokens](https://github.com/settings/tokens) | Optionnel |

### 6. Lancer l'API

```bash
python -c "import sys; sys.path.insert(0, 'src'); from api import app; import uvicorn; uvicorn.run(app, host='0.0.0.0', port=8000)"
```

```
INFO: Uvicorn running on http://0.0.0.0:8000
INFO: Application startup complete.
```

Swagger UI : **http://localhost:8000/docs**

Interface de démonstration : **http://localhost:8000/ui**

---

## Utilisation rapide

### Scanner un dépôt local

```bash
curl -X POST http://localhost:8000/scan/local \
  -H "Content-Type: application/json" \
  -d '{"repo_path": "/chemin/vers/projet", "max_iterations": 3}'
```

```json
{"scan_id": "f47ac10b", "status": "started"}
```

### Scanner un dépôt GitHub

```bash
curl -X POST http://localhost:8000/scan/github \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/user/repo", "branch": "main"}'
```

### Récupérer les résultats

```bash
# Statut
curl http://localhost:8000/scan/local/f47ac10b

# Vulnérabilités
curl http://localhost:8000/scan/local/f47ac10b/vulnerabilities
```

Exemple de réponse :

```json
{
  "scan_id": "f47ac10b",
  "status": "completed",
  "report": {
    "statistics": {
      "total": 7,
      "exploitable": 2,
      "by_severity": {"critical": 1, "high": 3, "medium": 3}
    },
    "vulnerabilities": [
      {
        "title": "SQL Injection via f-string",
        "severity": "critical",
        "cvss_score": 9.1,
        "file_path": "src/auth.py",
        "line_start": 42,
        "is_exploitable": true,
        "patch_applied": true
      }
    ]
  }
}
```

---

## Memory Safety Engine (Rust)

Le moteur d'analyse mémoire est un binaire Rust indépendant qui analyse les fichiers C, C++ et Rust avec **20 règles** :

| Catégorie | Règles | Exemples |
|-----------|--------|---------|
| Buffer Overflow | MEM-001 à MEM-005 | `strcpy`, `strcat`, `gets`, `sprintf`, `scanf` |
| Use-After-Free | MEM-010, MEM-011 | `free()` sans NULL, double-free |
| Memory Leaks | MEM-020, MEM-021 | `malloc` non vérifié, `new` sans `delete` |
| Null Pointer | MEM-030 | Déréférencement sans vérification |
| Integer Overflow | MEM-040 | `malloc(n * m)` sans guard |
| Format String | MEM-050 | `printf(user_input)` direct |
| Stack Overflow | MEM-060 | VLA taille non contrôlée |
| Unsafe Rust | MEM-070 à MEM-074 | `unsafe{}`, `transmute`, `ptr::read`, `Box::from_raw` |
| C++ spécifique | MEM-080, MEM-081 | `delete[]` mismatch, `memcpy` overlap |

Usage CLI direct :

```bash
./memory-engine/target/release/memory-engine --json /path/to/repo
./memory-engine/target/release/memory-engine --json --min-severity high /path/to/repo
./memory-engine/target/release/memory-engine --json --verbose /path/to/repo
```

---

## Mémoire persistante (Qdrant — optionnel)

```bash
docker run -d -p 6333:6333 qdrant/qdrant
```

Sans Qdrant, le scanner fonctionne en mode dégradé : analyse statique et LLM restent actifs, sans réutilisation des patterns passés.

---

## Documentation

La documentation complète est générée avec **Mintlify** :

```bash
npx mintlify dev
```

Ouvrez **http://localhost:3000**

---

## Endpoints API

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/` | Métadonnées du service |
| `GET` | `/agents` | Liste des 8 agents |
| `POST` | `/scan/local` | Scan dépôt local |
| `GET` | `/scan/local/{id}` | Statut + rapport |
| `GET` | `/scan/local/{id}/vulnerabilities` | Vulnérabilités |
| `POST` | `/scan/github` | Scan dépôt GitHub |
| `GET` | `/scan/github/{id}` | Statut + rapport |
| `POST` | `/user/register` | Créer utilisateur |
| `POST` | `/user/{id}/scan` | Scan GitHub utilisateur |
| `GET` | `/user/{id}/history` | Historique scans |
| `GET` | `/user/{id}/projects` | Projets scannés |
| `POST` | `/memory/test` | Test mémoire Qdrant |
| `GET` | `/memory/stats` | Stats mémoire |

---

## Équipe

| Nom | Rôle |
|-----|------|
| **Hinimdou Morsia Guitdam** | Architecture, développement, évaluation |
| **DJERI-ALASSANI OUBENOUPOU** | Documentation, analyse des résultats |
| **Chaibou Saidou Abdoulaye** | Support technique, validation |

*Élèves ingénieurs — IA & Technologie des Données · ENSAM 2026*

---

<div align="center">

[![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![LangGraph](https://img.shields.io/badge/LangGraph-1e3a8a)](https://langchain-ai.github.io/langgraph/)
[![Rust](https://img.shields.io/badge/Rust-ce422b?logo=rust&logoColor=white)](https://www.rust-lang.org)
[![Qdrant](https://img.shields.io/badge/Qdrant-dc143c)](https://qdrant.tech)
[![Semgrep](https://img.shields.io/badge/Semgrep-20b2aa)](https://semgrep.dev)

</div>
