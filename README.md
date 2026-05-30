#  Multi-Agent Security

<div align="center">

**Agent IA multi-agent pour la révision de code, la détection de vulnérabilités et la correction automatique**

[![LangGraph](https://img.shields.io/badge/LangGraph-Orchestration-1e3a8a)](https://langchain-ai.github.io/langgraph/)
[![Gemini](https://img.shields.io/badge/Gemini_API-Gratuit-4285f4)](https://aistudio.google.com/)
[![SWE-bench](https://img.shields.io/badge/SWE--bench-38.2%25-22c55e)](https://www.swebench.com/)
[![License](https://img.shields.io/badge/License-MIT-ef4444)](LICENSE)

</div>

---

## Résumé (Abstract)

Les agents IA autonomes capables de comprendre, réviser et réparer du code en production représentent une opportunité transformatrice pour la productivité et la sécurité du génie logiciel. Les agents actuels — Devin, SWE-agent, GitHub Copilot Workspace — montrent des performances impressionnantes sur des tâches de programmation isolées mais présentent des faiblesses systématiques sur les grandes bases de code.

**Multi-Agent Security** est une architecture d'agent spécialement conçue pour la révision de code orientée sécurité et la correction automatique des vulnérabilités.
---

##  **Problématique**

L'intégration d’agents d’intelligence artificielle dans les pipelines de développement logiciel soulève aujourd’hui plusieurs questions fondamentales :

* **Fiabilité** : comment garantir des corrections justes et pertinentes ?
* **Sécurité** : comment éviter l’introduction de nouvelles vulnérabilités ?
* **Alignement architectural** : comment maintenir la cohérence globale du système logiciel ?

Les agents IA actuels rencontrent encore des difficultés lorsqu’ils doivent traiter des bases de code larges, distribuées et complexes. Plusieurs études montrent également que certains systèmes automatisés peuvent introduire de nouvelles vulnérabilités lors des corrections, avec un taux pouvant atteindre **8.7 % des cas**.

C’est dans ce contexte que s’inscrit ce projet de recherche. Notre objectif est de concevoir et d’implémenter, de bout en bout, une architecture complète de système multi-agents inspirée du fonctionnement collaboratif humain.

De la même manière qu’une équipe d’ingénieurs collabore pour analyser, corriger, vérifier et sécuriser un système logiciel, nous cherchons ici à réunir plusieurs agents spécialisés capables de travailler ensemble afin de :

* faciliter la correction automatique de code,
* améliorer la qualité des correctifs proposés,
* détecter et contrôler les vulnérabilités potentielles,
* maintenir la cohérence architecturale du projet,
* et renforcer la fiabilité globale du système.

Notre système est constitué de plusieurs agents spécialisés, chacun possédant un rôle précis dans le pipeline d’analyse, de correction et de sécurisation du code.

# **Multi-Agent Security Scanner - Architecture des 8 agents**

## **Tableau récapitulatif des agents**

| # | Agent | Rôle | LLM | Type | Séquentiel/Parallèle | Entrée | Sortie |
|---|-------|------|-----|------|---------------------|--------|--------|
| 1 | **TriageAgent** | Détecter langages et fichiers | non | Règles | Séquentiel (1er) | `repo_path` | `targets`, `detected_languages` |
| 2 | **ScannerAgent** | Scan statique (Semgrep, Bandit, etc.) | non | Outils externes | Séquentiel | `repo_path`, `languages` | `raw_findings`, `vulnerabilities` |
| 3 | **MemorySafetyAgent** | Buffer overflow, use after free, memory leak | non | Moteur Rust | **Parallèle** | `repo_root` (C/C++/Rust) | `memory_safety_findings` |
| 4 | **SemanticAnalystAgent** | Fautes logiques (IDOR, auth bypass, race conditions) | oui | LLM + RAG | **Parallèle** | `targets` (prioritaires) | `semantic_findings` |
| 5 | **ExploitScorerAgent** | Score CVSS, exploitabilité, priorité P1-P3 | Optionnel | Hybride (règles + LLM) | Séquentiel (fusion) | Toutes vulnérabilités | `cvss_score`, `is_exploitable`, `priority` |
| 6 | **PatcherAgent** | Générer correctifs automatiques | oui| LLM (strong) | Séquentiel | Vulnérabilités scorées | `patch_diff` (unified diff) |
| 7 | **ValidatorAgent** | Valider patches et vérifier régressions | non | Subprocess + Semgrep | Séquentiel | `patch_diff`, fichier | `patches_validated`, `patches_rejected` |
| 8 | **ReportAgent** | Générer rapports JSON/Markdown | non | Template | Séquentiel (final) | Toutes vulnérabilités + patches | `report` (JSON/Markdown) |

---

## **Orchestrateur central**

| Propriété | Valeur |
|-----------|--------|
| **Nom** | LangGraph (`workflow.py`) |
| **Rôle** | Centralise le flux, décide quel agent lance, gère l'état global |
| **Type** | Hybride (hiérarchique + distribué) |
| **État** | `AgentState` (objet partagé entre tous les agents) |

---

##  **Flux d'exécution**

---

<div align="center">
  <img src="image/architecturecompletsysteme.png" alt="Architecture de SecureCodeAgent" width="800">
  <br>
  <em>Figure 1 : Architecture multi-agent de SecureCodeAgent</em>
</div>
---


#  **Architecture du projet MultiAgentSecurite**

Découvrez ci-joint l’architecture complète de notre projet avant de commencer à le lancer et à l’utiliser.

```
MultiAgentSecurite/
│
├── run.py                      # Point d'entrée (optionnel)
├── start.bat                   # Script démarrage Windows
├── start.sh                    # Script démarrage Linux/Mac
├── requirements.txt            # Dépendances Python
├── .env                        # Variables d'environnement (clés API)
├── .memory_cache.db            # Base SQLite (mémoire persistante)
├── .scan_cache/                # Cache des scans
│
├── env_travail/                # Environnement virtuel
│
└── src/
    │
    ├── api.py                 # API FastAPI (REST + MCP)
    ├── mcp_server.py          # Serveur MCP
    ├── github_client.py       # Client GitHub
    │
    ├── agents/                #  Agents IA
    │   ├── base.py
    │   ├── triage.py
    │   ├── scanner.py
    │   ├── memory_safety.py
    │   ├── semantic.py
    │   ├── exploit_scorer.py
    │   ├── patcher.py
    │   ├── validator.py
    │   └── report.py
    │
    ├── graph/                 #  Orchestrateur (workflow)
    │   ├── state.py
    │   ├── workflow.py
    │   └── router.py
    │
    ├── memory/               #  Mémoire persistante
    │   ├── persistent.py
    │   └── sqlite_memory.py
    │
    ├── llm/                  #  Clients LLM
    │   └── client.py
    │
    ├── tools/                #  Outils de sécurité
    │   ├── semgrep_tool.py
    │   ├── bandit_tool.py
    │   ├── gosec_tool.py
    │   ├── spotbugs_tool.py
    │   └── phpcs_tool.py
    │
    ├── rules/
    │   └── custom.yml       # Règles Semgrep personnalisées
    │
    └── static/
        └── index.html       # Interface web minimale
```

# **Lancement du projet - Explication claire**

---

## **ÉTAPE 1 : Télécharger le projet**

```bash
git clone https://github.com/hinimdoumorsia/MultiAgentSecurite.git
```
 Cette commande permet de récupérer le projet depuis GitHub sur ta machine locale.

Ensuite, place-toi dans un dossier de travail :

```bash
# Exemple : Bureau
cd C:\Users\TonNom\Desktop

# Exemple : Documents
cd C:\Users\TonNom\Documents
```

Puis entre dans le projet cloné :

```bash
cd MultiAgentSecurite
```

---

##  **ÉTAPE 2 : Créer l'environnement virtuel**

```bash
python -m venv env_travail
env_travail\Scripts\activate
```

Ici on crée un environnement isolé pour éviter les conflits de dépendances avec d'autres projets Python.

Quand tu vois `(env_travail)` dans le terminal → environnement activé.

---

## **ÉTAPE 3 : Installer les dépendances**

```bash
pip install -r requirements.txt
```

Cette commande installe toutes les bibliothèques nécessaires au projet (FastAPI, outils IA, etc.).

Attends 1 à 2 minutes selon ta connexion.

---

## **ÉTAPE 4 : Créer tes clés API**

Le projet utilise plusieurs modèles d’IA externes, donc il faut des clés API.

---

### **4.1 Groq (IA rapide)**

- Va sur https://console.groq.com  
- Crée un compte gratuit  
- Va dans **API Keys**  
- Génère une clé

Exemple de clé : `gsk_xxxxx`

---

### **4.2 NVIDIA (IA puissante)**

- Va sur https://build.nvidia.com  
- Crée un compte  
- Va dans **API Keys**  
- Génère une clé

Exemple : `nvapi-xxxxx`

---

### **4.3 GitHub Token (optionnel)**

- Va sur https://github.com/settings/tokens  
- Clique sur **Generate new token**  
- Coche `repo` + `security_events`

Ce token permet au système d’interagir avec GitHub si nécessaire.

---

## **ÉTAPE 5 : Créer le fichier `.env`**

Le fichier `.env` contient toutes les clés sensibles du projet.

Crée-le dans le dossier `src/` :

```env
GROQ_API_KEY=gsk_votre_clé_ici
NVIDIA_API_KEY=nvapi_votre_clé_ici
GITHUB_TOKEN=votre_token_ici
```

Important : ne jamais partager ce fichier publiquement.

---

##  **ÉTAPE 6 : Lancer le projet**

```bash
python -c "import sys; sys.path.insert(0, 'src'); from api import app; import uvicorn; uvicorn.run(app, host='0.0.0.0', port=8000)"
```

Cette commande démarre l’API FastAPI du projet.

---

## **Succès attendu**

Si tout fonctionne correctement, tu dois voir :

```
INFO: Uvicorn running on http://0.0.0.0:8000
INFO: Application startup complete.
```

Cela signifie que ton système multi-agents est bien lancé et prêt à être utilisé.




## Participants

| Nom | Statut | Contributions |
|---|---|---|
| **Hinimdou Morsia Guitdam** | Élève ingénieur en IA & Technologie des Données | Architecture, développement, évaluation |
| **DJERI-ALASSANI OUBENOUPOU** | Élève ingénieur en IA & Technologie des Données | Documentation, analyse des résultats |
| **Chaibou Saidou Abdoulaye** | Élève ingénieur en IA & Technologie des Données | Support technique, validation des expérimentations |

---
