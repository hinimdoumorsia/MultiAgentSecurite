# Architecture

## Vue d'ensemble

Le projet est construit comme un orchestrateur de sécurité multi-agents. Chaque agent a un rôle fonctionnel clair et les résultats sont assemblés dans un état partagé.

## Composants principaux

### 1. Orchestrateur

Le `LangGraph` coordonne les agents. La logique est centralisée dans `src/graph/workflow.py`.

### 2. Agents spécialisés

Les agents réalisent des étapes distinctes :

- triage des fichiers et langages
- détection statique
- analyse de sécurité mémoire
- analyse sémantique LLM
- scoring de vulnérabilité
- génération du correctif
- validation du patch
- génération du rapport

### 3. Outils de scan

Les outils sous `src/tools/` encapsulent les scanners externes :

- Semgrep
- Bandit
- Gosec
- SpotBugs
- PHPCS

### 4. Persistance

Le projet exploite :

- SQLite pour la persistance locale
- Qdrant pour la mémoire vectorielle et la similarité
- cache de scans local pour accélérer les analyses répétées

### 5. Interface API

L'application FastAPI expose le pipeline de scan, la gestion des projets et les résultats d'analyse.

## Fichiers matériels à connaître

- `src/main.py` : point d'entrée principal
- `src/api.py` : API REST
- `src/graph/workflow.py` : graphe de workflow
- `src/graph/state.py` : modèles de données partagés
- `src/agents/` : implémentation des agents
- `memory-engine/` : binaire Rust de sécurité mémoire
