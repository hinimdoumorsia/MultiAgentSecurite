# Multi-Agent Security

Multi-Agent Security est un système de sécurité logicielle basé sur des agents spécialisés qui collaborent pour détecter, analyser, corriger et valider les vulnérabilités dans le code source.

## Vue d'ensemble

Le projet combine plusieurs briques :

- scan statique multi-outils (Semgrep, Bandit, Gosec, SpotBugs, PHP CodeSniffer)
- moteur Rust pour la sécurité mémoire
- agents LLM pour l'analyse sémantique et le scoring d'exploitabilité
- génération de correctifs automatisés
- validation de patchs et génération de rapports

## Architecture générale

Le pipeline suit un schéma typique :

1. Triage des fichiers et des langages
2. Analyse statique des cibles
3. Analyse mémoire sur C/C++/Rust
4. Analyse sémantique des vulnérabilités prioritaires
5. Scoring CVSS et exploitabilité
6. Génération du correctif
7. Validation du patch
8. Rapport final

## Stack technique

- Python 3.11+
- FastAPI
- LangGraph
- SQLite / Qdrant
- Semgrep et outils SAST
- Modèles LLM via Groq / NVIDIA
- Moteur Rust pour la sécurité mémoire

## Références du dépôt

- `src/` : code principal du système
- `memory-engine/` : moteur Rust dédié à la sécurité mémoire
- `benchmark/` : évaluations, métriques et jeux de données
- `docs/` : documentation technique

!!! tip
    La documentation ci-dessous est destinée à faciliter la compréhension du flux de travail, des agents et des interfaces de ce projet.
