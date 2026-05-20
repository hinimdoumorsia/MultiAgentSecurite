# SecureCodeAgent

Outil d'analyse de sécurité de code multi-agent basé sur **LangGraph** + **Groq (LLaMA 3.3 70B)**.  
Combine l'analyse statique (Bandit / Semgrep) et la révision LLM pour détecter les vulnérabilités OWASP Top 10.

---

## Prérequis

- Python 3.10+
- `git` installé et accessible dans le PATH
- Un compte [Groq](https://console.groq.com) (gratuit) pour obtenir une clé API

---

## Installation

```bash
# 1. Cloner ou extraire le projet
cd SecureCodeAgent

# 2. Installer les dépendances
pip install -r requirements.txt
```

---

## Configuration — Clé API Groq (OBLIGATOIRE)

1. Créer un compte sur **https://console.groq.com**
2. Aller dans **API Keys** → **Create API Key**
3. Copier la clé générée (commence par `gsk_...`)
4. Ouvrir le fichier **`.env`** à la racine du projet et remplir :

```env
GROQ_API_KEY=gsk_VOTRE_CLE_API_ICI
```

> **Sans cette clé, l'analyse LLM ne fonctionnera pas.**

Le fichier `.env` complet ressemble à ceci :

```env
# Obligatoire — clé API Groq (https://console.groq.com)
GROQ_API_KEY=gsk_VOTRE_CLE_API_ICI

# Optionnel — clé pour l'API REST (par défaut : dev-key-change-me)
SECURE_AGENT_API_KEY=dev-key-change-me

# Optionnel — token GitHub pour les dépôts privés
# GITHUB_TOKEN=ghp_...

# Optionnel — configuration du serveur API
API_HOST=0.0.0.0
API_PORT=8000
```

---

## Commandes CLI

### Analyser un dépôt GitHub

```bash
python main.py analyze https://github.com/utilisateur/repo --language python
```

### Analyser un dossier local

```bash
python main.py analyze . --language python
```

### Exporter le rapport en JSON

```bash
python main.py analyze . --language python --output rapport.json
```

### Analyser des fichiers spécifiques

```bash
python main.py analyze . --language python --files app.py utils/auth.py
```

### Afficher la mémoire de session complète en fin d'analyse

```bash
python main.py analyze . --language python --dump-memory
```

### Langages supportés

```
python | javascript | typescript | java | go | php | ruby | rust
```

---

## Serveur API REST

### Démarrer le serveur

```bash
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

### Ouvrir l'interface web (Swagger UI)

```
http://localhost:8000/docs
```

> Dans Swagger, cliquer sur **Authorize** et entrer la valeur de `SECURE_AGENT_API_KEY` (par défaut `dev-key-change-me`).

### Endpoints disponibles

| Méthode | URL | Description |
|---|---|---|
| `GET` | `/health` | Vérifier que le serveur tourne |
| `POST` | `/analyze` | Lancer une analyse en arrière-plan (retourne un `job_id`) |
| `GET` | `/jobs/{job_id}` | Récupérer le résultat d'un job |
| `POST` | `/analyze/sync` | Analyse synchrone (attend le résultat, timeout 5 min) |
| `GET` | `/analyze/stream` | Résultats en temps réel via Server-Sent Events |

### Exemple avec curl

```bash
# Analyse synchrone
curl -X POST http://localhost:8000/analyze/sync \
  -H "X-API-Key: dev-key-change-me" \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/utilisateur/repo", "language": "python"}'

# Stream en temps réel
curl -N -H "X-API-Key: dev-key-change-me" \
  "http://localhost:8000/analyze/stream?repo_url=https://github.com/utilisateur/repo"
```

---

## Structure du projet

```
SecureCodeAgent/
├── main.py                  # Point d'entrée CLI
├── requirements.txt         # Dépendances Python
├── .env                     # Configuration (clés API) — NE PAS COMMITER
├── core/
│   ├── orchestrator.py      # Pipeline LangGraph multi-agent
│   └── reporter.py          # Interface terminal Live (Rich)
├── agents/
│   ├── indexation_agent.py  # Indexation du code (local ou GitHub)
│   ├── security_agent.py    # Analyse statique Bandit + Semgrep
│   ├── review_agent.py      # Révision LLM via Groq
│   ├── aggregator_agent.py  # Agrégation CVSS + score de risque
│   └── patch_agent.py       # Génération de patchs
└── api/
    └── main.py              # Serveur FastAPI REST
```

---

## Résolution des problèmes courants

| Erreur | Solution |
|---|---|
| `GROQ_API_KEY manquante` | Remplir `.env` avec votre clé Groq |
| `Rate limit Groq` | Normal sur le plan gratuit — l'outil réessaie automatiquement |
| `git clone échoué` | Vérifier que `git` est installé : `git --version` |
| `ModuleNotFoundError` | Relancer `pip install -r requirements.txt` |
