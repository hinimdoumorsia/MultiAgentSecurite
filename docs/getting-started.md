# Démarrage rapide

## Prérequis

Avant de lancer le projet, vérifiez que vous avez :

- Python 3.11+
- Git
- un accès réseau pour installer les dépendances
- au moins une clé API LLM (Groq ou NVIDIA)

## Installation

```bash
git clone https://github.com/hinimdoumorsia/MultiAgentSecurite.git
cd MultiAgentSecurite
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Pour Windows PowerShell :

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Variables d'environnement

Créez un fichier `.env` dans le dossier `src/` si nécessaire :

```env
GROQ_API_KEY=your_key_here
NVIDIA_API_KEY=your_key_here
GITHUB_TOKEN=optional_token
QDRANT_HOST=localhost
QDRANT_PORT=6333
```

!!! warning
    Ne commitez jamais votre fichier `.env`.

## Lancer l'API

```bash
python -c "import sys; sys.path.insert(0, 'src'); from api import app; import uvicorn; uvicorn.run(app, host='0.0.0.0', port=8000)"
```

L'API sera disponible sur :

- `http://localhost:8000`
- `http://localhost:8000/docs`

## Premier scan

Un scan local peut être démarré via l'API REST ou via l'orchestrateur Python du projet.

```bash
curl -X POST http://localhost:8000/scan/local \
  -H "Content-Type: application/json" \
  -d '{"repo_path": "/chemin/vers/votre/projet", "max_iterations": 3}'
```

## Outils optionnels

Selon les langages ciblés, il peut être nécessaire d'avoir certains outils installés :

- `semgrep`
- `bandit`
- `gosec`
- `spotbugs`
- `phpcs`
- Rust toolchain pour le moteur `memory-engine`
