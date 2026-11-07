# API

Le projet expose une API REST pour lancer des scans et récupérer les résultats.

## Endpoints principaux

- `GET /` : statut du service
- `POST /scan/local` : analyser un dépôt local
- `POST /scan/github` : analyser un dépôt GitHub
- `GET /scan/local/{scan_id}` : obtenir le statut d'un scan
- `GET /scan/local/{scan_id}/vulnerabilities` : récupérer les vulnérabilités

## Exemple

```bash
curl http://localhost:8000
```

```json
{
  "service": "Multi-Agent Security Scanner",
  "version": "1.0.0",
  "status": "running",
  "agents": 8
}
```

!!! note
    L'API est déclarée dans `src/api.py` et sert de front-end aux agents et scanners du système.
