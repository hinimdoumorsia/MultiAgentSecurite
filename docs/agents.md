# Agents

Le système est fondé sur plusieurs agents ayant des rôles complémentaires.

## Liste des agents

| Agent | Rôle |
| --- | --- |
| `TriageAgent` | Détecte les langages et les fichiers à analyser |
| `ScannerAgent` | Lance les analyses statiques et normalise les résultats |
| `MemorySafetyAgent` | Analyse les problèmes de mémoire C/C++/Rust |
| `SemanticAnalystAgent` | Vérifie les vulnérabilités logiques et contextuelles |
| `ExploitScorerAgent` | Évalue la gravité et l'exploitabilité |
| `PatcherAgent` | Génère les correctifs |
| `ValidatorAgent` | Vérifie la validité du correctif et les régressions |
| `ReportAgent` | Rassemble les résultats et produit le rapport final |

## Rôle de la collaboration

L'intérêt du design multi-agents est de séparer :

- détection brute,
- analyse contextuelle,
- décision de priorité,
- correction,
- validation.

Cette séparation aide à réduire les faux positifs et à mieux hiérarchiser les correctifs.
