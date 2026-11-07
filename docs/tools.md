# Outils de scan

Le projet s'appuie sur plusieurs outils de sécurité pour maximiser la couverture de détection.

## Outils supportés

- **Semgrep** : scan multi-langage avec règles de sécurité
- **Bandit** : analyse Python
- **Gosec** : analyse Go
- **SpotBugs** : analyse Java
- **PHPCS** : analyse PHP
- **Memory Engine** : analyse mémoire C/C++/Rust

## Répertoires pertinents

- `src/tools/semgrep_tool.py`
- `src/tools/bandit_tool.py`
- `src/tools/gosec_tool.py`
- `src/tools/spotbugs_tool.py`
- `src/tools/phpcs_tool.py`
- `memory-engine/`

## Objectif

La combinaison de plusieurs outils permet de couvrir :

- les règles standardisées,
- les failles logiques,
- les risques de sécurité mémoire,
- les vulnérabilités spécifiques à certains langages.
