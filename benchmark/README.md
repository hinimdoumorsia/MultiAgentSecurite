# Benchmark — MultiAgentSecurite

Harness d'evaluation **scientifique** de l'agent : qualite de **detection**
(precision, rappel, F1, FPR, Youden's J) et qualite de **correction**
(taux de fix, taux de regression, validite du diff), **par langage** et **global**,
sur des **datasets etiquetes** (verite terrain).

> Pourquoi pas "200 depots aleatoires" ? Sans verite terrain on ne peut calculer
> ni precision ni rappel. Un seul dataset comme OWASP Benchmark fournit ~2740 cas
> labellises = bien plus de puissance statistique que 200 depots non labellises.

## Demarrage rapide (sans API, pour valider l'installation)

```bash
python -m benchmark.harness.runner --dataset synthetic --mock
```

Le mode `--mock` n'appelle pas l'agent : il lit des findings preenregistres
(`_mock_findings.json`) sur le mini-dataset `datasets/synthetic/` (cas TP/FP/FN/TN
connus). Sert a verifier que matching + metriques tombent juste.
Resultat attendu : `P=0.6667 R=0.6667 F1=0.6667 FPR=0.5 YoudenJ=0.1667`.

## Lancer le vrai agent

Prerequis : cles API dans `src/.env` (GROQ_API_KEY, NVIDIA_API_KEY) + outils SAST
(`semgrep`, `bandit`...) installes. Puis :

```bash
python -m benchmark.harness.runner --dataset synthetic        # sur le mini-dataset
python -m benchmark.harness.runner                            # tous les datasets 'enabled'
```

## Ajouter un dataset reel

1. Telecharger le dataset dans `datasets/<nom>/` (gitignored).
2. Activer le bloc correspondant dans `config.yaml` (`enabled: true`).
3. Si besoin, ecrire un adapter dans `harness/adapters/<nom>.py` exposant
   `load(cfg) -> list[GroundTruthLabel]`, et l'enregistrer dans
   `harness/adapters/__init__.py`.

Datasets cibles (cf. plan) :

| Langage | Detection | Correction | Adapter |
|---|---|---|---|
| Java | OWASP Benchmark (`expectedresults-1.2.csv`) | Vul4J | `owasp` (fait), `vul4j` (a faire) |
| C/C++ | Juliet (NIST SARD) | Big-Vul / CVEfixes | `juliet` (a faire) |
| Python | SARD Python, SecurityEval | CVEfixes | `cvefixes` (a faire) |
| JS/TS, Go, PHP | CVEfixes | CVEfixes | `cvefixes` (a faire) |

### OWASP Benchmark (Java) — recommande pour le premier resultat
```bash
git clone https://github.com/OWASP-Benchmark/BenchmarkJava \
  benchmark/datasets/owasp/benchmark
# puis dans config.yaml : datasets.owasp.enabled: true
python -m benchmark.harness.runner --dataset owasp
```
Tous les cas OWASP partagent le meme projet : le runner ne scanne qu'**une fois**
puis classe les ~2740 cas (cache par `repo_path`).

## Sorties (dans `results/`)

- `detection_<stamp>.csv` — TP/FP/FN/TN + P/R/F1/FPR/Youden par langage + GLOBAL
- `summary_<stamp>.md` — tableaux prets pour le memoire (+ IC 95% bootstrap)
- `summary_<stamp>.json` — tout l'agrege
- `raw/records_<stamp>.json` — 1 ligne par (cas, run) pour analyse fine

## Parametres (`config.yaml`)

- `agent.runs_per_case` : repeter k fois chaque cas (LLM stochastiques) pour mean +/- std.
- `matching.line_tolerance` : +/- N lignes de chevauchement pour un TP.
- `matching.cwe_mode` : `exact` ou `family` (accepte parent/enfant via `cwe_map.py`).

## Architecture

```
config.yaml
harness/
  schema.py            GroundTruthLabel, AgentFinding, CaseResult
  cwe_map.py           hierarchie CWE (matching tolerant)
  match.py             findings <-> labels -> TP/FP/FN/TN
  detection_metrics.py P/R/F1/FPR/Youden, micro/macro, IC bootstrap
  run_agent.py         AgentRunner (workflow reel) | MockRunner (sans API)
  repair_verify.py     applique le patch en copie, lance tests vuln + fonctionnels
  repair_metrics.py    taux fix / regression / diff valide
  runner.py            orchestration + ecriture des resultats
  adapters/            owasp.py, synthetic.py (+ juliet/vul4j/cvefixes a venir)
datasets/              datasets (synthetic versionne ; le reste gitignored)
results/               sorties (gitignored)
```

## Limites a documenter dans le memoire

- **Contamination** : les LLM ont pu voir OWASP/Juliet a l'entrainement -> garder
  un holdout recent (CVE 2024-2025).
- **Granularite CWE** : le matching `family` peut sur/sous-compter -> reporter aussi en `exact`.
- **Quotas free-tier** (Groq/NVIDIA) : vrai goulot sur gros volume -> backoff + `.scan_cache`.
- **Stochasticite LLM** : utiliser `runs_per_case >= 3` et reporter l'ecart-type.

## Extension future : comparatif

Brancher un concurrent = ajouter un runner qui ressort une `list[AgentFinding]`
(Claude Code CLI, Semgrep nu, Snyk... automatisables ; Copilot/Antigravity/Kilocode
sur sous-ensemble manuel). Memes datasets, memes metriques -> comparaison directe,
sans toucher au coeur du harness.
