# Benchmark MultiAgentSecurite - 2026-06-06T21:25:58.026914+00:00

- Runner : `agent`  |  cas : 2740  |  runs/cas : 1
- Matching : tolerance=5 lignes, CWE `family`

## Datasets inclus

| Dataset | Cas | Langages | Piste | Qualite metriques |
|---|---|---|---|---|
| owasp | 2740 | java | detection | high |

## Detection par dataset / langage

> `haute` = negatifs propres (precision/FPR fiables). `indicative` = negatifs bruites (rappel surtout, precision a titre indicatif).

| Dataset / Langage | TP | FP | FN | TN | Precision | Rappel | F1 | FPR | Youden J |
|---|---|---|---|---|---|---|---|---|---|
| owasp/java | 1361 | 696 | 54 | 629 | 0.6616 | 0.9618 | 0.784 | 0.5253 | 0.4366 |

## Detection par langage (tous datasets confondus)

| Langage | TP | FP | FN | TN | Precision | Rappel | F1 | FPR | Youden J |
|---|---|---|---|---|---|---|---|---|---|
| java | 1361 | 696 | 54 | 629 | 0.6616 | 0.9618 | 0.784 | 0.5253 | 0.4366 |
| **GLOBAL (micro)** | 1361 | 696 | 54 | 629 | **0.6616** | **0.9618** | **0.784** | 0.5253 | **0.4366** |

- **Macro-moyenne** : precision=0.6616 rappel=0.9618 F1=0.784 Youden=0.4366
- **IC 95% du F1 (micro, bootstrap)** : [0.7695, 0.799]

## Correction (repair)

| Langage | Tentes | Diff valide | Taux fix | Taux regression |
|---|---|---|---|---|
| **GLOBAL** | 0 | 0.0 | **0.0** | **0.0** |
