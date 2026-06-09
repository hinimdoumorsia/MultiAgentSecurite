# Benchmark MultiAgentSecurite - 2026-06-07T13:53:01.666511+00:00

- Runner : `agent`  |  cas : 200  |  runs/cas : 1
- Matching : tolerance=5 lignes, CWE `family`

## Datasets inclus

| Dataset | Cas | Langages | Piste | Qualite metriques |
|---|---|---|---|---|
| juliet | 200 | c, cpp | detection | high |

## Detection par dataset / langage

> `haute` = negatifs propres (precision/FPR fiables). `indicative` = negatifs bruites (rappel surtout, precision a titre indicatif).

| Dataset / Langage | TP | FP | FN | TN | Precision | Rappel | F1 | FPR | Youden J |
|---|---|---|---|---|---|---|---|---|---|
| juliet/c | 5 | 4 | 45 | 46 | 0.5556 | 0.1 | 0.1695 | 0.08 | 0.02 |
| juliet/cpp | 0 | 0 | 50 | 50 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

## Detection par langage (tous datasets confondus)

| Langage | TP | FP | FN | TN | Precision | Rappel | F1 | FPR | Youden J |
|---|---|---|---|---|---|---|---|---|---|
| c | 5 | 4 | 45 | 46 | 0.5556 | 0.1 | 0.1695 | 0.08 | 0.02 |
| cpp | 0 | 0 | 50 | 50 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| **GLOBAL (micro)** | 5 | 4 | 95 | 96 | **0.5556** | **0.05** | **0.0917** | 0.04 | **0.01** |

- **Macro-moyenne** : precision=0.2778 rappel=0.05 F1=0.0847 Youden=0.01
- **IC 95% du F1 (micro, bootstrap)** : [0.0194, 0.1667]

## Correction (repair)

| Langage | Tentes | Diff valide | Taux fix | Taux regression |
|---|---|---|---|---|
| **GLOBAL** | 0 | 0.0 | **0.0** | **0.0** |
