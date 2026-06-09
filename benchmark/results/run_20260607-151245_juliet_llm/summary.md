# Benchmark MultiAgentSecurite - 2026-06-07T15:12:44.478950+00:00

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
| juliet/c | 48 | 46 | 2 | 4 | 0.5106 | 0.96 | 0.6667 | 0.92 | 0.04 |
| juliet/cpp | 35 | 31 | 15 | 19 | 0.5303 | 0.7 | 0.6034 | 0.62 | 0.08 |

## Detection par langage (tous datasets confondus)

| Langage | TP | FP | FN | TN | Precision | Rappel | F1 | FPR | Youden J |
|---|---|---|---|---|---|---|---|---|---|
| c | 48 | 46 | 2 | 4 | 0.5106 | 0.96 | 0.6667 | 0.92 | 0.04 |
| cpp | 35 | 31 | 15 | 19 | 0.5303 | 0.7 | 0.6034 | 0.62 | 0.08 |
| **GLOBAL (micro)** | 83 | 77 | 17 | 23 | **0.5188** | **0.83** | **0.6385** | 0.77 | **0.06** |

- **Macro-moyenne** : precision=0.5205 rappel=0.83 F1=0.6351 Youden=0.06
- **IC 95% du F1 (micro, bootstrap)** : [0.5703, 0.7041]

## Correction (repair)

| Langage | Tentes | Diff valide | Taux fix | Taux regression |
|---|---|---|---|---|
| **GLOBAL** | 0 | 0.0 | **0.0** | **0.0** |
