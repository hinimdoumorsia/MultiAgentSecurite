# Benchmark MultiAgentSecurite - 2026-05-31T19:10:17.410186+00:00

- Runner : `agent (re-score category, file-level)`  |  cas : 200  |  runs/cas : 1
- Matching : tolerance=5 lignes, CWE `family`

## Datasets inclus

| Dataset | Cas | Langages | Piste | Qualite metriques |
|---|---|---|---|---|
| juliet | 200 | c, cpp | detection | high |

## Detection par dataset / langage

> `haute` = negatifs propres (precision/FPR fiables). `indicative` = negatifs bruites (rappel surtout, precision a titre indicatif).

| Dataset / Langage | TP | FP | FN | TN | Precision | Rappel | F1 | FPR | Youden J |
|---|---|---|---|---|---|---|---|---|---|
| juliet/c | 48 | 45 | 2 | 5 | 0.5161 | 0.96 | 0.6713 | 0.9 | 0.06 |
| juliet/cpp | 33 | 29 | 17 | 21 | 0.5323 | 0.66 | 0.5893 | 0.58 | 0.08 |

## Detection par langage (tous datasets confondus)

| Langage | TP | FP | FN | TN | Precision | Rappel | F1 | FPR | Youden J |
|---|---|---|---|---|---|---|---|---|---|
| c | 48 | 45 | 2 | 5 | 0.5161 | 0.96 | 0.6713 | 0.9 | 0.06 |
| cpp | 33 | 29 | 17 | 21 | 0.5323 | 0.66 | 0.5893 | 0.58 | 0.08 |
| **GLOBAL (micro)** | 81 | 74 | 19 | 26 | **0.5226** | **0.81** | **0.6353** | 0.74 | **0.07** |

- **Macro-moyenne** : precision=0.5242 rappel=0.81 F1=0.6303 Youden=0.07
- **IC 95% du F1 (micro, bootstrap)** : [0.5656, 0.7007]

## Correction (repair)

| Langage | Tentes | Diff valide | Taux fix | Taux regression |
|---|---|---|---|---|
| **GLOBAL** | 0 | 0.0 | **0.0** | **0.0** |
