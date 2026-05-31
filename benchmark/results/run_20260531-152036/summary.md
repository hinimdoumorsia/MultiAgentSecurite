# Benchmark MultiAgentSecurite - 2026-05-31T15:20:34.897641+00:00

- Runner : `agent`  |  cas : 798  |  runs/cas : 1
- Matching : tolerance=5 lignes, CWE `family`

## Datasets inclus

| Dataset | Cas | Langages | Piste | Qualite metriques |
|---|---|---|---|---|
| cvefixes | 798 | c, cpp, go, java, javascript, php, python, typescript | detection | indicative |

## Detection par dataset / langage

> `haute` = negatifs propres (precision/FPR fiables). `indicative` = negatifs bruites (rappel surtout, precision a titre indicatif).

| Dataset / Langage | TP | FP | FN | TN | Precision | Rappel | F1 | FPR | Youden J |
|---|---|---|---|---|---|---|---|---|---|
| cvefixes/c | 15 | 45 | 35 | 5 | 0.25 | 0.3 | 0.2727 | 0.9 | -0.6 |
| cvefixes/cpp | 14 | 45 | 36 | 5 | 0.2373 | 0.28 | 0.2569 | 0.9 | -0.62 |
| cvefixes/go | 14 | 42 | 36 | 7 | 0.25 | 0.28 | 0.2642 | 0.8571 | -0.5771 |
| cvefixes/java | 13 | 40 | 37 | 10 | 0.2453 | 0.26 | 0.2524 | 0.8 | -0.54 |
| cvefixes/javascript | 4 | 36 | 46 | 14 | 0.1 | 0.08 | 0.0889 | 0.72 | -0.64 |
| cvefixes/php | 12 | 39 | 38 | 11 | 0.2353 | 0.24 | 0.2376 | 0.78 | -0.54 |
| cvefixes/python | 16 | 33 | 34 | 17 | 0.3265 | 0.32 | 0.3232 | 0.66 | -0.34 |
| cvefixes/typescript | 8 | 36 | 42 | 13 | 0.1818 | 0.16 | 0.1702 | 0.7347 | -0.5747 |

## Detection par langage (tous datasets confondus)

| Langage | TP | FP | FN | TN | Precision | Rappel | F1 | FPR | Youden J |
|---|---|---|---|---|---|---|---|---|---|
| c | 15 | 45 | 35 | 5 | 0.25 | 0.3 | 0.2727 | 0.9 | -0.6 |
| javascript | 4 | 36 | 46 | 14 | 0.1 | 0.08 | 0.0889 | 0.72 | -0.64 |
| python | 16 | 33 | 34 | 17 | 0.3265 | 0.32 | 0.3232 | 0.66 | -0.34 |
| cpp | 14 | 45 | 36 | 5 | 0.2373 | 0.28 | 0.2569 | 0.9 | -0.62 |
| php | 12 | 39 | 38 | 11 | 0.2353 | 0.24 | 0.2376 | 0.78 | -0.54 |
| go | 14 | 42 | 36 | 7 | 0.25 | 0.28 | 0.2642 | 0.8571 | -0.5771 |
| java | 13 | 40 | 37 | 10 | 0.2453 | 0.26 | 0.2524 | 0.8 | -0.54 |
| typescript | 8 | 36 | 42 | 13 | 0.1818 | 0.16 | 0.1702 | 0.7347 | -0.5747 |
| **GLOBAL (micro)** | 96 | 316 | 304 | 82 | **0.233** | **0.24** | **0.2365** | 0.794 | **-0.554** |

- **Macro-moyenne** : precision=0.2283 rappel=0.24 F1=0.2333 Youden=-0.554
- **IC 95% du F1 (micro, bootstrap)** : [0.1982, 0.2729]

## Correction (repair)

| Langage | Tentes | Diff valide | Taux fix | Taux regression |
|---|---|---|---|---|
| **GLOBAL** | 0 | 0.0 | **0.0** | **0.0** |
