# Benchmark MultiAgentSecurite - 2026-06-06T23:09:42.707805+00:00

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
| cvefixes/c | 0 | 10 | 50 | 40 | 0.0 | 0.0 | 0.0 | 0.2 | -0.2 |
| cvefixes/cpp | 0 | 12 | 50 | 38 | 0.0 | 0.0 | 0.0 | 0.24 | -0.24 |
| cvefixes/go | 0 | 0 | 50 | 49 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| cvefixes/java | 0 | 0 | 50 | 50 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| cvefixes/javascript | 0 | 0 | 50 | 50 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| cvefixes/php | 0 | 0 | 50 | 50 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| cvefixes/python | 1 | 2 | 49 | 48 | 0.3333 | 0.02 | 0.0377 | 0.04 | -0.02 |
| cvefixes/typescript | 0 | 2 | 50 | 47 | 0.0 | 0.0 | 0.0 | 0.0408 | -0.0408 |

## Detection par langage (tous datasets confondus)

| Langage | TP | FP | FN | TN | Precision | Rappel | F1 | FPR | Youden J |
|---|---|---|---|---|---|---|---|---|---|
| c | 0 | 10 | 50 | 40 | 0.0 | 0.0 | 0.0 | 0.2 | -0.2 |
| javascript | 0 | 0 | 50 | 50 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| python | 1 | 2 | 49 | 48 | 0.3333 | 0.02 | 0.0377 | 0.04 | -0.02 |
| cpp | 0 | 12 | 50 | 38 | 0.0 | 0.0 | 0.0 | 0.24 | -0.24 |
| php | 0 | 0 | 50 | 50 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| go | 0 | 0 | 50 | 49 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| java | 0 | 0 | 50 | 50 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| typescript | 0 | 2 | 50 | 47 | 0.0 | 0.0 | 0.0 | 0.0408 | -0.0408 |
| **GLOBAL (micro)** | 1 | 26 | 399 | 372 | **0.037** | **0.0025** | **0.0047** | 0.0653 | **-0.0628** |

- **Macro-moyenne** : precision=0.0417 rappel=0.0025 F1=0.0047 Youden=-0.0626
- **IC 95% du F1 (micro, bootstrap)** : [0.0, 0.0146]

## Correction (repair)

| Langage | Tentes | Diff valide | Taux fix | Taux regression |
|---|---|---|---|---|
| **GLOBAL** | 0 | 0.0 | **0.0** | **0.0** |
