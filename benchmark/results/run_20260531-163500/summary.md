# Benchmark MultiAgentSecurite - 2026-05-31T16:34:52.869102+00:00

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
| owasp/java | 1118 | 552 | 297 | 773 | 0.6695 | 0.7901 | 0.7248 | 0.4166 | 0.3735 |

## Detection par langage (tous datasets confondus)

| Langage | TP | FP | FN | TN | Precision | Rappel | F1 | FPR | Youden J |
|---|---|---|---|---|---|---|---|---|---|
| java | 1118 | 552 | 297 | 773 | 0.6695 | 0.7901 | 0.7248 | 0.4166 | 0.3735 |
| **GLOBAL (micro)** | 1118 | 552 | 297 | 773 | **0.6695** | **0.7901** | **0.7248** | 0.4166 | **0.3735** |

- **Macro-moyenne** : precision=0.6695 rappel=0.7901 F1=0.7248 Youden=0.3735
- **IC 95% du F1 (micro, bootstrap)** : [0.7068, 0.742]

## Correction (repair)

| Langage | Tentes | Diff valide | Taux fix | Taux regression |
|---|---|---|---|---|
| **GLOBAL** | 0 | 0.0 | **0.0** | **0.0** |
