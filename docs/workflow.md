# Workflow

Le workflow suit un enchaînement logique, de la détection au rapport final.

## Étapes

### 1. Triage

L'agent de triage identifie les langages présents et sélectionne les fichiers à analyser.

### 2. Analyse statique

Les scanners externes sont lancés sur les fichiers concernés. Les résultats sont normalisés dans un format commun.

### 3. Analyse mémoire

Pour les projets C/C++/Rust, le moteur Rust détecte les risques liés aux pointeurs, allocations, fuites mémoire et opérations dangereuses.

### 4. Analyse sémantique

Les vulnérabilités prioritaires sont ensuite passées à un agent basé sur LLM afin d'évaluer les risques logique et contextuel.

### 5. Scoring et priorisation

Chaque vulnérabilité est évaluée selon des critères de gravité, d'impact et d'exploitabilité. Cela permet de ne corriger que les éléments les plus pertinents.

### 6. Patching

L'agent de patch crée un diff unifié pour corriger la vulnérabilité détectée.

### 7. Validation

Le patch est vérifié via re-scan, tests et contrôle de régression.

### 8. Rapport final

Le résultat est consolidé dans un rapport structuré, avec détails de vulnérabilité, statut du patch et métriques.

## Exemple de séquence

```text
triage -> scanner -> memory_safety -> semantic_analyst -> exploit_scorer -> patcher -> validator -> report
```

!!! note
    Le flux peut être composé en mode détection seule ou en mode correction complète selon les options du workflow.
