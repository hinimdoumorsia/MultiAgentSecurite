"""Inspecte la structure d'un dataset HuggingFace CVEfixes (streaming, sans tout DL)."""
import sys

name = sys.argv[1] if len(sys.argv) > 1 else "hitoshura25/cvefixes"
try:
    from datasets import load_dataset
except Exception as e:
    print("DATASETS_ABSENT:", e)
    sys.exit(2)

try:
    ds = load_dataset(name, split="train", streaming=True)
    row = next(iter(ds))
    print("=== DATASET:", name, "===")
    print("=== COLONNES / apercu valeurs ===")
    for k, v in row.items():
        s = str(v).replace("\n", " ")[:90]
        print(f"- {k}: {s}")
except Exception as e:
    print("ERREUR_CHARGEMENT:", type(e).__name__, str(e)[:300])
    sys.exit(3)
