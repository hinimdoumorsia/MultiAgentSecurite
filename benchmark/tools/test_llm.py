"""Test rapide des API LLM (Groq + NVIDIA)."""
import sys
sys.path.insert(0, "src")
from llm.client import LLMClient

c = LLMClient()
for model in ("fast", "nvidia"):
    try:
        r = c.query(system="Reply with only: OK", user="ping", model=model, max_tokens=10)
        print(f"{model}: OK -> {repr((r or '')[:40])}")
    except Exception as e:
        print(f"{model}: ECHEC -> {type(e).__name__}: {str(e)[:120]}")
