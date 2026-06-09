"""Registre des LLM à benchmarker (vérifiés accessibles sur les clés du projet).

Chaque entrée : slug -> (base_url, clé, model_id, description, max_tokens).
Un seul modèle par run (attribution propre).

ROUTAGE : via **OpenRouter** (payant, budget ~2$) — fiable (pas le throttling/timeout
du free-tier NVIDIA qui sature sous charge soutenue). Les 6 mêmes modèles y sont dispos.
NB : les comparaisons détection/correction déjà faites l'ont été via NVIDIA NIM (gratuit) ;
on garde OpenRouter pour les runs qui restent (ex. Vul4J par-modèle) afin d'éviter les timeouts.
"""
from __future__ import annotations
import os
from pathlib import Path

def _load_env():
    f = Path(__file__).resolve().parents[1] / "src" / ".env"
    if f.exists():
        for line in f.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

_load_env()

_OR = "https://openrouter.ai/api/v1"
_ORK = os.environ.get("OPENROUTER_API_KEY")

# slug : (base, clé, model_id OpenRouter, description, max_tokens)
MODELS = {
    "llama70b":   (_OR, _ORK, "meta-llama/llama-3.3-70b-instruct",            "moyen dense 70B",      4096),
    "qwencoder":  (_OR, _ORK, "qwen/qwen3-coder",                             "spécialisé code",      4096),
    "maverick":   (_OR, _ORK, "meta-llama/llama-4-maverick",                  "MoE multimodal",       4096),
    "gptoss":     (_OR, _ORK, "openai/gpt-oss-120b",                          "raisonnement 120B",    4096),
    "nemotron":   (_OR, _ORK, "nvidia/llama-3.3-nemotron-super-49b-v1.5",     "nemotron 49B",         4096),
    "deepseek-v4":(_OR, _ORK, "deepseek/deepseek-v4-flash",                   "raisonnement",         8192),
}

INPUT_CHARS = 4000

# ─── Reproductibilité : versions de modèles FIGÉES (gelées au 2026-06) ──────────
# Les identifiants du dict MODELS sont volontairement pinnés (pas d'alias "latest").
# Modèles utilisés HORS de cette comparaison (renseignés pour la traçabilité) :
#   - Détection sémantique Phase 1 : "llama-3.1-8b-instant" (Groq, free-tier)
#   - PatcherAgent (correction)     : "deepseek-v4-flash"   (provider DeepSeek/OpenRouter)
# Décodage : temperature=0.2 partout. Les LLM hébergés ne garantissent PAS un
# décodage déterministe même à seed fixé (cf. rapport, section limites).
LLM_SEED = 0
FROZEN_AT = "2026-06"


def client_for(slug):
    """Retourne (OpenAI client robuste, model_id, description, max_tokens)."""
    from openai import OpenAI
    if slug not in MODELS:
        raise KeyError(f"modèle inconnu: {slug}. Dispo: {sorted(MODELS)}")
    base, key, model, desc, maxtok = MODELS[slug]
    if not key:
        raise RuntimeError(f"clé manquante pour {slug}")
    cli = OpenAI(base_url=base, api_key=key, timeout=120,
                 max_retries=int(os.environ.get("LLM_MAX_RETRIES", "3")))
    return cli, model, desc, maxtok
