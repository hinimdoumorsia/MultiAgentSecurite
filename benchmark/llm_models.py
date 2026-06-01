"""Registre des LLM à benchmarker (vérifiés accessibles sur les clés du projet).

Chaque entrée : slug -> (base_url, clé, model_id, description, max_tokens).
Un seul modèle par run (attribution propre).

Choix providers : Groq est épuisé (usage intensif de la journée -> 413/429), donc on
route la plupart des modèles via **NVIDIA NIM** (limites free plus généreuses) + **DeepSeek**
(payant, flash = rapide). max_tokens adapté par modèle (Groq TPM bas vs raisonnement
DeepSeek qui a besoin de place après le reasoning).
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

_GROQ = "https://api.groq.com/openai/v1"
_NVIDIA = "https://integrate.api.nvidia.com/v1"
_DEEPSEEK = "https://api.deepseek.com"
_NV = os.environ.get("NVIDIA_API_KEY")
_DS = os.environ.get("DEEPSEEK_API_KEY")
_GR = os.environ.get("GROQ_API_KEY")

# slug : (base, clé, model_id, description, max_tokens)
MODELS = {
    "nvidia-llama70b":  (_NVIDIA, _NV, "meta/llama-3.3-70b-instruct",                "moyen dense 70B",     4096),
    "nvidia-qwencoder": (_NVIDIA, _NV, "qwen/qwen3-coder-480b-a35b-instruct",        "spécialisé code 480B", 4096),
    "nvidia-maverick":  (_NVIDIA, _NV, "meta/llama-4-maverick-17b-128e-instruct",    "MoE multimodal",       4096),
    "nvidia-gptoss":    (_NVIDIA, _NV, "openai/gpt-oss-120b",                        "raisonnement 120B",    4096),
    "nvidia-nemotron":  (_NVIDIA, _NV, "nvidia/llama-3.3-nemotron-super-49b-v1",     "nemotron 49B",         4096),
    "deepseek-v4":      (_DEEPSEEK, _DS, "deepseek-v4-flash",                        "raisonnement (payant)", 8192),
}

# Limite de caractères du fichier envoyé (réduit -> évite 413/timeout).
INPUT_CHARS = 4000


def client_for(slug):
    """Retourne (OpenAI client robuste, model_id, description, max_tokens)."""
    from openai import OpenAI
    if slug not in MODELS:
        raise KeyError(f"modèle inconnu: {slug}. Dispo: {sorted(MODELS)}")
    base, key, model, desc, maxtok = MODELS[slug]
    if not key:
        raise RuntimeError(f"clé manquante pour {slug}")
    # timeout + retries modérés : on échoue assez vite sur un throttle persistant
    # (NVIDIA free saturé) pour ne pas bloquer 2 min/appel ; un modèle KO sera noté.
    cli = OpenAI(base_url=base, api_key=key, timeout=90,
                 max_retries=int(os.environ.get("LLM_MAX_RETRIES", "2")))
    return cli, model, desc, maxtok
