"""LLM client.

Actuellement : **Groq uniquement** (modèles "fast" et "strong"), avec **fallback
multi-clés** : plusieurs clés Groq sont chargées, et dès qu'une atteint sa limite
(rate limit / quota), le client bascule automatiquement sur la suivante.

Clés lues depuis .env : `GROQ_API_KEY`, puis toute variable `GROQ_API_KEY1`,
`GROQ_API_KEY2`, ... (ou `GROQ_API_KEY_1`, etc.). Ajouter une clé = ajouter une ligne.

Le client NVIDIA et sa clé restent câblés mais NON utilisés par défaut — conservés
pour un usage futur (benchmark comparatif de LLM, ajout d'OpenRouter...).
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path


def load_env():
    env_file = Path(__file__).parent.parent / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                os.environ[key.strip()] = value.strip()
                print(f"Loaded: {key.strip()}")

load_env()

from groq import Groq
from openai import OpenAI

logger = logging.getLogger(__name__)

# ── Modèles Groq (seuls utilisés actuellement) ────────────────────────────────
# Configurables via .env pour benchmarker différents modèles sans toucher au code.
# Ex. pour tester Llama 4 Scout :
#   GROQ_MODEL_STRONG=meta-llama/llama-4-scout-17b-16e-instruct
MODEL_FAST = os.environ.get("GROQ_MODEL_FAST", "llama-3.1-8b-instant")        # Groq — rapide (scoring, enrichissement)
MODEL_STRONG = os.environ.get("GROQ_MODEL_STRONG", "llama-3.3-70b-versatile") # Groq — puissant (analyse sémantique, patchs)

# ── Modèle NVIDIA (conservé pour usage futur / benchmark, non utilisé) ─────────
MODEL_STRONG_NVIDIA = "meta/llama-3.1-70b-instruct"


def _collect_groq_keys() -> list[str]:
    """Récupère toutes les clés Groq du .env : GROQ_API_KEY + GROQ_API_KEY1/2/...

    Ordre : la clé principale d'abord, puis les suffixées par ordre numérique.
    Doublons retirés en conservant l'ordre.
    """
    keys: list[tuple[int, str]] = []
    for name, value in os.environ.items():
        if not value:
            continue
        if name == "GROQ_API_KEY":
            keys.append((0, value))
        else:
            m = re.fullmatch(r"GROQ_API_KEY_?(\d+)", name)
            if m:
                keys.append((int(m.group(1)), value))
    keys.sort(key=lambda kv: kv[0])

    seen: set[str] = set()
    ordered: list[str] = []
    for _idx, val in keys:
        if val not in seen:
            seen.add(val)
            ordered.append(val)
    return ordered


def _is_quota_error(exc: Exception) -> bool:
    """Vrai si l'erreur indique une limite de débit / quota (bascule de clé utile)."""
    status = getattr(exc, "status_code", None)
    if status in (429, 413):
        return True
    text = str(exc).lower()
    return "rate_limit" in text or "rate limit" in text or "quota" in text or "too large" in text


class LLMClient:
    def __init__(self) -> None:
        groq_keys = _collect_groq_keys()
        nvidia_key = os.environ.get("NVIDIA_API_KEY")

        # Un client Groq par clé. La rotation se fait sur cette liste.
        self._groq_clients = [Groq(api_key=k) for k in groq_keys]
        self._key_index = 0  # clé courante (on reste dessus tant qu'elle répond)

        # Conservé pour un futur benchmark de LLM (NVIDIA / OpenRouter / etc.).
        self._nvidia = OpenAI(
            base_url="https://integrate.api.nvidia.com/v1",
            api_key=nvidia_key
        ) if nvidia_key else None

        self._total_calls = 0

        if not self._groq_clients:
            logger.warning("Aucune clé GROQ trouvée (GROQ_API_KEY / GROQ_API_KEY1 / ...)")
        else:
            logger.info("[llm] %d clé(s) Groq chargée(s) — fallback automatique activé", len(self._groq_clients))
        if not self._nvidia:
            logger.info("NVIDIA_API_KEY not set (optionnel — non utilisé actuellement)")

    def query(self, system: str, user: str, model: str = "fast", max_tokens: int = 4096) -> str:
        self._total_calls += 1

        # Les deux profils passent par Groq.
        model_name = MODEL_FAST if model == "fast" else MODEL_STRONG

        n = len(self._groq_clients)
        if n == 0:
            raise Exception("Aucune clé Groq configurée")

        last_exc: Exception | None = None
        # On essaie chaque clé, en partant de la clé courante puis en tournant.
        for attempt in range(n):
            idx = (self._key_index + attempt) % n
            client = self._groq_clients[idx]
            try:
                response = client.chat.completions.create(
                    model=model_name,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    temperature=0.2,
                    max_tokens=max_tokens,
                )
                # Cette clé répond : on reste dessus pour les prochains appels.
                self._key_index = idx
                return response.choices[0].message.content

            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if _is_quota_error(exc):
                    logger.warning(
                        "[llm] clé Groq #%d limitée (%s) → bascule sur la suivante",
                        idx + 1, getattr(exc, "status_code", "?"),
                    )
                    # Avance le pointeur pour ne pas re-cogner la clé saturée.
                    self._key_index = (idx + 1) % n
                    continue
                # Erreur non liée au quota (auth, réseau, payload) : inutile de
                # gaspiller les autres clés, on remonte tout de suite.
                logger.error("[llm] erreur non-quota sur clé #%d : %s", idx + 1, exc)
                raise

        logger.error("[llm] les %d clés Groq sont toutes limitées", n)
        raise last_exc if last_exc else Exception("Toutes les clés Groq sont épuisées")

    def stats(self) -> dict:
        return {"total_calls": self._total_calls, "groq_keys": len(self._groq_clients), "active_key": self._key_index + 1}
