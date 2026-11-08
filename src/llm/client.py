"""Client LLM multi-provider avec rotation croisée.

Tous les providers exposent une API compatible OpenAI -> on les unifie via le SDK
`openai` (un client par couple provider+clé).

Deux pools :
  - STRONG : DeepSeek > NVIDIA > Groq (gpt-oss-120b) > OpenRouter (strong).
  - FAST   : Groq (gpt-oss-20b) > OpenRouter (fast) > repli sur le pool strong.

`query(model="fast"|"strong")` parcourt le pool ; en cas de rate-limit, quota,
modèle/clé invalide ou erreur serveur, il bascule sur l'endpoint suivant.

Modèles surchargeables via .env : GROQ_MODEL_STRONG, GROQ_MODEL_FAST,
NVIDIA_MODEL_STRONG, DEEPSEEK_MODEL_STRONG, OPENROUTER_MODEL_STRONG,
OPENROUTER_MODEL_FAST.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


def _find_env_file() -> Path | None:
    """Cherche le .env : racine du projet, puis src/, puis dossier courant."""
    here = Path(__file__).resolve()
    candidates = [
        here.parents[2] / ".env",   # MultiAgentSecurite/.env  (racine projet)
        here.parents[1] / ".env",   # src/.env
        Path.cwd() / ".env",        # dossier d'où uvicorn est lancé
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None


def load_env() -> None:
    env_file = _find_env_file()
    if env_file is None:
        logger.warning("[llm] Aucun fichier .env trouvé")
        return
    # utf-8-sig : gère le BOM ajouté par le Bloc-notes Windows
    for line in env_file.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        # Commentaire en fin de ligne seulement s'il est précédé d'un espace
        value = re.split(r"\s+#", value, maxsplit=1)[0].strip().strip("'\"")
        if key:
            os.environ[key] = value
    logger.info("[llm] .env chargé depuis %s", env_file)


load_env()

from openai import OpenAI  # noqa: E402

_GROQ_BASE = "https://api.groq.com/openai/v1"
_NVIDIA_BASE = "https://integrate.api.nvidia.com/v1"
_DEEPSEEK_BASE = "https://api.deepseek.com"
_OPENROUTER_BASE = "https://openrouter.ai/api/v1"

_GROQ_STRONG = os.environ.get("GROQ_MODEL_STRONG", "openai/gpt-oss-120b")
_GROQ_FAST = os.environ.get("GROQ_MODEL_FAST", "openai/gpt-oss-20b")
_NVIDIA_STRONG = os.environ.get("NVIDIA_MODEL_STRONG", "meta/llama-3.3-70b-instruct")
_DEEPSEEK_STRONG = os.environ.get("DEEPSEEK_MODEL_STRONG", "deepseek-chat")
_OPENROUTER_STRONG = os.environ.get("OPENROUTER_MODEL_STRONG",
                                    "nvidia/nemotron-3-ultra-550b-a55b:free")
_OPENROUTER_FAST = os.environ.get("OPENROUTER_MODEL_FAST",
                                  "nvidia/nemotron-3.5-lightning:free")

_REQUEST_TIMEOUT = 60  # secondes


def _keys_for(base_name: str) -> list[str]:
    """Clés d'un provider : BASE puis BASE1, BASE_2... (ordre numérique), sans doublon."""
    found: list[tuple[int, str]] = []
    for name, val in os.environ.items():
        if not val:
            continue
        if name == base_name:
            found.append((0, val))
        else:
            m = re.fullmatch(re.escape(base_name) + r"_?(\d+)", name)
            if m:
                found.append((int(m.group(1)), val))
    found.sort(key=lambda kv: kv[0])
    seen, out = set(), []
    for _i, v in found:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


@dataclass
class _Endpoint:
    label: str
    client: OpenAI
    model: str
    reasoning_low: bool = False  # envoyer reasoning_effort="low" (gpt-oss sur Groq)


def _is_fallback_error(exc: Exception) -> bool:
    """True si l'erreur justifie de passer à l'endpoint suivant."""
    status = getattr(exc, "status_code", None)
    # 400/401/402/403/404 : modèle ou clé invalide, crédit épuisé, param refusé
    if status in (400, 401, 402, 403, 404, 408, 413, 429) or (
        isinstance(status, int) and status >= 500
    ):
        return True
    t = str(exc).lower()
    return any(k in t for k in (
        "rate_limit", "rate limit", "quota", "too large", "429", "insufficient",
        "overloaded", "503", "502", "timeout", "timed out", "connection",
    ))


class LLMClient:
    def __init__(self) -> None:
        groq = _keys_for("GROQ_API_KEY")
        nvidia = _keys_for("NVIDIA_API_KEY")
        deepseek = _keys_for("DEEPSEEK_API_KEY")
        openrouter = _keys_for("OPENROUTER_API_KEY")

        logger.info("[llm] clés détectées: groq=%d nvidia=%d deepseek=%d openrouter=%d",
                    len(groq), len(nvidia), len(deepseek), len(openrouter))

        def mk(base, key, model, label, reasoning_low=False):
            # max_retries=0 : c'est NOTRE rotation qui gère les erreurs, pas le SDK
            client = OpenAI(base_url=base, api_key=key,
                            max_retries=0, timeout=_REQUEST_TIMEOUT)
            return _Endpoint(label, client, model, reasoning_low)

        def is_oss(model: str) -> bool:
            return "gpt-oss" in model

        # Pool STRONG — ordre = priorité qualité/fiabilité.
        self._strong: list[_Endpoint] = []
        for i, k in enumerate(deepseek):
            self._strong.append(mk(_DEEPSEEK_BASE, k, _DEEPSEEK_STRONG, f"deepseek#{i+1}"))
        for i, k in enumerate(nvidia):
            self._strong.append(mk(_NVIDIA_BASE, k, _NVIDIA_STRONG, f"nvidia/70b#{i+1}"))
        for i, k in enumerate(groq):
            self._strong.append(mk(_GROQ_BASE, k, _GROQ_STRONG, f"groq/strong#{i+1}",
                                   reasoning_low=is_oss(_GROQ_STRONG)))
        for i, k in enumerate(openrouter):
            self._strong.append(mk(_OPENROUTER_BASE, k, _OPENROUTER_STRONG,
                                   f"openrouter/strong#{i+1}"))

        # Pool FAST — Groq fast, puis OpenRouter fast, puis repli sur strong.
        self._fast: list[_Endpoint] = []
        for i, k in enumerate(groq):
            self._fast.append(mk(_GROQ_BASE, k, _GROQ_FAST, f"groq/fast#{i+1}",
                                 reasoning_low=is_oss(_GROQ_FAST)))
        for i, k in enumerate(openrouter):
            self._fast.append(mk(_OPENROUTER_BASE, k, _OPENROUTER_FAST,
                                 f"openrouter/fast#{i+1}"))
        self._fast.extend(self._strong)

        self._idx = {"fast": 0, "strong": 0}
        self._total_calls = 0
        logger.info("[llm] pools: STRONG=%d endpoints, FAST=%d endpoints",
                    len(self._strong), len(self._fast))

    def query(self, system: str, user: str, model: str = "fast",
              max_tokens: int = 4096, json_mode: bool = False) -> str:
        self._total_calls += 1
        kind = "fast" if model == "fast" else "strong"
        pool = self._fast if kind == "fast" else self._strong
        n = len(pool)
        if n == 0:
            raise Exception("Aucun endpoint LLM configuré (vérifier les clés .env)")

        last_exc: Exception | None = None
        for attempt in range(n):
            idx = (self._idx[kind] + attempt) % n
            ep = pool[idx]
            try:
                params = dict(
                    model=ep.model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    temperature=0.2,
                    # marge pour les modèles de raisonnement (réflexion + réponse)
                    max_tokens=max(max_tokens, 8192),
                )
                if ep.reasoning_low:
                    params["reasoning_effort"] = "low"
                if json_mode:
                    # le prompt système doit contenir le mot "JSON"
                    params["response_format"] = {"type": "json_object"}

                resp = ep.client.chat.completions.create(**params)
                content = resp.choices[0].message.content
                if not content or not content.strip():
                    raise Exception(f"réponse vide de {ep.label}")
                self._idx[kind] = idx  # rester sur l'endpoint qui répond
                return content
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if _is_fallback_error(exc) or "réponse vide" in str(exc):
                    logger.warning("[llm] %s indisponible (%s) -> endpoint suivant",
                                   ep.label, getattr(exc, "status_code", None) or str(exc)[:80])
                    self._idx[kind] = (idx + 1) % n
                    continue
                logger.error("[llm] erreur non-récupérable sur %s : %s", ep.label, exc)
                raise

        logger.error("[llm] tous les %d endpoints (%s) épuisés", n, kind)
        raise last_exc if last_exc else Exception("Tous les endpoints LLM épuisés")

    def stats(self) -> dict:
        return {"total_calls": self._total_calls,
                "strong_endpoints": len(self._strong),
                "fast_endpoints": len(self._fast)}