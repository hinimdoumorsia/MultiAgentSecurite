"""Client LLM multi-provider avec rotation croisée.

Tous les providers exposent une API compatible OpenAI -> on les unifie via le SDK
`openai` (un client par couple provider+clé).

Deux pools :
  - STRONG (patching, analyse fine) : DeepSeek V3 > NVIDIA Llama-3.3-70B > Groq
    Llama-3.3-70B > OpenRouter Qwen3-Coder (fallback).
  - FAST (rapide/économique) : Groq Llama-3.1-8B, puis repli sur le pool strong.

`query(model="fast"|"strong")` parcourt le pool ; en cas de rate-limit/quota
(429/413/5xx) il bascule automatiquement sur l'endpoint suivant (provider ou clé
différente). Ainsi on additionne les quotas gratuits de tous les providers.

Modèles surchargeables via .env : GROQ_MODEL_STRONG, GROQ_MODEL_FAST,
NVIDIA_MODEL_STRONG, DEEPSEEK_MODEL_STRONG, OPENROUTER_MODEL_STRONG.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path


def load_env():
    env_file = Path(__file__).parent.parent / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                os.environ[key.strip()] = value.strip()

load_env()

from openai import OpenAI

logger = logging.getLogger(__name__)

_GROQ_BASE = "https://api.groq.com/openai/v1"
_NVIDIA_BASE = "https://integrate.api.nvidia.com/v1"
_DEEPSEEK_BASE = "https://api.deepseek.com"
_OPENROUTER_BASE = "https://openrouter.ai/api/v1"

_GROQ_STRONG = os.environ.get("GROQ_MODEL_STRONG", "llama-3.3-70b-versatile")
_GROQ_FAST = os.environ.get("GROQ_MODEL_FAST", "llama-3.1-8b-instant")
_NVIDIA_STRONG = os.environ.get("NVIDIA_MODEL_STRONG", "meta/llama-3.3-70b-instruct")
_DEEPSEEK_STRONG = os.environ.get("DEEPSEEK_MODEL_STRONG", "deepseek-v4-pro")
_OPENROUTER_STRONG = os.environ.get("OPENROUTER_MODEL_STRONG", "qwen/qwen3-coder:free")


def _keys_for(base_name: str) -> list[str]:
    """Clés d'un provider : BASE puis BASE1, BASE2... (ordre numérique), sans doublon."""
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


def _is_quota_error(exc: Exception) -> bool:
    status = getattr(exc, "status_code", None)
    if status in (429, 413) or (isinstance(status, int) and status >= 500):
        return True
    t = str(exc).lower()
    return any(k in t for k in ("rate_limit", "rate limit", "quota", "too large",
                                "429", "insufficient", "overloaded", "503", "502"))


class LLMClient:
    def __init__(self) -> None:
        groq = _keys_for("GROQ_API_KEY")
        nvidia = _keys_for("NVIDIA_API_KEY")
        deepseek = _keys_for("DEEPSEEK_API_KEY")
        openrouter = _keys_for("OPENROUTER_API_KEY")

        def mk(base, key, model, label):
            return _Endpoint(label, OpenAI(base_url=base, api_key=key), model)

        # Pool STRONG (patching) — ordre = priorité qualité/fiabilité.
        self._strong: list[_Endpoint] = []
        for k in deepseek:
            self._strong.append(mk(_DEEPSEEK_BASE, k, _DEEPSEEK_STRONG, "deepseek/v3"))
        for i, k in enumerate(nvidia):
            self._strong.append(mk(_NVIDIA_BASE, k, _NVIDIA_STRONG, f"nvidia/70b#{i+1}"))
        for i, k in enumerate(groq):
            self._strong.append(mk(_GROQ_BASE, k, _GROQ_STRONG, f"groq/70b#{i+1}"))
        for k in openrouter:
            self._strong.append(mk(_OPENROUTER_BASE, k, _OPENROUTER_STRONG, "openrouter/qwen-coder"))

        # Pool FAST (détection) — Groq 8B, repli sur strong.
        self._fast: list[_Endpoint] = []
        for i, k in enumerate(groq):
            self._fast.append(mk(_GROQ_BASE, k, _GROQ_FAST, f"groq/8b#{i+1}"))
        self._fast.extend(self._strong)

        self._idx = {"fast": 0, "strong": 0}
        self._total_calls = 0
        logger.info("[llm] pools: STRONG=%d endpoints, FAST=%d endpoints",
                    len(self._strong), len(self._fast))

    def query(self, system: str, user: str, model: str = "fast", max_tokens: int = 4096) -> str:
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
                resp = ep.client.chat.completions.create(
                    model=ep.model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    temperature=0.2,
                    max_tokens=max_tokens,
                )
                content = resp.choices[0].message.content
                if not content or not content.strip():
                    raise Exception(f"réponse vide de {ep.label}")
                self._idx[kind] = idx  # rester sur l'endpoint qui répond
                return content
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if _is_quota_error(exc) or "réponse vide" in str(exc):
                    logger.warning("[llm] %s indisponible (%s) -> endpoint suivant",
                                   ep.label, getattr(exc, "status_code", "?"))
                    self._idx[kind] = (idx + 1) % n
                    continue
                logger.error("[llm] erreur non-quota sur %s : %s", ep.label, exc)
                raise

        logger.error("[llm] tous les %d endpoints (%s) épuisés", n, kind)
        raise last_exc if last_exc else Exception("Tous les endpoints LLM épuisés")

    def stats(self) -> dict:
        return {"total_calls": self._total_calls,
                "strong_endpoints": len(self._strong),
                "fast_endpoints": len(self._fast)}
