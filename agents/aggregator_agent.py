"""
Agents d'Agrégation et de Génération de Patchs
================================================
"""

import json
import time
import logging
import asyncio
import random
from groq import AsyncGroq, RateLimitError

logger = logging.getLogger(__name__)


# ─── AGRÉGATEUR ───────────────────────────────────────────────────────────────

class ResultAggregator:
    """
    Fusionne les résultats de l'analyse statique (Bandit/Semgrep)
    et de la révision LLM. Calcule un score de confiance global.
    Priorise selon CVSS v3.
    """

    SEVERITY_WEIGHTS = {
        "CRITICAL": 10.0,
        "HIGH": 7.0,
        "MEDIUM": 4.0,
        "LOW": 2.0,
        "INFO": 0.5
    }

    async def aggregate(
        self,
        security_findings: list[dict],
        llm_review: dict,
        code_index: dict
    ) -> dict:
        """Point d'entrée principal de l'agrégation."""

        # Collecte de tous les findings
        all_vulns = list(security_findings)  # Findings statiques

        # Ajout des findings LLM
        for file_result in llm_review.get("results", []):
            for vuln in file_result.get("vulnerabilities", []):
                vuln["source"] = "llm"
                all_vulns.append(vuln)

        # Classification par sévérité
        critical = [v for v in all_vulns if v.get("severity") == "CRITICAL"]
        high = [v for v in all_vulns if v.get("severity") == "HIGH"]
        medium = [v for v in all_vulns if v.get("severity") == "MEDIUM"]
        low = [v for v in all_vulns if v.get("severity") in ("LOW", "INFO")]

        # Score de risque global (0-10)
        risk_score = min(10.0, self._compute_risk_score(all_vulns))

        # Confidence basée sur la concordance statique/LLM
        static_count = len(security_findings)
        llm_count = sum(len(r.get("vulnerabilities", [])) for r in llm_review.get("results", []))
        confidence = self._compute_confidence(static_count, llm_count, llm_review)

        # Résumé par fichier
        files_summary = self._summarize_by_file(all_vulns, code_index)

        # Classement des vuln les plus critiques (top 10)
        top_vulns = sorted(
            all_vulns,
            key=lambda v: self.SEVERITY_WEIGHTS.get(v.get("severity", "LOW"), 1.0),
            reverse=True
        )[:10]

        return {
            "timestamp": time.time(),
            "risk_score": round(risk_score, 2),
            "confidence_score": round(confidence, 3),
            "total_findings": len(all_vulns),
            "critical_vulns": critical,
            "high_vulns": high,
            "medium_vulns": medium,
            "low_vulns": low,
            "top_10_vulns": top_vulns,
            "files_summary": files_summary,
            "statistics": {
                "files_analyzed": code_index.get("files_count", 0),
                "total_lines": code_index.get("total_lines", 0),
                "static_findings": static_count,
                "llm_findings": llm_count,
                "unique_cwes": list({v.get("cwe", "") for v in all_vulns if v.get("cwe")})
            },
            "recommendation": self._generate_recommendation(risk_score, critical, high)
        }

    def _compute_risk_score(self, vulns: list[dict]) -> float:
        """Calcule le score de risque CVSS-like."""
        if not vulns:
            return 0.0
        total = sum(self.SEVERITY_WEIGHTS.get(v.get("severity", "LOW"), 1.0) for v in vulns)
        # Normalisation logarithmique
        import math
        return min(10.0, math.log1p(total) * 2.0)

    def _compute_confidence(
        self,
        static_count: int,
        llm_count: int,
        llm_review: dict
    ) -> float:
        """Confiance basée sur la concordance des sources."""
        llm_confidence = 0.0
        results = llm_review.get("results", [])
        if results:
            confidences = [r.get("confidence", 0.5) for r in results]
            llm_confidence = sum(confidences) / len(confidences)

        # Si statique et LLM concordent → confiance haute
        both_found = static_count > 0 and llm_count > 0
        agreement_bonus = 0.2 if both_found else 0.0

        return min(1.0, llm_confidence + agreement_bonus)

    def _summarize_by_file(self, vulns: list[dict], code_index: dict) -> list[dict]:
        """Résumé des findings par fichier."""
        from collections import defaultdict
        by_file: dict[str, list] = defaultdict(list)
        for v in vulns:
            by_file[v.get("file", "unknown")].append(v)

        summary = []
        for filename, file_vulns in by_file.items():
            file_info = code_index.get("files", {}).get(filename, {})
            summary.append({
                "file": filename,
                "lines": file_info.get("lines", 0),
                "findings_count": len(file_vulns),
                "max_severity": max(
                    (v.get("severity", "LOW") for v in file_vulns),
                    key=lambda s: self.SEVERITY_WEIGHTS.get(s, 0)
                ),
                "cwes": list({v.get("cwe", "") for v in file_vulns if v.get("cwe")})
            })

        return sorted(summary, key=lambda x: x["findings_count"], reverse=True)

    def _generate_recommendation(self, risk_score: float, critical: list, high: list) -> str:
        """Recommandation exécutive."""
        if risk_score >= 8.0:
            return "BLOCAGE IMMÉDIAT requis — Vulnérabilités critiques détectées. Ne pas merger."
        elif risk_score >= 5.0:
            return "Révision obligatoire avant merge — Risques élevés identifiés."
        elif risk_score >= 2.0:
            return "Corrections recommandées — Risques moyens, merger avec précaution."
        else:
            return "Code globalement sain — Revue légère suffisante."


# ─── GÉNÉRATEUR DE PATCHS ─────────────────────────────────────────────────────

PATCH_SYSTEM_PROMPT = """Tu es un expert en correction de vulnérabilités de sécurité.
Tu génères des patchs de code corrects, minimaux et sûrs.

FORMAT: Réponds UNIQUEMENT en JSON avec la structure:
{
  "patches": [
    {
      "vuln_id": "VULN-001",
      "file": "chemin/fichier.py",
      "original_code": "code vulnérable exact",
      "patched_code": "code corrigé",
      "explanation": "explication de la correction",
      "test_snippet": "test pytest pour valider la correction"
    }
  ]
}

RÈGLES:
- Corrections minimales (principe du moindre privilège de modification)
- Ne jamais changer la logique métier, seulement corriger la faille
- Inclure un test unitaire pour chaque correction
- Si une correction est trop complexe, marquer "requires_human_review": true
"""


class PatchGenerator:
    """Génère des patchs de correction via Groq avec validation."""

    def __init__(self, api_key: str, model: str = "llama-3.3-70b-versatile"):
        self._client = AsyncGroq(api_key=api_key)
        self.model = model

    async def generate(self, report: dict, code_index: dict) -> list[dict]:
        """Génère des patchs pour les vulnérabilités critiques et high."""
        target_vulns = report.get("critical_vulns", []) + report.get("high_vulns", [])

        if not target_vulns:
            return []

        # On traite max 5 vulnérabilités à la fois
        target_vulns = target_vulns[:5]
        patches = []

        for vuln in target_vulns:
            patch = await self._generate_single_patch(vuln, code_index)
            if patch:
                patches.append(patch)

        return patches

    async def _generate_single_patch(self, vuln: dict, code_index: dict) -> dict | None:
        """Génère un patch pour une vulnérabilité unique."""
        filename = vuln.get("file", "")
        file_data = code_index.get("files", {}).get(filename, {})
        file_content = file_data.get("content", "")

        if not file_content:
            return None

        # Extraction du contexte autour de la ligne vulnérable
        lines = file_content.split("\n")
        line_start = max(0, vuln.get("line_start", 1) - 5)
        line_end = min(len(lines), vuln.get("line_end", 1) + 5)
        context = "\n".join(lines[line_start:line_end])

        user_message = f"""Génère un patch pour cette vulnérabilité:

Fichier: {filename}
Type: {vuln.get('cwe', 'N/A')} — {vuln.get('title', '')}
Sévérité: {vuln.get('severity', 'HIGH')}
Description: {vuln.get('description', '')}

Code contexte (lignes {line_start+1}-{line_end}):
<code_context>
{context}
</code_context>

Génère uniquement le patch JSON."""

        for attempt in range(3):
            try:
                response = await self._client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": PATCH_SYSTEM_PROMPT},
                        {"role": "user", "content": user_message}
                    ],
                    temperature=0.05,
                    max_tokens=2048,
                    response_format={"type": "json_object"}
                )
                raw = response.choices[0].message.content
                data = json.loads(raw)
                patches = data.get("patches", [])
                if patches:
                    return patches[0]

            except RateLimitError:
                wait = (2 ** attempt) + random.uniform(0, 1)
                await asyncio.sleep(wait)
            except (json.JSONDecodeError, Exception) as e:
                logger.error(f"Erreur génération patch: {e}")
                break

        return None
