"""SpotBugs + Find Security Bugs wrapper — Java security scanner (bytecode).

SpotBugs analyse du BYTECODE (.class), pas du source : le projet Java doit donc
etre COMPILE (target/classes) au prealable.

Configuration via .env (toutes optionnelles) :
  SPOTBUGS_BIN          chemin vers spotbugs / spotbugs.bat (sinon "spotbugs" du PATH)
  FINDSECBUGS_PLUGIN    chemin vers le jar findsecbugs (active les regles securite + CWE)
  SPOTBUGS_AUXCLASSPATH classpath des dependances compilees (precision accrue)
"""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

logger = logging.getLogger(__name__)

# FindSecBugs ne met pas toujours d'attribut cweid dans le XML : on derive le CWE
# du TYPE de bug par sous-chaine (robuste aux variantes _JDBC/_SPRING_JDBC/etc.).
# Couvre les categories du benchmark OWASP. Les bugs de style (DM_*, BC_*, DLS_*...)
# tombent sur CWE-Unknown -> ignores au scoring 'category'.
def _cwe_for_type(btype: str) -> str:
    t = (btype or "").upper()
    if "SQL" in t and ("INJECTION" in t or "NONCONSTANT" in t or "PREPARED_STATEMENT" in t):
        return "CWE-89"
    if "COMMAND_INJECTION" in t:
        return "CWE-78"
    if "PATH_TRAVERSAL" in t or "PT_" in t:
        return "CWE-22"
    if "XSS" in t:
        return "CWE-79"
    if "LDAP_INJECTION" in t:
        return "CWE-90"
    if "XPATH" in t:
        return "CWE-643"
    if "WEAK_MESSAGE_DIGEST" in t or "WEAK_HASH" in t:
        return "CWE-328"
    if any(k in t for k in ("DES_USAGE", "TDES", "CIPHER_INTEGRITY", "ECB_MODE",
                            "STATIC_IV", "PADDING_ORACLE", "RSA_NO_PADDING", "CIPHER")):
        return "CWE-327"
    if "RANDOM" in t or "PREDICTABLE" in t:
        return "CWE-330"
    if "COOKIE" in t and "HTTPONLY" not in t:
        return "CWE-614"
    if "TRUST_BOUNDARY" in t:
        return "CWE-501"
    return "CWE-Unknown"


def _bin_argv(bin_path: str) -> list[str]:
    """Sous Windows, un .bat doit etre lance via cmd /c."""
    if bin_path.lower().endswith((".bat", ".cmd")):
        return ["cmd", "/c", bin_path]
    return [bin_path]


def _classes_dir(repo_root: str) -> str | None:
    candidate = Path(repo_root) / "target" / "classes"
    return str(candidate) if candidate.is_dir() and any(candidate.rglob("*.class")) else None


class SpotBugsTool:
    def run(self, repo_root: str) -> list[dict]:
        classes = _classes_dir(repo_root)
        if classes is None:
            logger.warning(
                "[spotbugs] pas de bytecode (.class) sous %s/target/classes — "
                "compiler le projet (mvn compile) d'abord. Analyse Java sautee.",
                repo_root,
            )
            return []

        bin_path = os.environ.get("SPOTBUGS_BIN", "spotbugs")
        plugin = os.environ.get("FINDSECBUGS_PLUGIN")
        auxcp = os.environ.get("SPOTBUGS_AUXCLASSPATH")

        out_xml = Path(tempfile.gettempdir()) / f"spotbugs_{os.getpid()}.xml"
        cmd = _bin_argv(bin_path) + ["-textui", "-xml:withMessages",
                                     "-output", str(out_xml), "-effort:default"]
        if plugin:
            cmd += ["-pluginList", plugin]
        if auxcp:
            cmd += ["-auxclasspath", auxcp]
        cmd.append(classes)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=1800,
            )
            if not out_xml.exists():
                logger.warning("[spotbugs] pas de sortie XML (code %s): %s",
                               result.returncode, (result.stderr or "")[:300])
                return []
            findings = self._parse_xml(str(out_xml))
            logger.info("[spotbugs] %d findings (findsecbugs=%s)", len(findings), bool(plugin))
            return findings
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            logger.warning("[spotbugs] error: %s", exc)
            return []
        finally:
            try:
                out_xml.unlink(missing_ok=True)
            except Exception:
                pass

    def _parse_xml(self, path: str) -> list[dict]:
        findings = []
        try:
            tree = ET.parse(path)
            for bug in tree.getroot().findall(".//BugInstance"):
                source = bug.find("SourceLine")
                btype = bug.get("type", "")
                # CWE : attribut natif (findsecbugs) sinon dérivé du type de bug.
                cwe = bug.get("cweid")
                cwe = f"CWE-{cwe}" if cwe else _cwe_for_type(btype)
                msg_el = bug.find("LongMessage")
                if msg_el is None:
                    msg_el = bug.find("ShortMessage")
                findings.append({
                    "tool": "spotbugs",
                    "rule_id": btype,
                    "file": source.get("sourcepath", "") if source is not None else "",
                    "line": int(source.get("start", 0)) if source is not None and source.get("start") else 0,
                    "line_start": int(source.get("start", 0)) if source is not None and source.get("start") else 0,
                    "line_end": int(source.get("end", 0)) if source is not None and source.get("end") else 0,
                    "message": msg_el.text if msg_el is not None else "",
                    "description": msg_el.text if msg_el is not None else "",
                    "severity": _map_priority(bug.get("priority", "2")),
                    "cwe": cwe,
                    "snippet": "",
                })
        except Exception as exc:  # noqa: BLE001
            logger.warning("[spotbugs] parse error: %s", exc)
        return findings


def _map_priority(priority: str) -> str:
    return {"1": "high", "2": "medium", "3": "low"}.get(priority, "low")
