"""Verification d'un correctif (piste repair).

Pour un cas avec des tests executables (ex: Vul4J), on mesure 3 choses :

  1. patch_valid_diff : le diff genere par l'agent s'applique-t-il proprement ?
  2. patch_fixes      : apres application, le test de vuln (PoC) passe-t-il ?
                        (il echoue tant que la vuln est presente)
  3. patch_regresses  : un test fonctionnel casse-t-il a cause du patch ?

Le patch est applique dans une COPIE du depot pour ne jamais abimer la source.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from MultiAgentSecurite.benchmark.harness.schema import AgentFinding, CaseResult, GroundTruthLabel


def _run_cmd(cmd: str, cwd: str, timeout: int = 600) -> bool:
    """True si la commande sort avec code 0."""
    if not cmd:
        return True
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, shell=True, capture_output=True,
            text=True, timeout=timeout,
        )
        return proc.returncode == 0
    except Exception:  # noqa: BLE001 - timeout, exe absent, etc.
        return False


def _apply_diff(repo_dir: str, diff: str, timeout: int = 30) -> bool:
    """Applique un diff unifie via `git apply` puis `patch` en repli."""
    if not diff:
        return False
    # Tentative 1 : git apply (tolerant, gere bien les chemins)
    try:
        p = subprocess.run(
            ["git", "apply", "--whitespace=nowarn", "-"],
            cwd=repo_dir, input=diff, capture_output=True, text=True, timeout=timeout,
        )
        if p.returncode == 0:
            return True
    except Exception:  # noqa: BLE001
        pass
    # Tentative 2 : patch -p1
    try:
        p = subprocess.run(
            ["patch", "-p1", "--forward"],
            cwd=repo_dir, input=diff, capture_output=True, text=True, timeout=timeout,
        )
        return p.returncode == 0
    except Exception:  # noqa: BLE001
        return False


def verify_repair(
    label: GroundTruthLabel,
    findings: list[AgentFinding],
    result: CaseResult,
    timeout_sec: int = 600,
) -> CaseResult:
    """Renseigne result.patch_* a partir des tests du dataset."""
    # Selectionne le finding porteur d'un patch (le premier qui en a un).
    patched = next((f for f in findings if f.patch_diff), None)
    if patched is None:
        result.patch_valid_diff = False
        result.patch_fixes = False
        result.patch_regresses = False
        return result

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "repo"
        shutil.copytree(label.repo_path, work, dirs_exist_ok=True)

        applied = _apply_diff(str(work), patched.patch_diff)
        result.patch_valid_diff = applied
        if not applied:
            result.patch_fixes = False
            result.patch_regresses = False
            return result

        # La vuln doit avoir disparu : le test PoC (qui echouait) doit passer.
        if label.vuln_test_cmd:
            result.patch_fixes = _run_cmd(label.vuln_test_cmd, str(work), timeout_sec)
        else:
            result.patch_fixes = None  # pas de PoC : non mesurable ici

        # Pas de regression : les tests fonctionnels doivent rester verts.
        if label.functional_test_cmd:
            result.patch_regresses = not _run_cmd(
                label.functional_test_cmd, str(work), timeout_sec
            )
        else:
            result.patch_regresses = None

    return result
