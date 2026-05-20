"""
core/reporter.py — Affichage live dans le terminal
====================================================
Affiche les événements de l'orchestrateur en temps réel :
  - étapes du pipeline (tokens au fil de l'eau)
  - données mémoire de session (état interne de l'agent)
  - findings au fur et à mesure qu'ils arrivent

Utilisation :
    reporter = LiveReporter()
    reporter.start()
    # ... passer reporter.on_event comme callback à l'orchestrateur
    reporter.stop()
"""

import time
import asyncio
from datetime import datetime
from collections import defaultdict
from typing import Callable

try:
    from rich.console import Console, Group
    from rich.live import Live
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.columns import Columns
    RICH = True
except ImportError:
    RICH = False

console = Console(legacy_windows=False) if RICH else None


# ─── Types d'événements émis par l'orchestrateur ─────────────────────────────

EVENT_STEP_START   = "step_start"     # début d'un nœud LangGraph
EVENT_STEP_DONE    = "step_done"      # fin d'un nœud
EVENT_TOKEN        = "token"          # token LLM reçu (streaming Groq)
EVENT_FINDING      = "finding"        # vulnérabilité détectée
EVENT_MEMORY       = "memory"         # mise à jour mémoire de session
EVENT_ERROR        = "error"          # erreur non fatale
EVENT_DONE         = "done"           # pipeline terminé


# ─── Mémoire de session observable ───────────────────────────────────────────

class SessionMemory:
    """
    Stocke l'état interne du pipeline pendant l'analyse.
    Visible dans le terminal via LiveReporter.
    Persisté en JSON à la fin pour réutilisation.
    """
    def __init__(self):
        self._data: dict = {}
        self._history: list[dict] = []
        self._start = time.time()

    def set(self, key: str, value):
        self._data[key] = value
        self._history.append({
            "ts": round(time.time() - self._start, 2),
            "op": "set",
            "key": key,
            "value": str(value)[:80]
        })

    def get(self, key: str, default=None):
        return self._data.get(key, default)

    def snapshot(self) -> dict:
        return dict(self._data)

    def history(self) -> list:
        return list(self._history)

    def as_table(self) -> "Table":
        """Retourne un Rich Table pour affichage dans le terminal."""
        t = Table(show_header=True, box=None, padding=(0, 1))
        t.add_column("clé", style="cyan", width=22)
        t.add_column("valeur", width=38)
        t.add_column("t+", style="dim", width=6)

        # Afficher les 8 dernières entrées
        for entry in self._history[-8:]:
            t.add_row(
                entry["key"],
                entry["value"],
                f"{entry['ts']}s"
            )
        return t


# ─── Reporter Live ────────────────────────────────────────────────────────────

class LiveReporter:
    """
    Affichage Live Rich dans le terminal.
    Reçoit les événements via on_event() et met à jour l'UI en temps réel.

    Layout :
    ┌──────────────────────────────────────────────┐
    │  Pipeline  [étape en cours + barre temps]    │
    ├────────────────────┬─────────────────────────┤
    │  Tokens LLM        │  Mémoire de session      │
    ├────────────────────┴─────────────────────────┤
    │  Findings détectés                           │
    └──────────────────────────────────────────────┘
    """

    STEP_LABELS = {
        "indexation":  ("Indexation", "green"),
        "security":    ("Analyse statique", "yellow"),
        "llm_review":  ("Révision LLM (Groq)", "blue"),
        "aggregation": ("Agrégation CVSS", "magenta"),
        "patching":    ("Génération patchs", "cyan"),
    }

    SEV_COLORS = {
        "CRITICAL": "bold red",
        "HIGH":     "orange3",
        "MEDIUM":   "yellow",
        "LOW":      "cyan",
        "INFO":     "dim",
    }

    def __init__(self, repo_url: str = ""):
        self.memory = SessionMemory()
        self.repo_url = repo_url
        self._tokens: list[str] = []
        self._findings: list[dict] = []
        self._errors: list[str] = []
        self._current_step = ""
        self._step_times: dict[str, float] = {}
        self._completed_steps: list[str] = []
        self._live: "Live | None" = None
        self._start = time.time()

    # ── Callback principal appelé par l'orchestrateur ──────────────────────

    def on_event(self, event_type: str, data: dict):
        """Point d'entrée unique pour tous les événements du pipeline."""
        if event_type == EVENT_STEP_START:
            step = data.get("step", "")
            self._current_step = step
            self._step_times[step] = time.time()
            self.memory.set(f"step:{step}", "running")

        elif event_type == EVENT_STEP_DONE:
            step = data.get("step", "")
            elapsed = round(time.time() - self._step_times.get(step, time.time()), 1)
            self._completed_steps.append(step)
            self.memory.set(f"step:{step}", f"done ({elapsed}s)")

        elif event_type == EVENT_TOKEN:
            token = data.get("token", "")
            self._tokens.append(token)
            if len(self._tokens) > 300:
                self._tokens = self._tokens[-300:]

        elif event_type == EVENT_FINDING:
            self._findings.append(data)
            sev = data.get("severity", "?")
            self.memory.set(f"findings:{sev}", str(self._count_by_sev(sev)))

        elif event_type == EVENT_MEMORY:
            self.memory.set(data.get("key", "?"), data.get("value", ""))

        elif event_type == EVENT_ERROR:
            self._errors.append(data.get("message", ""))

        elif event_type == EVENT_DONE:
            self.memory.set("status", "completed")
            self.memory.set("total_findings", str(len(self._findings)))
            self.memory.set("risk_score", str(data.get("risk_score", "?")))

        if self._live:
            self._live.update(self._build_layout())

    # ── Démarrage/arrêt ────────────────────────────────────────────────────

    def start(self):
        if not RICH:
            return
        self._live = Live(
            self._build_layout(),
            console=console,
            refresh_per_second=8,
            vertical_overflow="visible"
        )
        self._live.__enter__()
        self.memory.set("status", "running")
        self.memory.set("repo", self.repo_url[-50:])

    def stop(self):
        if self._live:
            self._live.__exit__(None, None, None)
            self._live = None

    def print_final_summary(self, report: dict):
        """Affiche le résumé final après la fermeture du Live."""
        if not RICH:
            return

        risk = report.get("risk_score", 0)
        color = "red" if risk >= 7 else "yellow" if risk >= 4 else "green"

        console.print()
        console.rule("[bold]Analyse terminée[/bold]")

        # Stats
        stats = report.get("statistics", {})
        console.print(
            f"  Fichiers : [bold]{stats.get('files_analyzed', 0)}[/bold]  |  "
            f"Lignes : [bold]{stats.get('total_lines', 0)}[/bold]  |  "
            f"Findings : [bold]{report.get('total_findings', 0)}[/bold]  |  "
            f"Score risque : [{color}]{risk:.1f}/10[/{color}]"
        )

        # Tableau des top vulnérabilités
        vulns = report.get("top_10_vulns", [])
        if vulns:
            t = Table(title="\nTop vulnérabilités", show_header=True, box=None, padding=(0,1))
            t.add_column("Sév.", width=10)
            t.add_column("Fichier", width=28)
            t.add_column("Ligne", width=6)
            t.add_column("CWE", width=10)
            t.add_column("Description", width=45)
            for v in vulns:
                sev = str(v.get("severity", "?"))
                t.add_row(
                    f"[{self.SEV_COLORS.get(sev, 'white')}]{sev}[/]",
                    str(v.get("file", ""))[-28:],
                    str(v.get("line_start", "")),
                    str(v.get("cwe", "")),
                    (str(v.get("description") or v.get("title", "")))[:45]
                )
            console.print(t)

        # Mémoire de session finale
        console.print()
        console.print(Panel(
            self.memory.as_table(),
            title="[dim]Mémoire de session finale[/dim]",
            border_style="dim"
        ))

        # Recommandation
        rec = report.get("recommendation", "")
        if rec:
            rec_color = "red" if "BLOCAGE" in rec else "yellow" if "obligatoire" in rec else "green"
            console.print(f"\n[{rec_color}]{rec}[/{rec_color}]\n")

    # ── Construction de la mise en page Rich Live ───────────────────────────

    def _build_layout(self) -> Panel:
        elapsed = round(time.time() - self._start, 1)

        # Ligne header
        header = Text()
        header.append(f"{self.repo_url[-60:]}", style="bold")
        header.append(f"  —  {elapsed}s écoulées")

        # Ligne pipeline
        steps_txt = Text()
        all_steps = ["indexation", "security", "llm_review", "aggregation", "patching"]
        for s in all_steps:
            label, color = self.STEP_LABELS.get(s, (s, "white"))
            if s in self._completed_steps:
                steps_txt.append(f" ✓ {label} ", style=f"bold {color}")
            elif s == self._current_step:
                steps_txt.append(f" ⟳ {label} ", style=f"bold {color} reverse")
            else:
                steps_txt.append(f" · {label} ", style="dim")
            steps_txt.append(" ")

        # Tokens LLM (derniers 200 chars)
        token_str = "".join(self._tokens[-200:])
        token_panel = Panel(
            Text(token_str[-300:], style="dim") if token_str else Text("En attente du LLM...", style="dim italic"),
            title=f"[blue]Tokens Groq ({len(self._tokens)})[/blue]",
            height=8
        )

        # Mémoire de session
        mem_panel = Panel(
            self.memory.as_table(),
            title="[cyan]Mémoire de session[/cyan]",
            height=8
        )

        # Findings
        findings_txt = Text()
        sevs = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        for sev in sevs:
            count = self._count_by_sev(sev)
            if count:
                findings_txt.append(f"  {sev}: {count}", style=self.SEV_COLORS.get(sev, "white"))
        if not self._findings:
            findings_txt.append("Aucun finding pour l'instant...", style="dim italic")

        findings_panel = Panel(
            findings_txt,
            title=f"[yellow]Findings ({len(self._findings)} total)[/yellow]"
        )

        renderables = [header, steps_txt, token_panel, mem_panel, findings_panel]
        if self._errors:
            err_txt = Text()
            for e in self._errors[-3:]:
                err_txt.append(f"  • {e}\n", style="red")
            renderables.append(err_txt)

        return Panel(
            Group(*renderables),
            title="[bold blue]SecureCodeAgent — Live[/bold blue]",
            border_style="blue"
        )

    def _count_by_sev(self, sev: str) -> int:
        return sum(1 for f in self._findings if f.get("severity") == sev)


# ─── Fallback simple (sans Rich) ─────────────────────────────────────────────

class SimpleReporter:
    """Reporter minimal pour environnements sans Rich."""
    def __init__(self, repo_url=""):
        self.memory = SessionMemory()
        self.repo_url = repo_url

    def on_event(self, event_type: str, data: dict):
        ts = datetime.now().strftime("%H:%M:%S")
        if event_type == EVENT_STEP_START:
            print(f"[{ts}] ▶ {data.get('step', '')}")
        elif event_type == EVENT_STEP_DONE:
            print(f"[{ts}] ✓ {data.get('step', '')} terminé")
        elif event_type == EVENT_FINDING:
            sev = data.get("severity", "?")
            print(f"[{ts}] [{sev}] {data.get('title', '')} — {data.get('file', '')}")
        elif event_type == EVENT_ERROR:
            print(f"[{ts}] ERREUR: {data.get('message', '')}")
        elif event_type == EVENT_DONE:
            print(f"[{ts}] Pipeline terminé. Score: {data.get('risk_score', '?')}/10")
        self.memory.set(event_type, str(data)[:60])

    def start(self): pass
    def stop(self): pass
    def print_final_summary(self, report: dict):
        print(f"\nRésultat: {report.get('total_findings', 0)} findings, score {report.get('risk_score', 0)}/10")


def make_reporter(repo_url: str = "") -> "LiveReporter | SimpleReporter":
    """Factory : retourne le bon reporter selon l'environnement."""
    return LiveReporter(repo_url) if RICH else SimpleReporter(repo_url)