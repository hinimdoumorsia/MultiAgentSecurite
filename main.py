#!/usr/bin/env python3
"""
SecureCodeAgent CLI — avec LiveReporter terminal
=================================================
Usage:
    python main.py analyze https://github.com/user/repo --language python
    python main.py analyze . --language python --output rapport.json
"""

import asyncio, os, sys, argparse, json, warnings, pathlib
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Windows : forcer UTF-8 sur stdout/stderr avant tout import de Rich
# (cp1252 par défaut ne supporte pas les caractères Unicode ✓ ⟳ etc.)
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from dotenv import load_dotenv
load_dotenv()
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from core.orchestrator import run_analysis
from core.reporter import make_reporter, EVENT_DONE


def check_env():
    if not os.environ.get("GROQ_API_KEY"):
        print("❌ GROQ_API_KEY manquante. Configurez .env")
        sys.exit(1)


async def cmd_analyze(args):
    check_env()
    target = args.target

    # Créer le reporter Live (affiche tout en temps réel)
    reporter = make_reporter(repo_url=target)
    reporter.start()

    try:
        result = await run_analysis(
            repo_url=target,
            target_files=args.files or [],
            language=args.language,
            on_event=reporter.on_event  # ← branche les événements sur le terminal
        )
    finally:
        reporter.stop()  # ferme le Live proprement

    # Résumé final après le Live
    reporter.print_final_summary(result.get("report", {}))

    # Export JSON
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"\n💾 Rapport exporté : {args.output}")

    # Mémoire de session : dump complet en fin de run
    if args.dump_memory:
        print("\n--- Mémoire de session complète ---")
        for entry in reporter.memory.history():
            print(f"  t+{entry['ts']}s  {entry['key']} = {entry['value']}")

    # Exit code non-zéro si vulnérabilités critiques
    if result.get("report", {}).get("critical_vulns"):
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="SecureCodeAgent — Révision de code orientée sécurité",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
exemples:
  python main.py analyze .
  python main.py analyze https://github.com/user/repo --language python
  python main.py analyze . --output rapport.json --dump-memory
"""
    )
    sub = parser.add_subparsers(dest="command")

    ap = sub.add_parser("analyze", help="Analyse un répertoire local OU une URL GitHub")
    ap.add_argument("target", help="Chemin local OU URL GitHub (un seul argument)")
    ap.add_argument("--language", "-l", default="python",
                    choices=["python","javascript","typescript","java","go","php","ruby","rust"])
    ap.add_argument("--files", "-f", nargs="+")
    ap.add_argument("--output", "-o", help="Exporter le rapport en JSON")
    ap.add_argument("--dump-memory", action="store_true",
                    help="Afficher la mémoire de session complète à la fin")

    args = parser.parse_args()
    if args.command == "analyze":
        asyncio.run(cmd_analyze(args))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()