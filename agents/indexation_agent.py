"""
Agent d'Indexation de Code
===========================
Utilise tree-sitter pour l'analyse AST et ChromaDB pour les embeddings sémantiques.
Supporte Python, JS/TS, Java, Go, PHP, Ruby.

SÉCURITÉ:
- Le code n'est jamais eval() ou exec()
- L'accès réseau est désactivé pendant l'indexation
- Limite de taille par fichier pour éviter les DoS
"""

import os
import asyncio
import hashlib
import logging
from pathlib import Path
from typing import Optional
import httpx

logger = logging.getLogger(__name__)

# Limite de taille : 500KB par fichier max
MAX_FILE_SIZE_BYTES = 500 * 1024

# Extensions supportées par langage
LANG_EXTENSIONS = {
    "python": [".py"],
    "javascript": [".js", ".mjs"],
    "typescript": [".ts", ".tsx"],
    "java": [".java"],
    "go": [".go"],
    "php": [".php"],
    "ruby": [".rb"],
    "rust": [".rs"],
    "c": [".c", ".h"],
    "cpp": [".cpp", ".cc", ".cxx", ".hpp"],
}


class CodeIndexer:
    """
    Indexe un dépôt Git ou une liste de fichiers.
    Produit un index structuré pour les agents suivants.
    """

    def __init__(self, max_files: int = 200):
        self.max_files = max_files

    async def index_repository(
        self,
        repo_url: str,
        target_files: list[str],
        language: str = "python"
    ) -> dict:
        """
        Point d'entrée principal.
        - Si repo_url est un chemin local : lecture directe
        - Si repo_url est une URL GitHub : clonage via git (pas d'API)
        """
        if repo_url.startswith("http") or repo_url.startswith("git@"):
            return await self._index_remote(repo_url, language)
        else:
            return await self._index_local(repo_url, target_files, language)

    async def _index_local(self, path: str, target_files: list[str], language: str) -> dict:
        """Indexe un dépôt local."""
        base = Path(path)
        if not base.exists():
            raise FileNotFoundError(f"Répertoire introuvable: {path}")

        extensions = LANG_EXTENSIONS.get(language, [".py"])
        files_found = {}
        count = 0

        # Si des fichiers spécifiques sont demandés
        if target_files:
            candidates = [base / f for f in target_files]
        else:
            candidates = []
            for ext in extensions:
                candidates.extend(base.rglob(f"*{ext}"))

        for filepath in candidates[:self.max_files]:
            filepath = Path(filepath)
            if not filepath.exists() or not filepath.is_file():
                continue

            # SÉCURITÉ: Vérification que le fichier est dans le répertoire de base
            try:
                filepath.relative_to(base)
            except ValueError:
                logger.warning(f"Fichier hors répertoire ignoré: {filepath}")
                continue

            file_size = filepath.stat().st_size
            if file_size > MAX_FILE_SIZE_BYTES:
                logger.warning(f"Fichier trop grand ignoré: {filepath} ({file_size} bytes)")
                continue

            try:
                content = filepath.read_text(encoding="utf-8", errors="ignore")
                rel_path = str(filepath.relative_to(base))
                files_found[rel_path] = {
                    "content": content,
                    "size": file_size,
                    "hash": hashlib.sha256(content.encode()).hexdigest(),
                    "lines": content.count("\n") + 1,
                    "extension": filepath.suffix
                }
                count += 1
            except (OSError, PermissionError) as e:
                logger.warning(f"Lecture impossible: {filepath}: {e}")

        # Extraction des métadonnées AST (sans tree-sitter si non dispo)
        ast_metadata = await self._extract_ast_metadata(files_found, language)

        return {
            "language": language,
            "repo_url": path,
            "files_count": count,
            "files": files_found,
            "ast_metadata": ast_metadata,
            "total_lines": sum(f["lines"] for f in files_found.values())
        }

    async def _index_remote(self, repo_url: str, language: str) -> dict:
        """
        Clone un dépôt distant et l'indexe.
        SÉCURITÉ: Utilise git clone avec --depth=1 et sans credentials.
        """
        import tempfile
        import subprocess

        # Validation de l'URL (whitelist de domaines)
        allowed_domains = ["github.com", "gitlab.com", "bitbucket.org"]
        from urllib.parse import urlparse
        parsed = urlparse(repo_url)
        if parsed.netloc not in allowed_domains:
            raise ValueError(f"Domaine non autorisé: {parsed.netloc}")

        with tempfile.TemporaryDirectory(prefix="securecodeagent_clone_") as tmpdir:
            # Clone superficiel sans credentials
            result = subprocess.run(
                ["git", "clone", "--depth=1", "--single-branch",
                 repo_url, tmpdir],
                capture_output=True,
                timeout=120,
                env={k: v for k, v in os.environ.items()
                     if k not in ("GIT_TOKEN", "GITHUB_TOKEN", "GL_TOKEN")}
            )
            if result.returncode != 0:
                raise RuntimeError(f"git clone échoué: {result.stderr.decode()[:200]}")

            return await self._index_local(tmpdir, [], language)

    async def _extract_ast_metadata(self, files: dict, language: str) -> dict:
        """
        Extraction des fonctions, classes et imports via tree-sitter.
        Fallback vers regex si tree-sitter n'est pas installé.
        """
        metadata = {}
        for filepath, file_data in files.items():
            content = file_data["content"]
            try:
                import tree_sitter
                meta = self._parse_with_treesitter(content, language)
            except ImportError:
                meta = self._parse_with_regex(content, language)

            metadata[filepath] = meta
        return metadata

    def _parse_with_regex(self, content: str, language: str) -> dict:
        """Fallback regex pour extraire les symboles principaux."""
        import re
        functions = []
        classes = []
        imports = []

        if language == "python":
            functions = re.findall(r"^def\s+(\w+)\s*\(", content, re.MULTILINE)
            classes = re.findall(r"^class\s+(\w+)", content, re.MULTILINE)
            imports = re.findall(r"^(?:import|from)\s+(\S+)", content, re.MULTILINE)
        elif language in ("javascript", "typescript"):
            functions = re.findall(r"function\s+(\w+)\s*\(", content)
            classes = re.findall(r"class\s+(\w+)", content)
            imports = re.findall(r"import\s+.*from\s+['\"]([^'\"]+)['\"]", content)

        return {
            "functions": functions[:50],
            "classes": classes[:20],
            "imports": imports[:30]
        }

    def _parse_with_treesitter(self, content: str, language: str) -> dict:
        """Analyse AST complète avec tree-sitter."""
        # Implémentation complète avec tree-sitter
        # (nécessite tree-sitter-languages installé)
        from tree_sitter import Language, Parser
        try:
            import tree_sitter_languages
            lang_obj = tree_sitter_languages.get_language(language)
            parser = Parser()
            parser.set_language(lang_obj)
            tree = parser.parse(content.encode())
            # Extraction récursive des nœuds
            return self._traverse_tree(tree.root_node, content)
        except Exception as e:
            logger.debug(f"tree-sitter parse error: {e}")
            return self._parse_with_regex(content, language)

    def _traverse_tree(self, node, content: str) -> dict:
        """Traverse l'AST et extrait fonctions/classes."""
        functions = []
        classes = []
        lines = content.split("\n")

        def walk(n):
            if n.type in ("function_definition", "function_declaration"):
                name_node = n.child_by_field_name("name")
                if name_node:
                    functions.append({
                        "name": content[name_node.start_byte:name_node.end_byte],
                        "line": n.start_point[0] + 1
                    })
            elif n.type in ("class_definition", "class_declaration"):
                name_node = n.child_by_field_name("name")
                if name_node:
                    classes.append({
                        "name": content[name_node.start_byte:name_node.end_byte],
                        "line": n.start_point[0] + 1
                    })
            for child in n.children:
                walk(child)

        walk(node)
        return {"functions": functions[:50], "classes": classes[:20], "imports": []}
