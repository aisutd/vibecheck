"""Map files to tree-sitter grammars and load parsers for them."""

import importlib
from functools import lru_cache
from pathlib import PurePath

import tree_sitter


# language name -> (python module, function that returns the grammar)
GRAMMARS = {
    "python": ("tree_sitter_python", "language"),
    "javascript": ("tree_sitter_javascript", "language"),
    "typescript": ("tree_sitter_typescript", "language_typescript"),
    "tsx": ("tree_sitter_typescript", "language_tsx"),
    "ruby": ("tree_sitter_ruby", "language"),
    "go": ("tree_sitter_go", "language"),
    "java": ("tree_sitter_java", "language"),
    "csharp": ("tree_sitter_c_sharp", "language"),
    "php": ("tree_sitter_php", "language_php"),
    "kotlin": ("tree_sitter_kotlin", "language"),
    "rust": ("tree_sitter_rust", "language"),
    "c": ("tree_sitter_c", "language"),
    "cpp": ("tree_sitter_cpp", "language"),
    "elixir": ("tree_sitter_elixir", "language"),
    "bash": ("tree_sitter_bash", "language"),
    "html": ("tree_sitter_html", "language"),
    "css": ("tree_sitter_css", "language"),
    "json": ("tree_sitter_json", "language"),
    "yaml": ("tree_sitter_yaml", "language"),
    "toml": ("tree_sitter_toml", "language"),
    "hcl": ("tree_sitter_hcl", "language"),
    "xml": ("tree_sitter_xml", "language_xml"),
    "sql": ("tree_sitter_sql", "language"),
    "dockerfile": ("tree_sitter_dockerfile", "language"),
}

EXTENSIONS = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".tsx": "tsx",
    ".rb": "ruby", ".rake": "ruby", ".gemspec": "ruby",
    ".go": "go",
    ".java": "java",
    ".cs": "csharp",
    ".php": "php",
    ".kt": "kotlin", ".kts": "kotlin",
    ".rs": "rust",
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
    ".ex": "elixir", ".exs": "elixir",
    ".sh": "bash", ".bash": "bash",
    ".html": "html", ".htm": "html",
    ".css": "css",
    ".json": "json",
    ".yml": "yaml", ".yaml": "yaml",
    ".toml": "toml",
    ".tf": "hcl", ".hcl": "hcl",
    ".xml": "xml",
    ".sql": "sql",
    ".ini": "ini", ".cfg": "ini",
    ".dockerfile": "dockerfile",
}

FILENAMES = {
    "dockerfile": "dockerfile",
    "containerfile": "dockerfile",
    "gemfile": "ruby",
    "rakefile": "ruby",
    "vagrantfile": "ruby",
    "podfile": "ruby",
    "nginx.conf": "nginx",
}


def detect_language(path: str, code: str = "") -> str | None:
    """Guess the language of a file from its name (and contents for .conf files)."""
    name = PurePath(path).name.lower()
    if name in FILENAMES:
        return FILENAMES[name]
    # Dockerfile.dev, Dockerfile.prod, ...
    if name.startswith("dockerfile."):
        return "dockerfile"
    # .env, .env.example, .env.prod, ...
    if name == ".env" or name.startswith(".env."):
        return "dotenv"

    suffix = PurePath(name).suffix
    if suffix in EXTENSIONS:
        return EXTENSIONS[suffix]

    # .conf is used for many formats; only treat it as nginx when it looks like nginx.
    if suffix == ".conf":
        if "nginx" in path.lower() or any(
            marker in code for marker in ("server {", "location ", "http {", "upstream ")
        ):
            return "nginx"
    return None


def _load_from_package(language: str):
    module_name, func_name = GRAMMARS[language]
    module = importlib.import_module(module_name)
    return tree_sitter.Language(getattr(module, func_name)())


def _load_from_language_pack(language: str):
    from tree_sitter_language_pack import get_language

    return get_language(language)


@lru_cache(maxsize=None)
def get_parser(language: str) -> tree_sitter.Parser | None:
    """Return a cached parser for language, or None if no grammar is installed."""
    loaders = []
    if language in GRAMMARS:
        loaders.append(_load_from_package)
    loaders.append(_load_from_language_pack)

    for loader in loaders:
        try:
            return tree_sitter.Parser(loader(language))
        # Missing package, missing function, blocked native library, unknown language...
        except Exception:
            continue
    return None
