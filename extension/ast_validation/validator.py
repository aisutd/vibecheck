"""Validate LLM-generated security patches with tree-sitter.

A patch is accepted only if it:
  - is non-empty raw code (no markdown fences or chatty preamble),
  - parses without new syntax errors (ERROR / MISSING nodes),
  - is not truncated compared to the original file,
  - keeps every function / class / method defined in the original,
  - actually changes the file.
"""

import ast
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass, field

from .fallback import CHECKERS
from .languages import detect_language, get_parser

PASS, FAIL, SKIP = "pass", "fail", "skip"

# Node types that count as top-level structure the patch must not delete.
DEFINITION_NODES = {
    "python": {"function_definition", "class_definition"},
    "javascript": {"function_declaration", "generator_function_declaration", "class_declaration", "method_definition"},
    "typescript": {"function_declaration", "class_declaration", "method_definition", "interface_declaration", "abstract_class_declaration"},
    "tsx": {"function_declaration", "class_declaration", "method_definition", "interface_declaration", "abstract_class_declaration"},
    "ruby": {"method", "singleton_method", "class", "module"},
    "go": {"function_declaration", "method_declaration", "type_spec"},
    "java": {"class_declaration", "interface_declaration", "method_declaration", "constructor_declaration", "enum_declaration"},
    "csharp": {"class_declaration", "interface_declaration", "method_declaration", "constructor_declaration", "struct_declaration"},
    "php": {"function_definition", "class_declaration", "method_declaration"},
    "kotlin": {"function_declaration", "class_declaration", "object_declaration"},
    "rust": {"function_item", "struct_item", "enum_item", "impl_item", "trait_item"},
    "c": {"function_definition"},
    "cpp": {"function_definition", "class_specifier"},
}

# Formats where our checker beats the available grammar on real files:
# tree-sitter dotenv rejects ${VAR} interpolation, nginx rejects several top-level
# blocks in one file, and ini rejects indented multi-line values.
FALLBACK_FIRST = {"dotenv", "nginx", "ini"}

FENCE = re.compile(r"^\s*```|```\s*$")
PREAMBLE = re.compile(
    r"^\s*(here(?:'s| is| are)|sure[,!]|certainly|below is|the following|i(?:'ve| have) (?:fixed|updated))",
    re.IGNORECASE,
)


@dataclass
class Issue:
    check: str
    message: str
    line: int = 0
    column: int = 0
    snippet: str = ""


@dataclass
class ValidationResult:
    file: str
    language: str | None
    parser: str  # "tree-sitter", "fallback" or "none"
    valid: bool
    checks: dict[str, str] = field(default_factory=dict)
    issues: list[Issue] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def reasons(self) -> list[str]:
        return [check for check, status in self.checks.items() if status == FAIL]


# Syntax

def _snippet(code: bytes, start: int, end: int, limit: int = 80) -> str:
    text = code[start:end].decode("utf-8", errors="replace").strip().replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _tree_sitter_errors(tree, source: bytes) -> list[Issue]:
    """Collect ERROR and MISSING nodes, without descending into ERROR subtrees."""
    issues = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.is_missing:
            issues.append(Issue(
                "syntax", f"Missing '{node.type}'",
                node.start_point[0] + 1, node.start_point[1] + 1,
            ))
        elif node.is_error:
            issues.append(Issue(
                "syntax", "Unexpected or unparseable code",
                node.start_point[0] + 1, node.start_point[1] + 1,
                _snippet(source, node.start_byte, node.end_byte),
            ))
        elif node.has_error:
            stack.extend(reversed(node.children))
    issues.sort(key=lambda issue: (issue.line, issue.column))
    return issues


def _native_errors(code: str, language: str) -> list[Issue]:
    """Second opinion from the language's own parser where Python ships one."""
    if language == "python":
        try:
            ast.parse(code)
        except SyntaxError as e:
            return [Issue("syntax", f"Python: {e.msg}", e.lineno or 0, e.offset or 0, (e.text or "").strip())]
        except ValueError as e:  # e.g. null bytes
            return [Issue("syntax", f"Python: {e}")]
    elif language == "json":
        try:
            json.loads(code)
        except json.JSONDecodeError as e:
            return [Issue("syntax", f"JSON: {e.msg}", e.lineno, e.colno)]
    elif language == "php" and "<?" not in code:
        # Without an opening tag PHP serves the whole file as plain text.
        return [Issue("syntax", "PHP file has no '<?php' opening tag", 1, 1)]
    return []


def parse(code: str, language: str):
    """Parse code, returning the tree-sitter tree or None if no grammar is installed."""
    parser = get_parser(language)
    return parser.parse(_source(code)) if parser else None


def _source(code: str) -> bytes:
    # Some grammars (e.g. dockerfile) require a final newline; dataset files usually lack one.
    return (code if code.endswith("\n") else code + "\n").encode("utf-8")


def _fallback_errors(code: str, language: str) -> list[Issue]:
    return [Issue("syntax", message, line, column) for line, column, message in CHECKERS[language](code)]


def syntax_issues(code: str, language: str | None) -> tuple[str, list[Issue]]:
    """Return (parser_used, issues) for code in language."""
    if language is None:
        return "none", []

    if language in FALLBACK_FIRST:
        return "fallback", _fallback_errors(code, language)

    tree = parse(code, language)
    if tree is not None:
        issues = _tree_sitter_errors(tree, _source(code))
        # Only add the native result when tree-sitter missed it, to avoid double counting.
        if not issues:
            issues = _native_errors(code, language)
        return "tree-sitter", issues

    if language in CHECKERS:
        return "fallback", _fallback_errors(code, language)

    native = _native_errors(code, language)
    return ("native", native) if language in ("python", "json") else ("none", [])


# Structure

def _definition_name(node) -> str:
    name = node.child_by_field_name("name")
    if name is None:
        # C/C++ put the name inside nested declarators.
        declarator = node.child_by_field_name("declarator")
        while declarator is not None and declarator.child_by_field_name("declarator") is not None:
            declarator = declarator.child_by_field_name("declarator")
        name = declarator
    if name is None:
        name = next(
            (c for c in node.named_children if "identifier" in c.type or c.type == "constant"),
            None,
        )
    return name.text.decode("utf-8", errors="replace") if name is not None else "<anonymous>"


def definitions(code: str, language: str | None) -> Counter | None:
    """Count definitions as 'type name' strings, or None if not supported for language."""
    node_types = DEFINITION_NODES.get(language or "")
    tree = parse(code, language) if node_types else None
    if tree is None:
        return None

    found = Counter()
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in node_types:
            found[f"{node.type} {_definition_name(node)}"] += 1
        stack.extend(node.children)
    return found


# Validation entry points

def validate_code(code: str, path: str, language: str | None = None) -> ValidationResult:
    """Check that a single file parses."""
    language = language or detect_language(path, code)
    parser, issues = syntax_issues(code, language)
    result = ValidationResult(file=path, language=language, parser=parser, valid=True)
    result.checks["syntax"] = SKIP if parser == "none" else (FAIL if issues else PASS)
    result.issues = issues
    result.valid = result.checks["syntax"] != FAIL
    return result


def validate_patch(
    original: str,
    patched: str,
    path: str,
    language: str | None = None,
    min_length_ratio: float = 0.5,
    allow_preexisting_errors: bool = True,
    require_change: bool = True,
    strict: bool = False,
) -> ValidationResult:
    """Check that patched is a structurally sound replacement for original.

    allow_preexisting_errors: if the original already had N syntax errors (common
        with templated files tree-sitter can't fully parse), the patch may keep up to N.
    strict: treat unsupported languages as a failure instead of skipping the syntax check.
    """
    language = language or detect_language(path, original)
    result = ValidationResult(file=path, language=language, parser="none", valid=True)
    checks, issues = result.checks, result.issues

    # 1. Raw output
    if not patched.strip():
        checks["non_empty"] = FAIL
        issues.append(Issue("non_empty", "Patch is empty"))
        result.valid = False
        return result
    checks["non_empty"] = PASS

    lines = patched.strip().splitlines()
    wrapped = bool(FENCE.search(lines[0]) or FENCE.search(lines[-1]) or PREAMBLE.match(lines[0]))
    # Don't flag a fence the original file itself had (e.g. a markdown string in code).
    if wrapped and "```" in original and not PREAMBLE.match(lines[0]):
        wrapped = False
    checks["raw_output"] = FAIL if wrapped else PASS
    if wrapped:
        issues.append(Issue("raw_output", "Patch is wrapped in markdown fences or explanation text", 1, 1, lines[0][:80]))

    # 2. Syntax
    parser, patched_errors = syntax_issues(patched, language)
    result.parser = parser
    if parser == "none":
        checks["syntax"] = FAIL if strict else SKIP
        if strict:
            issues.append(Issue("syntax", f"No parser available for language '{language}'"))
    else:
        allowed = len(syntax_issues(original, language)[1]) if allow_preexisting_errors else 0
        if len(patched_errors) > allowed:
            checks["syntax"] = FAIL
            issues.extend(patched_errors)
        else:
            checks["syntax"] = PASS

    # 3. Truncation
    original_lines = len(original.strip().splitlines())
    if original_lines >= 10 and len(lines) < original_lines * min_length_ratio:
        checks["not_truncated"] = FAIL
        issues.append(Issue(
            "not_truncated",
            f"Patch has {len(lines)} lines vs {original_lines} in the original (possible truncation)",
        ))
    else:
        checks["not_truncated"] = PASS

    # 4. Structure: nothing the original defined may disappear.
    before = definitions(original, language)
    after = definitions(patched, language) if before is not None else None
    if before is None or after is None:
        checks["structure"] = SKIP
    else:
        removed = before - after
        checks["structure"] = FAIL if removed else PASS
        for definition, count in sorted(removed.items()):
            kind, _, name = definition.partition(" ")
            issues.append(Issue("structure", f"Patch removed {kind.replace('_', ' ')} '{name}'" + (f" (x{count})" if count > 1 else "")))

    # 5. The patch must do something.
    if require_change:
        unchanged = original.strip() == patched.strip()
        checks["changed"] = FAIL if unchanged else PASS
        if unchanged:
            issues.append(Issue("changed", "Patch is identical to the original file"))

    result.valid = FAIL not in checks.values()
    return result
