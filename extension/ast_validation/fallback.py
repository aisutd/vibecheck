"""Lightweight structural checks for formats with no tree-sitter grammar available.

These are not full parsers. They catch the mistakes an LLM patch typically makes
(unbalanced braces, missing semicolons, unknown instructions, broken JSON arrays).
Each checker returns a list of (line, column, message) tuples, 1-indexed.
"""

import json
import re

DOCKER_INSTRUCTIONS = {
    "ADD", "ARG", "CMD", "COPY", "ENTRYPOINT", "ENV", "EXPOSE", "FROM", "HEALTHCHECK",
    "LABEL", "MAINTAINER", "ONBUILD", "RUN", "SHELL", "STOPSIGNAL", "USER", "VOLUME",
    "WORKDIR",
}
# Instructions whose arguments may be written as a JSON array (exec form).
EXEC_FORM = {"CMD", "ENTRYPOINT", "RUN", "SHELL", "VOLUME", "ADD", "COPY"}
HEREDOC = re.compile(r"<<-?\s*[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?")


def check_dockerfile(code: str) -> list[tuple[int, int, str]]:
    problems = []
    lines = code.splitlines()
    seen_from = False
    i = 0

    while i < len(lines):
        start = i
        raw = lines[i]
        stripped = raw.strip()
        i += 1
        if not stripped or stripped.startswith("#"):
            continue

        # Join continuation lines (comment lines inside a continuation are allowed).
        logical = stripped
        while logical.endswith("\\") and i < len(lines):
            nxt = lines[i].strip()
            i += 1
            if nxt.startswith("#"):
                continue
            logical = logical[:-1] + " " + nxt
        if logical.endswith("\\"):
            problems.append((start + 1, 1, "Line continuation at end of file"))
            logical = logical[:-1]

        # Skip heredoc bodies (RUN <<EOF ... EOF).
        for marker in HEREDOC.findall(logical):
            while i < len(lines) and lines[i].strip() != marker:
                i += 1
            if i >= len(lines):
                problems.append((start + 1, 1, f"Heredoc '{marker}' is never closed"))
            i += 1

        instruction, _, args = logical.partition(" ")
        keyword = instruction.upper()
        column = len(raw) - len(raw.lstrip()) + 1

        if keyword not in DOCKER_INSTRUCTIONS:
            problems.append((start + 1, column, f"Unknown Dockerfile instruction '{instruction}'"))
            continue
        if keyword == "FROM":
            seen_from = True
        elif keyword != "ARG" and not seen_from:
            problems.append((start + 1, column, f"'{keyword}' appears before any FROM"))

        args = args.strip()
        if keyword in EXEC_FORM and args.startswith("["):
            try:
                value = json.loads(args)
                if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                    raise ValueError
            except ValueError:
                problems.append((start + 1, column, f"{keyword} exec form is not a valid JSON string array"))
        elif keyword in {"FROM", "USER", "WORKDIR", "EXPOSE"} and not args:
            problems.append((start + 1, column, f"{keyword} is missing its argument"))

    if not seen_from:
        problems.append((1, 1, "Dockerfile has no FROM instruction"))
    return problems


def check_nginx(code: str) -> list[tuple[int, int, str]]:
    """Check brace balance and that every simple directive ends with ';'."""
    problems = []
    stack = []  # (line, column) of each open '{'
    pending = None  # (line, column) where the current unterminated directive started
    line, column = 1, 0
    quote = None
    i = 0

    while i < len(code):
        ch = code[i]
        column += 1

        if ch == "\n":
            line, column = line + 1, 0
        elif quote:
            if ch == "\\":
                i += 1
                column += 1
            elif ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            pending = pending or (line, column)
        elif ch == "#":
            while i < len(code) and code[i] != "\n":
                i += 1
            continue
        elif ch == "$" and code[i + 1 : i + 2] == "{":
            # ${variable} inside a value; not a block.
            end = code.find("}", i)
            if end == -1:
                problems.append((line, column, "Unclosed '${' variable"))
                break
            column += end - i
            i = end
            pending = pending or (line, column)
        elif ch == "{":
            # "listen 80 <newline> location / {" merges two directives into one block
            # header. A header may wrap, but only when the brace is alone on its line.
            if pending and pending[0] != line:
                line_start = code.rfind("\n", 0, i) + 1
                if code[line_start:i].strip():
                    problems.append((pending[0], pending[1], "Directive is missing a terminating ';'"))
            stack.append((line, column))
            pending = None
        elif ch == "}":
            if pending:
                problems.append((pending[0], pending[1], "Directive is missing a terminating ';'"))
                pending = None
            if not stack:
                problems.append((line, column, "Unmatched '}'"))
            else:
                stack.pop()
        elif ch == ";":
            pending = None
        elif not ch.isspace():
            pending = pending or (line, column)
        i += 1

    if quote:
        problems.append((line, column, "Unclosed string literal"))
    if pending:
        problems.append((pending[0], pending[1], "Directive is missing a terminating ';'"))
    for open_line, open_column in stack:
        problems.append((open_line, open_column, "Block '{' is never closed"))
    return problems


DOTENV_LINE = re.compile(r"^(export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*=")


def check_dotenv(code: str) -> list[tuple[int, int, str]]:
    """Every line must be blank, a comment, or KEY=value (quoted values may span lines)."""
    problems = []
    quote = None
    for number, line in enumerate(code.splitlines(), start=1):
        stripped = line.strip()
        if quote:
            if stripped.endswith(quote):
                quote = None
            continue
        if not stripped or stripped.startswith("#"):
            continue
        if not DOTENV_LINE.match(stripped):
            problems.append((number, 1, "Line is not a KEY=value assignment"))
            continue
        value = stripped.split("=", 1)[1].strip()
        if value[:1] in ("'", '"') and (len(value) == 1 or not value.endswith(value[0])):
            quote = value[0]
    if quote:
        problems.append((len(code.splitlines()), 1, "Unclosed quoted value"))
    return problems


def check_ini(code: str) -> list[tuple[int, int, str]]:
    """Sections, key = value / key: value pairs, comments and indented continuations."""
    problems = []
    for number, line in enumerate(code.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped[0] in "#;" or line[:1].isspace():
            continue
        if stripped.startswith("["):
            if not stripped.endswith("]"):
                problems.append((number, 1, "Section header is missing ']'"))
        elif "=" not in stripped and ":" not in stripped:
            problems.append((number, 1, "Line is not a section, key = value pair or comment"))
    return problems


CHECKERS = {
    "dockerfile": check_dockerfile,
    "nginx": check_nginx,
    "dotenv": check_dotenv,
    "ini": check_ini,
}
