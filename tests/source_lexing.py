#!/usr/bin/env python3
"""Language-specific comment removal for checks that inspect source text."""

from __future__ import annotations

import argparse
import io
from pathlib import Path
import tokenize


def c_like_code(source: str, *, raw_quotes: bool = False) -> str:
    """Blank C/Go-style comments while preserving quoted literals and line positions."""
    result = []
    index = 0
    state = "code"
    escaped = False
    while index < len(source):
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "line-comment":
            if character == "\n":
                result.append(character)
                state = "code"
            else:
                result.append(" ")
        elif state == "block-comment":
            if character == "*" and following == "/":
                result.extend((" ", " "))
                index += 1
                state = "code"
            else:
                result.append("\n" if character == "\n" else " ")
        elif state in ("string", "rune"):
            result.append(character)
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif (state == "string" and character == '"') or (state == "rune" and character == "'"):
                state = "code"
        elif state == "raw":
            result.append(character)
            if character == "`":
                state = "code"
        elif character == "/" and following == "/":
            result.extend((" ", " "))
            index += 1
            state = "line-comment"
        elif character == "/" and following == "*":
            result.extend((" ", " "))
            index += 1
            state = "block-comment"
        else:
            result.append(character)
            if character == '"':
                state = "string"
            elif character == "'":
                state = "rune"
            elif raw_quotes and character == "`":
                state = "raw"
        index += 1
    return "".join(result)


def go_code(source: str) -> str:
    return c_like_code(source, raw_quotes=True)


def python_code(source: str) -> str:
    """Blank Python comments and docstrings while retaining executable strings."""
    tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    output = []
    previous_type = tokenize.INDENT
    for token in tokens:
        token_type, value, _, _, _ = token
        if token_type == tokenize.COMMENT:
            value = ""
        elif token_type == tokenize.STRING and previous_type in (
                tokenize.INDENT, tokenize.NEWLINE, tokenize.DEDENT):
            value = ""
        output.append((token_type, value))
        if token_type not in (tokenize.NL, tokenize.COMMENT, tokenize.ENCODING):
            previous_type = token_type
    return tokenize.untokenize(output)


def shell_code(source: str) -> str:
    """Blank shell comments while preserving quoted hashes and physical lines."""
    result = []
    quote = None
    escaped = False
    comment = False
    at_word_start = True
    for character in source:
        if comment:
            if character == "\n":
                result.append(character)
                comment = False
                at_word_start = True
            else:
                result.append(" ")
        elif escaped:
            result.append(character)
            escaped = False
            at_word_start = False
        elif quote == '"' and character == "\\":
            result.append(character)
            escaped = True
        elif quote and character == quote:
            result.append(character)
            quote = None
            at_word_start = False
        elif quote:
            result.append(character)
        elif character in ("'", '"', "`"):
            result.append(character)
            quote = character
            at_word_start = False
        elif character == "#" and at_word_start:
            result.append(" ")
            comment = True
        else:
            result.append(character)
            at_word_start = character.isspace() or character in ";|&()"
    uncommented = "".join(result)
    output = []
    heredocs = []
    def declared_heredocs(line):
        found = []
        index = 0
        quote = None
        escaped = False
        while index < len(line):
            character = line[index]
            if escaped:
                escaped = False
            elif quote == '"' and character == "\\":
                escaped = True
            elif quote and character == quote:
                quote = None
            elif quote:
                pass
            elif character in ("'", '"', "`"):
                quote = character
            elif line[index:index + 2] == "<<" and line[index:index + 3] != "<<<":
                cursor = index + 2
                # `<<-` strips leading TABS from the body and from the terminator; plain `<<`
                # requires the terminator alone on its line with no leading whitespace at all.
                # The mode travels with the delimiter because the two are not interchangeable:
                # accepting an indented terminator for a plain heredoc ends masking early, and
                # the source checks then read heredoc DATA as executable shell.
                dash = False
                if cursor < len(line) and line[cursor] == "-":
                    dash = True
                    cursor += 1
                while cursor < len(line) and line[cursor].isspace():
                    cursor += 1
                delimiter_quote = line[cursor] if cursor < len(line) and line[cursor] in "'\"" else None
                if delimiter_quote:
                    cursor += 1
                start = cursor
                while cursor < len(line) and (line[cursor].isalnum() or line[cursor] == "_"):
                    cursor += 1
                if cursor > start and (not delimiter_quote or
                                       (cursor < len(line) and line[cursor] == delimiter_quote)):
                    found.append((line[start:cursor], dash))
                index = cursor
                continue
            index += 1
        return found

    for line in uncommented.splitlines(keepends=True):
        if heredocs:
            delimiter, dash = heredocs[0]
            body = line[:-1] if line.endswith("\n") else line
            # Tabs only, and only for `<<-`. `line.strip()` accepted an indented terminator for
            # both forms, so a body line that merely MENTIONS the delimiter — indented, inside the
            # data — closed the heredoc, and everything after it was lexed as code.
            candidate = body.lstrip("\t") if dash else body
            output.append("\n" if line.endswith("\n") else "")
            if candidate == delimiter:
                heredocs.pop(0)
            continue
        output.append(line)
        heredocs.extend(declared_heredocs(line))
    return "".join(output)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("language", choices=("c", "go", "python", "shell"))
    parser.add_argument("path", type=Path)
    arguments = parser.parse_args()
    source = arguments.path.read_text(encoding="utf-8")
    functions = {
        "c": c_like_code,
        "go": go_code,
        "python": python_code,
        "shell": shell_code,
    }
    print(functions[arguments.language](source), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
