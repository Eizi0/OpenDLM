"""List every translatable message id used by the application.

Usage: python scripts/extract_messages.py
Message ids are the string literals passed to _(), t() or N_() in Python code and templates.
"""

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_CALL = re.compile(r"""\b_\(\s*(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')""")


def python_ids(path: Path) -> set[str]:
    ids = set()
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("t", "N_", "_"):
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                ids.add(node.args[0].value)
    return ids


def template_ids(path: Path) -> set[str]:
    ids = set()
    for m in TEMPLATE_CALL.finditer(path.read_text()):
        raw = m.group(1) if m.group(1) is not None else m.group(2)
        ids.add(raw.replace('\\"', '"').replace("\\'", "'"))
    return ids


def extract() -> set[str]:
    ids: set[str] = set()
    for path in (ROOT / "app").rglob("*.py"):
        if "locale" in path.parts:
            continue
        ids |= python_ids(path)
    for path in (ROOT / "app" / "templates").glob("*.html"):
        ids |= template_ids(path)
    return ids


if __name__ == "__main__":
    for msgid in sorted(extract()):
        sys.stdout.write(msgid + "\n")
