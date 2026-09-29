#!/usr/bin/env python3
"""CI gate: process execution may exist ONLY in packages/core/guard.py.

Fails (exit 1) if any other Python file references subprocess spawning, os.system,
os.exec*, or asyncio subprocess creation. This is what keeps run_tool the single
un-bypassable exec choke point where scope + rate + redaction are enforced.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# guard.py is the sanctioned exec choke point; this checker names the forbidden
# APIs in its own text, so it is exempt from scanning itself.
ALLOWED = {Path("packages/core/guard.py"), Path("scripts/check_no_subprocess.py")}

FORBIDDEN = re.compile(
    r"\b(?:"
    r"subprocess\.(?:Popen|run|call|check_output|check_call)"
    r"|os\.system"
    r"|os\.exec[lv]?[pe]*"
    r"|os\.popen"
    r"|os\.spawn\w*"
    r"|asyncio\.create_subprocess_(?:exec|shell)"
    r"|loop\.subprocess_(?:exec|shell)"
    r"|pty\.spawn"
    r"|commands\.(?:getoutput|getstatusoutput)"
    r")\b"
)
# Bare `import subprocess` is also only allowed in the guard.
IMPORT_SUBPROCESS = re.compile(r"^\s*(?:import\s+subprocess|from\s+subprocess\s+import)\b")

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache"}


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    violations: list[str] = []
    for path in root.rglob("*.py"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        rel = path.relative_to(root)
        if rel in ALLOWED:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            stripped = line.split("#", 1)[0]
            if FORBIDDEN.search(stripped) or IMPORT_SUBPROCESS.search(stripped):
                violations.append(f"{rel}:{lineno}: {line.strip()}")

    if violations:
        print("FAIL: process execution found outside packages/core/guard.py:\n")
        for v in violations:
            print("  " + v)
        print("\nAll engine execution must go through guard.run_tool().")
        return 1
    print("OK: no subprocess/exec usage outside guard.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
