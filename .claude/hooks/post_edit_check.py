#!/usr/bin/env python3
"""PostToolUse check: syntax-check edited Python files.

Exit 2 shows stderr to Claude so it can fix the error right away.
"""
import json
import subprocess
import sys


def main() -> None:
    data = json.load(sys.stdin)
    path = str((data.get("tool_input") or {}).get("file_path", ""))
    if not path.endswith(".py"):
        sys.exit(0)
    result = subprocess.run(
        [sys.executable, "-m", "py_compile", path],
        capture_output=True, text=True, timeout=20,
    )
    if result.returncode != 0:
        sys.stderr.write(f"Syntax check failed for {path}:\n{result.stderr}")
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
