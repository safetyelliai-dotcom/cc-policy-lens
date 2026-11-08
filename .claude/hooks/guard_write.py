#!/usr/bin/env python3
"""PreToolUse guard for Edit/Write.

Denies the tool call when:
  1. the target path is outside the project directory, or inside a managed-settings directory
  2. the new content looks like it contains a real secret

Exit 0 with no output = no decision (normal permission flow applies).
Any crash exits non-zero; with onFailure="block" the call is blocked (fail-closed).
"""
import json
import os
import re
import sys

SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key"),
    (re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"), "Anthropic API key"),
    (re.compile(r"sk-[A-Za-z0-9]{32,}"), "API secret key"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), "GitHub token"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
]

PROTECTED_DIRS = [
    "/Library/Application Support/ClaudeCode",
    "/etc/claude-code",
]


def deny(reason: str) -> None:
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))
    sys.exit(0)


def is_inside(child: str, parent: str) -> bool:
    return child == parent or child.startswith(parent.rstrip(os.sep) + os.sep)


def main() -> None:
    data = json.load(sys.stdin)
    tool_input = data.get("tool_input") or {}
    cwd = data.get("cwd") or os.getcwd()
    project = os.path.realpath(os.environ.get("CLAUDE_PROJECT_DIR") or cwd)

    path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
    if path:
        real = os.path.realpath(path if os.path.isabs(path) else os.path.join(cwd, path))
        for d in PROTECTED_DIRS:
            if is_inside(real, os.path.realpath(d)):
                deny(f"Writes to managed-settings directory are not allowed: {d}")
        if not is_inside(real, project):
            deny(f"Writes outside the project directory are not allowed: {real}")

    chunks = [str(tool_input.get(k, "")) for k in ("content", "new_string", "new_source")]
    for edit in tool_input.get("edits") or []:
        chunks.append(str(edit.get("new_string", "")))
    text = "\n".join(chunks)

    for rx, name in SECRET_PATTERNS:
        if rx.search(text):
            deny(f"Content looks like it contains a {name}. "
                 "Build fake secrets at runtime in tests (see CLAUDE.md rule 2).")

    sys.exit(0)


if __name__ == "__main__":
    main()
