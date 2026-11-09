#!/usr/bin/env python3
"""PreToolUse guard for Bash. Defense in depth on top of permission deny rules.

Hard controls live in settings.json permissions.deny and the sandbox.
This hook catches variants those rules may miss (pipes, subshells, odd spacing).
"""
import json
import re
import sys

DENY = [
    (re.compile(r"(^|[\s;&|(`$])sudo\b"), "sudo is not allowed"),
    (re.compile(r"(^|[\s;&|(`$])(curl|wget|nc|ncat|telnet)\b"), "network tools are not allowed (offline tool)"),
    (re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*\s+(/|~|\$HOME)(\s|$)"), "recursive delete of root or home"),
    (re.compile(r"\bchmod\s+(-R\s+)?0?777\b"), "world-writable permissions"),
]

MANAGED_MARKERS = ("ClaudeCode/managed-settings", "/etc/claude-code")
WRITE_OPS = re.compile(r"(>|\btee\b|\bcp\b|\bmv\b|\brm\b|\bsed\s+-i|\bchmod\b|\bchown\b|\bln\b|\btouch\b)")

ASK = [
    (re.compile(r"\bpip3?\s+install\b"), "installing packages needs approval (stdlib-only project)"),
    (re.compile(r"\bgit\s+push\b"), "git push needs approval"),
]


def decide(decision: str, reason: str) -> None:
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }))
    sys.exit(0)


def main() -> None:
    data = json.load(sys.stdin)
    command = str((data.get("tool_input") or {}).get("command", ""))

    for rx, reason in DENY:
        if rx.search(command):
            decide("deny", f"Blocked by guard_bash: {reason}")

    if any(m in command for m in MANAGED_MARKERS) and WRITE_OPS.search(command):
        decide("deny", "Blocked by guard_bash: modifying managed settings is not allowed")

    for rx, reason in ASK:
        if rx.search(command):
            decide("ask", reason)

    sys.exit(0)


if __name__ == "__main__":
    main()
