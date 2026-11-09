"""HOOK-* checks. Hook inventory comes from rules.inventory (every source, unmerged)."""
from __future__ import annotations

import fnmatch
import re

from ..model import HookDef, RuleResult
from . import Context, finding, result, rule
from .inventory import hook_script

# Origins that bring code the user did not write themselves.
_SUPPLY_CHAIN = ("project", "local", "skill:project", "skill:user", "agent:project")


def _supply_chain(h: HookDef) -> bool:
    return h.origin in _SUPPLY_CHAIN or h.origin.startswith("plugin:")


def _is_command(h: HookDef) -> bool:
    return h.type in ("command", "", None)


def _desc(h: HookDef) -> str:
    target = h.url if h.type == "http" else h.command
    return f"{h.event} [{h.type}] {target or '(no command)'}"


@rule("HOOK-001", settings=False)
def hook_001(ctx: Context) -> RuleResult:
    rid = "HOOK-001"
    if not ctx.hooks:
        return result(rid, [], status="na", note="no hooks defined")
    out = [finding(rid, f"hook from {h.origin} runs outside the sandbox with your user rights",
                   evidence=_desc(h), layer=h.origin, path=h.path)
           for h in ctx.hooks if _supply_chain(h)]
    own = sorted({h.origin for h in ctx.hooks if not _supply_chain(h)})
    return result(rid, out, note=f"hooks from {', '.join(own)} not flagged" if own else None)


_POLICY_EVENTS = ("PreToolUse", "PermissionRequest")


@rule("HOOK-002", settings=False)
def hook_002(ctx: Context) -> RuleResult:
    rid = "HOOK-002"
    policy = [h for h in ctx.hooks if h.event in _POLICY_EVENTS and (h.type in ("command", "http"))]
    if not policy:
        return result(rid, [], status="na", note="no PreToolUse/PermissionRequest hooks")
    out = []
    for h in policy:
        if h.is_async:
            out.append(finding(rid, "async policy hook: onFailure does not apply and the tool call is not held",
                               evidence=_desc(h), layer=h.origin, path=h.path))
        elif h.on_failure != "block":
            out.append(finding(rid, f"policy hook fails open (onFailure={h.on_failure or 'continue (default)'}): "
                                    "a crash or timeout lets the tool call proceed",
                               evidence=_desc(h), layer=h.origin, path=h.path))
    return result(rid, out)


_NET = re.compile(
    r"(?<![\w-])(curl|wget|nc|ncat|socat|telnet)(?![\w-])"
    r"|/dev/(?:tcp|udp)/"
    r"|\bpython[0-9.]*\s+-c\b.*\b(urllib|requests|http\.client|socket)\b"
    r"|\bnode\s+-e\b.*\b(fetch|https?\.request|net\.connect)\b"
    r"|\bhttps?://", re.S)


@rule("HOOK-003", settings=False)
def hook_003(ctx: Context) -> RuleResult:
    rid = "HOOK-003"
    cmds = [h for h in ctx.hooks if _is_command(h)]
    if not cmds:
        return result(rid, [], status="na", note="no command hooks")
    out = []
    for h in cmds:
        text = h.command or h.raw_text
        m = _NET.search(text)
        if m:
            out.append(finding(rid, f"command hook contains a network transfer pattern ({m.group(0).strip()[:20]!r})",
                               evidence=_desc(h), layer=h.origin, path=h.path))
    return result(rid, out)


_ENV_EVENTS = ("SessionStart", "Setup", "CwdChanged", "FileChanged")


@rule("HOOK-004", settings=False)
def hook_004(ctx: Context) -> RuleResult:
    rid = "HOOK-004"
    cand = [h for h in ctx.hooks if h.event in _ENV_EVENTS and _is_command(h)]
    if not cand:
        return result(rid, [], status="na", note="no SessionStart/Setup/CwdChanged/FileChanged command hooks")
    out = []
    for h in cand:
        where = None
        if "CLAUDE_ENV_FILE" in (h.command or h.raw_text):
            where = "command"
        else:
            script = hook_script(ctx, h)
            if script and "CLAUDE_ENV_FILE" in script:
                where = "script"
        if where:
            out.append(finding(rid, f"hook writes CLAUDE_ENV_FILE (in its {where}); the content runs before every "
                                    "later Bash command", severity="high" if _supply_chain(h) else None,
                               evidence=_desc(h), layer=h.origin, path=h.path))
    return result(rid, out)


_ENV_REF = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)")


@rule("HOOK-005")
def hook_005(ctx: Context) -> RuleResult:
    rid = "HOOK-005"
    http = [h for h in ctx.hooks if h.type == "http"]
    if not http:
        return result(rid, [], status="na", note="no HTTP hooks")
    allowed = ctx.eff.get("allowedHttpHookUrls")
    out = []
    if not isinstance(allowed, list):
        out.append(finding(rid, f"{len(http)} HTTP hook(s) and no allowedHttpHookUrls: any URL is allowed",
                           evidence="; ".join(_desc(h) for h in http[:5])))
    else:
        for h in http:
            if not any(isinstance(p, str) and fnmatch.fnmatchcase(h.url or "", p) for p in allowed):
                out.append(finding(rid, "HTTP hook URL is not in allowedHttpHookUrls (Claude Code blocks it)",
                                   severity="info", evidence=_desc(h), layer=h.origin, path=h.path))
    if not isinstance(ctx.eff.get("httpHookAllowedEnvVars"), list):
        for h in http:
            refs = sorted({m.group(1) for v in h.headers.values() if isinstance(v, str) for m in _ENV_REF.finditer(v)})
            if refs:
                out.append(finding(rid, "HTTP hook headers use environment variables and httpHookAllowedEnvVars "
                                        "is not set", severity="low", evidence=", ".join(refs),
                                   layer=h.origin, path=h.path))
    return result(rid, out)


@rule("HOOK-006")
def hook_006(ctx: Context) -> RuleResult:
    rid = "HOOK-006"
    e = ctx.eff.entry("allowManagedHooksOnly")
    if e is not None and e.value is True and e.source and e.source.layer == "managed":
        return result(rid, [], note="only managed hooks run")
    ev = None
    if e is not None and e.ignored:
        ev = "; ".join(f"{p.layer}: {reason}" for _, p, reason in e.ignored)
    return result(rid, [finding(rid, "allowManagedHooksOnly is not set in managed settings: user, project and "
                                     "plugin hooks all run", evidence=ev)])
