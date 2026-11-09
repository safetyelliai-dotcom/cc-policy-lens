"""Inventories used by several rules: every hook and every MCP server, with origin.

Built from raw documents (not the merged view) because hooks and MCP servers from
every source run side by side; precedence does not remove them.
"""
from __future__ import annotations

import os
import re
import shlex
from typing import TYPE_CHECKING, Any

from ..collect import read_text_limited
from ..model import HookDef, McpServer

if TYPE_CHECKING:
    from . import Context

COMMAND_TYPES = ("command", None)


def _cmd_text(h: dict[str, Any]) -> str:
    parts = [str(h.get("command", ""))]
    args = h.get("args")
    if isinstance(args, list):
        parts.extend(str(a) for a in args)
    return " ".join(p for p in parts if p)


def hooks_from_doc(doc: Any, origin: str, path: str) -> list[HookDef]:
    """``{"hooks": {Event: [{matcher, hooks: [...]}]}}`` (settings) or the inner mapping (plugin)."""
    out: list[HookDef] = []
    if not isinstance(doc, dict):
        return out
    mapping = doc.get("hooks", doc) if isinstance(doc.get("hooks"), dict) else doc
    for event, groups in mapping.items():
        if not isinstance(groups, list):
            continue
        for g in groups:
            if not isinstance(g, dict):
                continue
            for h in g.get("hooks", []) if isinstance(g.get("hooks"), list) else []:
                if not isinstance(h, dict):
                    continue
                out.append(HookDef(
                    event=str(event), type=str(h.get("type", "command")), command=_cmd_text(h),
                    url=h.get("url") if isinstance(h.get("url"), str) else None,
                    headers=h.get("headers") if isinstance(h.get("headers"), dict) else {},
                    on_failure=h.get("onFailure") if isinstance(h.get("onFailure"), str) else None,
                    is_async=bool(h.get("async") or h.get("asyncRewake")),
                    origin=origin, path=path,
                    matcher=g.get("matcher") if isinstance(g.get("matcher"), str) else None))
    return out


_EVENT_LINE = re.compile(r"^\s{1,6}([A-Z][A-Za-z]+):\s*$")
_FIELD = re.compile(r"^\s*-?\s*(type|command|url|onFailure|async)\s*:\s*(.*?)\s*$")


def hooks_from_frontmatter(block: str, origin: str, path: str) -> list[HookDef]:
    """Best-effort read of a YAML ``hooks:`` block (no YAML library; nothing is executed).

    Each ``type:``/``command:`` group under an event becomes one HookDef; raw text is kept.
    """
    out: list[HookDef] = []
    event = "unknown"
    cur: dict[str, str] | None = None

    def flush() -> None:
        if cur is not None:
            out.append(HookDef(event=event, type=cur.get("type", "command"), command=cur.get("command", ""),
                               url=cur.get("url"), on_failure=cur.get("onFailure"),
                               is_async=cur.get("async", "").lower() == "true",
                               origin=origin, path=path, raw_text=block))
    for ln in block.splitlines():
        m = _EVENT_LINE.match(ln)
        if m:
            flush()
            cur, event = None, m.group(1)
            continue
        f = _FIELD.match(ln)
        if f:
            key, val = f.group(1), f.group(2).strip().strip("'\"")
            if key == "type" or cur is None or key in cur:
                flush()
                cur = {}
            cur[key] = val
    flush()
    if not out and block.strip():
        out.append(HookDef(event="unknown", type="command", command="", origin=origin, path=path, raw_text=block))
    return out


def enabled_plugins(ctx: "Context") -> dict[str, bool]:
    out: dict[str, bool] = {}
    for key, e in ctx.eff.subtree("enabledPlugins").items():
        if len(key) == 2 and isinstance(e.value, bool):
            out[key[1]] = e.value
    return out


def collect_hooks(ctx: "Context") -> list[HookDef]:
    col = ctx.col
    hooks: list[HookDef] = []
    for layer in ("managed", "local", "project", "user"):
        doc = col.settings.get(layer)
        if doc is not None and doc.data:
            hooks += hooks_from_doc(doc.data.get("hooks", {}), layer, doc.info.path)
    for doc in col.managed_dropins:
        if doc.data:
            hooks += hooks_from_doc(doc.data.get("hooks", {}), "managed", doc.info.path)
    enabled = enabled_plugins(ctx)
    for p in col.plugins:
        p.enabled = enabled.get(p.plugin_id, False)
        if p.enabled and p.hooks_doc:
            hooks += hooks_from_doc(p.hooks_doc, f"plugin:{p.plugin_id}",
                                    os.path.join(p.path or "", "hooks", "hooks.json"))
    for md in [*col.skills, *col.agents]:
        block = md.blocks.get("hooks")
        if block:
            hooks += hooks_from_frontmatter(block, f"{md.kind}:{md.scope}", md.path)
    return hooks


def _servers(doc: Any) -> dict[str, Any]:
    if not isinstance(doc, dict):
        return {}
    s = doc.get("mcpServers")
    return s if isinstance(s, dict) else {}


def collect_mcp(ctx: "Context") -> list[McpServer]:
    col = ctx.col
    out: list[McpServer] = []

    def add(doc: Any, origin: str, path: str) -> None:
        for name, cfg in _servers(doc).items():
            if isinstance(cfg, dict):
                out.append(McpServer(name=str(name), origin=origin, path=path, config=cfg))
    if col.project_mcp is not None:
        add(col.project_mcp.data, "project_mcp", col.project_mcp.info.path)
    if col.user_state is not None and col.user_state.data:
        add(col.user_state.data, "user_state", col.user_state.info.path)
        add(col.user_state.data.get("project"), "local_state", col.user_state.info.path)
    if col.managed_mcp is not None:
        add(col.managed_mcp.data, "managed_mcp", col.managed_mcp.info.path)
    enabled = enabled_plugins(ctx)
    for p in col.plugins:
        if enabled.get(p.plugin_id) and p.mcp_doc:
            doc = p.mcp_doc if "mcpServers" in p.mcp_doc else {"mcpServers": p.mcp_doc}
            add(doc, f"plugin:{p.plugin_id}", os.path.join(p.path or "", ".mcp.json"))
    return out


def argv(cfg: dict[str, Any]) -> list[str]:
    """command + args as a token list (shlex split of the command string; nothing executed)."""
    cmd = cfg.get("command")
    tokens: list[str] = []
    if isinstance(cmd, str) and cmd.strip():
        try:
            tokens = shlex.split(cmd)
        except ValueError:
            tokens = cmd.split()
    args = cfg.get("args")
    if isinstance(args, list):
        tokens += [str(a) for a in args]
    return tokens


def hook_script(ctx: "Context", h: HookDef) -> str | None:
    """Text of the script a command hook runs, when it can be located safely inside its root."""
    try:
        tokens = shlex.split(h.command)
    except ValueError:
        tokens = h.command.split()
    if not tokens:
        return None
    project = ctx.col.project
    plugin_root = None
    if h.origin.startswith("plugin:"):
        plugin_root = os.path.dirname(os.path.dirname(h.path))
    for tok in tokens[:3]:
        path, root = None, None
        if "${CLAUDE_PROJECT_DIR}" in tok or "$CLAUDE_PROJECT_DIR" in tok:
            if project:
                path = tok.replace("${CLAUDE_PROJECT_DIR}", project).replace("$CLAUDE_PROJECT_DIR", project)
                root = project
        elif "${CLAUDE_PLUGIN_ROOT}" in tok and plugin_root:
            path, root = tok.replace("${CLAUDE_PLUGIN_ROOT}", plugin_root), plugin_root
        elif tok.startswith("./") and project and h.origin in ("project", "local"):
            path, root = os.path.join(project, tok[2:]), project
        if path and root:
            text = read_text_limited(path, confine=os.path.realpath(root))
            if text is not None:
                return text
    return None
