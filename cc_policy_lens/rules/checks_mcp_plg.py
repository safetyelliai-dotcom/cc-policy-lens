"""MCP-* and PLG-* checks."""
from __future__ import annotations

import os
import re

from ..mask import find_secret, is_env_reference, is_sensitive_key, mask_value, strip_references
from ..model import McpServer, RuleResult
from . import Context, finding, result, rule
from .inventory import argv, enabled_plugins

# ---------------------------------------------------------------- MCP-001


@rule("MCP-001")
def mcp_001(ctx: Context) -> RuleResult:
    rid = "MCP-001"
    if ctx.col.project is None:
        return result(rid, [], status="na", note="no project")
    pm = ctx.col.project_mcp
    if pm is not None and pm.info.error_kind in ("permission", "io", "outside", "too_large", "too_deep"):
        return result(rid, [], status="unknown", note=f".mcp.json not readable: {pm.info.error}")
    disabled = ctx.eff.get("disabledMcpjsonServers") or []
    servers = [s for s in ctx.mcp if s.origin == "project_mcp"]
    out = [finding(rid, "repository .mcp.json defines an MCP server that runs on every clone's machine",
                   evidence=f"{s.name}: {' '.join(argv(s.config)) or s.config.get('url', '')}",
                   layer="project", path=s.path)
           for s in servers if s.name not in disabled]
    doc = ctx.col.settings.get("project")
    data = (doc.data or {}) if doc is not None else {}
    if data.get("enableAllProjectMcpServers") is True:
        out.append(finding(rid, "shared project settings set enableAllProjectMcpServers: the repo approves its own "
                                "MCP servers (CVE-2025-59536 pattern)", severity="high",
                           evidence="enableAllProjectMcpServers: true", layer="project", path=doc.info.path))
    if isinstance(data.get("enabledMcpjsonServers"), list) and data["enabledMcpjsonServers"]:
        out.append(finding(rid, "shared project settings pre-approve .mcp.json servers with enabledMcpjsonServers",
                           severity="high", evidence=", ".join(map(str, data["enabledMcpjsonServers"])),
                           layer="project", path=doc.info.path))
    if not servers and not out:
        return result(rid, [], status="na", note="no repository .mcp.json servers")
    return result(rid, out)


# ---------------------------------------------------------------- MCP-002

_RUNNERS = {"npx": 1, "bunx": 1, "uvx": 1, "pnpm": 2, "yarn": 2, "pipx": 2}   # tokens before package
_SUB = {"pnpm": "dlx", "yarn": "dlx", "pipx": "run"}
_SEMVER = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?$")
# flags whose next token is a value, not the package
_VALUE_FLAGS = {"-p", "--package", "--from", "--spec", "--python", "--with", "--index-url", "--registry",
                "-c", "--call", "--cache", "--userconfig"}


def _npm_version(spec: str) -> str | None:
    """'@scope/name@1.2.3' -> '1.2.3'; 'name' -> None."""
    at = spec.rfind("@")
    return spec[at + 1:] if at > 0 else None


def _package(tokens: list[str], runner: str) -> tuple[str | None, str]:
    """Return (package spec, ecosystem) from runner argv."""
    rest = tokens[_RUNNERS[runner]:]
    eco = "py" if runner in ("uvx", "pipx") else "npm"
    i = 0
    while i < len(rest):
        t = rest[i]
        if t in ("-p", "--package", "--from", "--spec") and i + 1 < len(rest):
            return rest[i + 1], eco                           # explicit package flag wins
        if t.startswith(("--package=", "--from=", "--spec=")):
            return t.split("=", 1)[1], eco
        if t in _VALUE_FLAGS:
            i += 2
            continue
        if t.startswith("-"):
            i += 1
            continue
        return t, eco
    return None, eco


def pinned(spec: str, eco: str) -> bool:
    if eco == "py":
        m = re.search(r"===?\s*([^\s,;]+)$", spec)
        return bool(m and _SEMVER.match(m.group(1)) or m and re.fullmatch(r"\d+(\.\d+)*", m.group(1)))
    v = _npm_version(spec)
    return bool(v and _SEMVER.match(v))


def _docker_pinned(tokens: list[str]) -> bool:
    return any("@sha256:" in t for t in tokens)


@rule("MCP-002", settings=False)
def mcp_002(ctx: Context) -> RuleResult:
    rid = "MCP-002"
    stdio = [s for s in ctx.mcp if argv(s.config)]
    if not stdio:
        return result(rid, [], status="na", note="no stdio MCP servers")
    out = []
    for s in stdio:
        tokens = argv(s.config)
        prog = os.path.basename(tokens[0])
        if prog in _RUNNERS:
            if prog in _SUB and (len(tokens) < 2 or tokens[1] != _SUB[prog]):
                continue
            spec, eco = _package(tokens, prog)
            if spec and not pinned(spec, eco):
                out.append(finding(rid, f"MCP server {s.name!r} runs {spec!r} through {prog} without an exact "
                                        "version: every start can fetch a different release",
                                   evidence=" ".join(tokens), layer=s.origin, path=s.path))
        elif prog == "docker" and "run" in tokens and not _docker_pinned(tokens):
            out.append(finding(rid, f"MCP server {s.name!r} runs a docker image without an @sha256 digest",
                               severity="low", evidence=" ".join(tokens), layer=s.origin, path=s.path))
    return result(rid, out)


# ---------------------------------------------------------------- MCP-003

def _literal_secret(key: str, value: object) -> str | None:
    if not isinstance(value, str) or not value.strip() or is_env_reference(value):
        return None
    label = find_secret(value)
    if label:
        return label
    if is_sensitive_key(key) and strip_references(value).strip() and \
            strip_references(value).strip().lower() not in ("bearer", "basic", "token"):
        return "literal value under a secret-like name"
    return None


@rule("MCP-003", settings=False)
def mcp_003(ctx: Context) -> RuleResult:
    rid = "MCP-003"
    if not ctx.mcp:
        return result(rid, [], status="na", note="no MCP servers")
    out = []
    for s in ctx.mcp:
        for field in ("env", "headers"):
            block = s.config.get(field)
            if not isinstance(block, dict):
                continue
            for k, v in block.items():
                label = _literal_secret(str(k), v)
                if label:
                    out.append(finding(rid, f"MCP server {s.name!r} has a literal secret in {field}.{k} ({label})",
                                       evidence=f"{k}={mask_value(str(v), key=str(k))}",
                                       layer=s.origin, path=s.path))
    return result(rid, out)


# ---------------------------------------------------------------- PLG


@rule("PLG-001")
def plg_001(ctx: Context) -> RuleResult:
    rid = "PLG-001"
    out = []
    lists = [ctx.eff.entry(k) for k in ("strictKnownMarketplaces", "allowedMarketplaces")]
    effective = [e for e in lists if e is not None and e.source and e.source.layer == "managed"
                 and isinstance(e.value, list)]
    if not effective:
        out.append(finding(rid, "no managed strictKnownMarketplaces: plugins can be installed from any marketplace"))
    elif all(e.value == [] for e in effective):
        out.append(finding(rid, "strictKnownMarketplaces is an empty list: every marketplace, including the "
                                "official one, is blocked", severity="info"))
    if ctx.eff.get("disableSideloadFlags") is not True:
        out.append(finding(rid, "disableSideloadFlags is not true: --plugin-dir and similar flags bypass the "
                                "marketplace allowlist", severity="low"))
    return result(rid, out)


_EXEC_COMPONENTS = ("hooks", "mcp", "lsp", "monitors", "mods", "bin")


@rule("PLG-002", settings=False)
def plg_002(ctx: Context) -> RuleResult:
    rid = "PLG-002"
    enabled = {pid for pid, on in enabled_plugins(ctx).items() if on}
    if not enabled:
        return result(rid, [], status="na", note="no enabled plugins")
    cached = {p.plugin_id: p for p in ctx.col.plugins}
    out = []
    for pid in sorted(enabled):
        p = cached.get(pid)
        if p is None:
            out.append(finding(rid, f"enabled plugin {pid!r} was not found in the plugin cache (not inspected)",
                               severity="info"))
            continue
        execs = [c for c in p.components if c in _EXEC_COMPONENTS]
        if execs:
            # TODO(verify): marketplace tier and autoUpdate source are not yet confirmed in docs
            out.append(finding(rid, f"enabled plugin {pid!r} ships executable components: {', '.join(execs)}",
                               evidence=f"versions in cache: {', '.join(p.versions) or '?'}",
                               layer=f"plugin:{pid}", path=p.path))
    return result(rid, out)
