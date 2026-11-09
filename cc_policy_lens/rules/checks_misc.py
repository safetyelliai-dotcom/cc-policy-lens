"""WF-001, AGT-001, ENV-001, VER-001."""
from __future__ import annotations

import os
import re

from ..collect import read_text_limited
from ..mask import find_secret, is_env_reference, is_sensitive_key, mask_value
from ..model import RuleResult
from . import Context, finding, result, rule

_META_FIELD = re.compile(r"""\b(name|description)\s*:\s*(['"`])((?:\\.|(?!\2).){0,200})\2""")


def workflow_meta(text: str) -> dict[str, str]:
    """Static read of ``export const meta = {...}``: name/description string literals only."""
    m = re.search(r"export\s+const\s+meta\s*=\s*\{", text)
    if not m:
        return {}
    body = text[m.end():m.end() + 4000]
    depth, end = 1, len(body)
    for i, ch in enumerate(body):
        depth += ch == "{"
        depth -= ch == "}"
        if depth == 0:
            end = i
            break
    return {f.group(1): f.group(3) for f in _META_FIELD.finditer(body[:end])}


@rule("WF-001", settings=False)
def wf_001(ctx: Context) -> RuleResult:
    rid = "WF-001"
    if not ctx.col.workflows:
        return result(rid, [], status="na", note="no workflow scripts")
    project = ctx.col.project
    proj_root = os.path.realpath(project) if project else None
    by_name: dict[str, list[str]] = {}
    out = []
    for path in ctx.col.workflows:
        scope = "project" if proj_root and os.path.realpath(path).startswith(proj_root + os.sep) else "user"
        text = read_text_limited(path, confine=proj_root if scope == "project" else None) or ""
        meta = workflow_meta(text)
        name = meta.get("name") or os.path.splitext(os.path.basename(path))[0]
        by_name.setdefault(name, []).append(scope)
        if scope == "project":
            out.append(finding(rid, f"repository ships workflow script {name!r}",
                               evidence=meta.get("description") or "(no description)", layer="project", path=path))
    for name, scopes in by_name.items():
        if "project" in scopes and "user" in scopes:
            out.append(finding(rid, f"workflow {name!r} exists in both project and user scope; the project "
                                    "version takes precedence", severity="info"))
    return result(rid, out, note=f"{len(ctx.col.workflows)} workflow file(s) listed")


@rule("AGT-001", settings=False)
def agt_001(ctx: Context) -> RuleResult:
    rid = "AGT-001"
    if not ctx.col.agents:
        return result(rid, [], status="na", note="no subagent definitions")
    out = []
    for a in ctx.col.agents:
        fm = a.frontmatter
        extra = []
        if fm.get("permissionMode") == "bypassPermissions":
            extra.append("permissionMode: bypassPermissions")
        if "mcpServers" in fm:
            extra.append("inline mcpServers")
        name = fm.get("name") or os.path.basename(a.path)
        if "hooks" in fm:
            out.append(finding(rid, f"subagent {name!r} ({a.scope}) defines hooks"
                                    + (f" and {', '.join(extra)}" if extra else ""),
                               evidence=(a.blocks.get("hooks") or "").strip()[:300], layer=f"agent:{a.scope}",
                               path=a.path))
        elif extra:
            out.append(finding(rid, f"subagent {name!r} ({a.scope}) sets {', '.join(extra)}", severity="low",
                               evidence=", ".join(extra), layer=f"agent:{a.scope}", path=a.path))
    return result(rid, out)


@rule("ENV-001")
def env_001(ctx: Context) -> RuleResult:
    rid = "ENV-001"
    docs = [d for d in [*ctx.col.settings.values(), *ctx.col.managed_dropins] if d.data]
    out = []
    for d in docs:
        env = d.data.get("env")
        if not isinstance(env, dict):
            continue
        for k, v in env.items():
            if not isinstance(v, str) or not v.strip() or is_env_reference(v):
                continue
            label = find_secret(v)
            if label:
                out.append(finding(rid, f"env.{k} holds a literal secret ({label})",
                                   evidence=f"{k}={mask_value(v, key=str(k))}", layer=d.layer, path=d.info.path))
            elif is_sensitive_key(str(k)):
                out.append(finding(rid, f"env.{k} has a secret-like name and a literal value", severity="medium",
                                   evidence=f"{k}={mask_value(v, key=str(k))}", layer=d.layer, path=d.info.path))
    return result(rid, out)


_VERSION = re.compile(r"^\d+\.\d+\.\d+$")


@rule("VER-001")
def ver_001(ctx: Context) -> RuleResult:
    rid = "VER-001"
    e = ctx.eff.entry("requiredMinimumVersion")
    if e is not None and e.source and e.source.layer == "managed" and isinstance(e.value, str) \
            and _VERSION.match(e.value):
        return result(rid, [], note=f"requires Claude Code {e.value} or later")
    notes = []
    if e is not None:
        notes += [f"{p.layer}: {reason}" for _, p, reason in e.ignored]
        if e.value is not None and not _VERSION.match(str(e.value)):
            notes.append(f"invalid version {e.value!r} (ignored; fails open)")
    mv = ctx.eff.get("minimumVersion")
    if mv:
        notes.append(f"minimumVersion {mv} only limits auto-updates; it does not block older versions from starting")
    return result(rid, [finding(rid, "no managed requiredMinimumVersion: old Claude Code versions can still start",
                                evidence="; ".join(notes) or None)])
