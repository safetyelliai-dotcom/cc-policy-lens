"""CFG-*, PERM-*, SBX-* checks."""
from __future__ import annotations

import os
import re
import stat as stat_mod

from ..model import FileInfo, RuleResult
from . import Context, finding, result, rule

# ---------------------------------------------------------------- CFG


def _managed_files(ctx: Context) -> list[tuple[str, FileInfo]]:
    col = ctx.col
    items: list[tuple[str, FileInfo]] = []
    if col.managed_dir_info is not None and col.managed_dir_info.exists:
        items.append(("directory", col.managed_dir_info))
    for doc in [col.settings.get("managed"), *col.managed_dropins, col.managed_mcp]:
        if doc is not None and doc.info.exists:
            items.append(("file", doc.info))
    dropin_dir = os.path.join(col.managed_dir, "managed-settings.d")
    if os.path.isdir(dropin_dir):
        from ..collect import stat_file
        items.append(("directory", stat_file(dropin_dir)))
    return items


@rule("CFG-001", settings=False)
def cfg_001(ctx: Context) -> RuleResult:
    rid = "CFG-001"
    if ctx.col.platform == "win32":
        return result(rid, [], status="unknown", note="Windows ACLs cannot be checked with the standard library")
    items = _managed_files(ctx)
    if not items:
        return result(rid, [], status="na", note="no managed settings directory or files")
    out, unknown = [], []
    for kind, info in items:
        if info.mode is None or info.uid is None:
            unknown.append(info.path)
            continue
        problems = []
        if info.uid != ctx.paths.trusted_uid:
            problems.append(f"owner uid {info.uid} (expected {ctx.paths.trusted_uid})")
        if info.mode & 0o022:
            problems.append(f"mode {stat_mod.S_IMODE(info.mode):04o} is group/other-writable")
        if problems:
            out.append(finding(rid, f"managed {kind} can be modified by a non-admin user: " + "; ".join(problems),
                               evidence=f"{stat_mod.S_IMODE(info.mode):04o} uid={info.uid}"
                               + (f" symlink->{info.symlink_target}" if info.is_symlink else ""),
                               layer="managed", path=info.path))
    if not out and unknown:
        return result(rid, [], status="unknown", note="could not stat: " + ", ".join(unknown))
    return result(rid, out)


@rule("CFG-002", settings=False)
def cfg_002(ctx: Context) -> RuleResult:
    rid = "CFG-002"
    docs = [d for d in [ctx.col.settings.get("managed"), *ctx.col.managed_dropins] if d is not None and d.info.exists]
    if not docs:
        return result(rid, [], status="na", note="no managed settings file")
    out, unknown = [], []
    for d in docs:
        if d.info.error_kind in ("parse", "not_object"):
            out.append(finding(rid, "managed settings file is not a JSON object; Claude Code refuses to start",
                               evidence=d.info.error, layer="managed", path=d.info.path))
        elif d.info.error_kind == "io":
            out.append(finding(rid, "managed settings file cannot be read (I/O error); Claude Code exits at startup",
                               evidence=d.info.error, layer="managed", path=d.info.path))
        elif d.info.error_kind:
            unknown.append(f"{d.info.path}: {d.info.error}")
    if not out and unknown:
        return result(rid, [], status="unknown", note="; ".join(unknown))
    return result(rid, out)


# ---------------------------------------------------------------- PERM

def _bypass_locked(ctx: Context) -> bool:
    return ctx.eff.get("permissions.disableBypassPermissionsMode") == "disable"


@rule("PERM-001")
def perm_001(ctx: Context) -> RuleResult:
    rid = "PERM-001"
    e = ctx.eff.entry("permissions.defaultMode")
    out = []
    if e is not None:
        if e.value == "bypassPermissions" and e.source:
            if _bypass_locked(ctx):
                out.append(finding(rid, "defaultMode is bypassPermissions, but disableBypassPermissionsMode "
                                        "blocks it from taking effect", severity="low",
                                   evidence="bypassPermissions", layer=e.source.layer, path=e.source.path))
            else:
                out.append(finding(rid, "default permission mode is bypassPermissions: every tool call runs "
                                        "without a prompt", evidence="bypassPermissions",
                                   layer=e.source.layer, path=e.source.path))
        for value, prov, reason in e.ignored:
            if value == "bypassPermissions" and "v2.1.257" in reason:
                out.append(finding(rid, "project/local settings set defaultMode to bypassPermissions; ignored on "
                                        "Claude Code v2.1.257+, but applies on older versions", severity="info",
                                   evidence="bypassPermissions", layer=prov.layer, path=prov.path))
    note = None if out else f"defaultMode is {e.value!r}" if e is not None and e.value else "defaultMode not set (default)"
    return result(rid, out, note=note)


@rule("PERM-002")
def perm_002(ctx: Context) -> RuleResult:
    rid = "PERM-002"
    e = ctx.eff.entry("permissions.disableBypassPermissionsMode")
    if e is not None and e.value == "disable" and e.source:
        if e.source.layer == "managed":
            return result(rid, [], note="locked in managed settings")
        return result(rid, [finding(rid, f"bypass lock is set only in {e.source.layer} settings, which the user "
                                         "can remove", severity="low", evidence="disable",
                                    layer=e.source.layer, path=e.source.path)])
    return result(rid, [finding(rid, "permissions.disableBypassPermissionsMode is not \"disable\": bypassPermissions "
                                     "can be turned on with a flag or a subagent setting")])


# Read deny coverage -----------------------------------------------------------

_SENSITIVE_TARGETS = (
    ("~/.ssh", "~/.ssh/id_ed25519"),
    ("~/.aws", "~/.aws/credentials"),
    (".env", "./.env"),
    (".env.*", "./.env.local"),
    ("*.pem", "./certs/server.pem"),
)
_HOME, _PROJ = "/__home__", "/__project__"


def _glob_to_regex(pat: str) -> re.Pattern[str]:
    out, i = [], 0
    while i < len(pat):
        if pat.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pat.startswith("**", i):
            out.append(".*")
            i += 2
        elif pat[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pat[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pat[i]))
            i += 1
    # gitignore: a pattern also matches everything below a matched directory
    return re.compile("".join(out) + "(?:/.*)?")


def _anchor(spec: str) -> str:
    """Resolve a rule path to an absolute pattern (permissions docs: // root, ~/ home,
    / and ./ and bare = project / working directory)."""
    if spec.startswith("//"):
        return spec[1:]
    if spec.startswith("~/"):
        return _HOME + spec[1:]
    if spec == "~":
        return _HOME
    if spec.startswith("/"):
        return _PROJ + spec
    if spec.startswith("./"):
        return _PROJ + spec[1:]
    return _PROJ + "/" + spec


def _sample(path: str) -> str:
    if path.startswith("~/"):
        return _HOME + path[1:]
    return _PROJ + path[1:]


_RULE = re.compile(r"^\s*([A-Za-z]+)\s*(?:\((.*)\))?\s*$", re.S)


def read_rule_covers(rule_text: str, sample: str) -> bool:
    m = _RULE.match(rule_text or "")
    if not m or m.group(1) != "Read":
        return False
    spec = (m.group(2) or "").strip()
    if spec == "":
        return True                              # bare "Read" denies every read
    if len(spec) > 1 and spec.endswith("/"):
        spec = spec.rstrip("/") or "/"           # gitignore: "dir/" matches the directory and its contents
    return bool(_glob_to_regex(_anchor(spec)).fullmatch(_sample(sample)))


@rule("PERM-003")
def perm_003(ctx: Context) -> RuleResult:
    rid = "PERM-003"
    deny = ctx.eff.get("permissions.deny") or []
    deny = [d for d in deny if isinstance(d, str)]
    out = []
    for label, sample in _SENSITIVE_TARGETS:
        if not any(read_rule_covers(r, sample) for r in deny):
            out.append(finding(rid, f"no Read deny rule covers {label}", evidence=f"sample path {sample}"))
    return result(rid, out, note=f"{len(deny)} deny rules checked")


def _bash_spec(rule_text: str) -> str | None:
    m = _RULE.match(rule_text or "")
    if not m or m.group(1) != "Bash":
        return None
    return (m.group(2) or "").strip()


_ALL_COMMANDS = {"", "*", "**", ":*", "*:*"}


@rule("PERM-004")
def perm_004(ctx: Context) -> RuleResult:
    rid = "PERM-004"
    e = ctx.eff.entry("permissions.allow")
    out = []
    for item, prov in (e.items or []) if e else []:
        spec = _bash_spec(item) if isinstance(item, str) else None
        if spec is not None and spec in _ALL_COMMANDS:
            out.append(finding(rid, "allow rule matches every Bash command", evidence=item,
                               layer=prov.layer, path=prov.path))
    return result(rid, out)


_NET_TOOLS = {"curl", "wget", "nc", "ncat", "socat"}


@rule("PERM-005")
def perm_005(ctx: Context) -> RuleResult:
    rid = "PERM-005"
    e = ctx.eff.entry("permissions.allow")
    out = []
    for item, prov in (e.items or []) if e else []:
        spec = _bash_spec(item) if isinstance(item, str) else None
        if not spec:
            continue
        prog = re.split(r"[\s:]", spec, maxsplit=1)[0]
        if os.path.basename(prog) in _NET_TOOLS:
            out.append(finding(rid, f"allow rule lets Claude run the network tool {os.path.basename(prog)!r} "
                                    "without a prompt", evidence=item, layer=prov.layer, path=prov.path))
    return result(rid, out)


@rule("PERM-006")
def perm_006(ctx: Context) -> RuleResult:
    rid = "PERM-006"
    doc = ctx.col.settings.get("project")
    if doc is None:
        return result(rid, [], status="na", note="no project")
    if doc.info.error_kind in ("permission", "io", "outside", "too_large", "too_deep"):
        return result(rid, [], status="unknown", note=f"project settings not readable: {doc.info.error}")
    perms = (doc.data or {}).get("permissions")
    out = []
    if isinstance(perms, dict):
        for key in ("allow", "additionalDirectories"):
            items = perms.get(key)
            if isinstance(items, list):
                for it in items:
                    out.append(finding(rid, f"shared project settings add permissions.{key} (applies to everyone "
                                            "who clones and trusts the repo)", evidence=str(it),
                                       layer="project", path=doc.info.path))
    note = ("whether .claude/settings.local.json is tracked by git is not checked (.git is not read); "
            "a tracked local file needs workspace trust like the shared file")
    return result(rid, out, note=note)


# ---------------------------------------------------------------- SBX

@rule("SBX-001")
def sbx_001(ctx: Context) -> RuleResult:
    rid = "SBX-001"
    if ctx.col.platform == "win32":
        return result(rid, [finding(rid, "native Windows does not support the Bash sandbox (use WSL2)",
                                    severity="info")])
    eff = ctx.eff
    enabled = eff.entry("sandbox.enabled")
    if eff.get("sandbox.enabled") is not True:
        src = enabled.source if enabled else None
        return result(rid, [finding(rid, "Bash sandbox is not enabled (sandbox.enabled defaults to false)",
                                    evidence=repr(eff.get("sandbox.enabled")),
                                    layer=src.layer if src else None, path=src.path if src else None)])
    out = []
    if eff.get("sandbox.failIfUnavailable") is not True:
        out.append(finding(rid, "sandbox.failIfUnavailable is not true: if the sandbox cannot start, commands "
                                "run unsandboxed", severity="medium"))
    if eff.get("sandbox.allowUnsandboxedCommands") is not False:
        out.append(finding(rid, "sandbox.allowUnsandboxedCommands is not false: a blocked command can be retried "
                                "outside the sandbox", severity="low"))
    return result(rid, out, note=f"enabled in {enabled.source.layer} settings" if enabled and enabled.source else None)
