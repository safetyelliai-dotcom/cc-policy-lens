"""Read every settings source (read-only). Paths come from an injected PathSet.

Never writes. Never follows a path that a setting value names. Project-scope files
(and plugin cache files) must resolve inside their root: a repo cannot point
``.mcp.json`` at ``~/.claude.json`` and have it read.
"""
from __future__ import annotations

import json
import os
import stat as stat_mod
from typing import Any

from .mask import mask_value, safe_error
from .model import Collection, FileInfo, MarkdownDef, PluginInfo, SettingsDoc
from .paths import PathSet

MAX_BYTES = 5 * 1024 * 1024
MAX_STATE_BYTES = 32 * 1024 * 1024       # ~/.claude.json can be large; only a subset is kept
MAX_PLUGIN_DOC_BYTES = 1024 * 1024
MAX_DEPTH = 64
MAX_DIR_ENTRIES = 500
MAX_PLUGINS = 200
MAX_MD_BYTES = 256 * 1024
MAX_SCRIPT_BYTES = 256 * 1024
MAX_INT_DIGITS = 4000

_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)


# ---------------------------------------------------------------- file basics

def inside(path: str, root_real: str) -> bool:
    """True when ``path`` resolves (following symlinks) to ``root_real`` or below it."""
    p = os.path.realpath(path)
    return p == root_real or p.startswith(root_real.rstrip(os.sep) + os.sep)


def stat_file(path: str, confine: str | None = None) -> FileInfo:
    info = FileInfo(path=path)
    try:
        lst = os.lstat(path)
    except FileNotFoundError:
        return info
    except PermissionError as e:
        info.exists = True
        info.error, info.error_kind = safe_error(e), "permission"
        return info
    except OSError as e:
        info.error, info.error_kind = safe_error(e), "io"
        return info
    info.exists = True
    st = lst
    if stat_mod.S_ISLNK(lst.st_mode):
        info.is_symlink = True
        try:
            info.symlink_target = mask_value(os.readlink(path))
            st = os.stat(path)
        except FileNotFoundError:
            info.error, info.error_kind = "broken symlink", "io"
            return info
        except OSError as e:
            info.error, info.error_kind = safe_error(e), "io"
            return info
    if confine is not None and not inside(path, confine):
        info.error, info.error_kind = "resolves outside its root (symlink); not read", "outside"
        return info
    info.size, info.mode, info.uid = st.st_size, st.st_mode, getattr(st, "st_uid", None)
    info.dev, info.ino = st.st_dev, st.st_ino
    return info


def _depth_ok(obj: Any, limit: int) -> bool:
    stack = [(obj, 1)]
    while stack:
        cur, d = stack.pop()
        if d > limit:
            return False
        if isinstance(cur, dict):
            stack.extend((v, d + 1) for v in cur.values())
        elif isinstance(cur, list):
            stack.extend((v, d + 1) for v in cur)
    return True


def read_bytes_limited(info: FileInfo, limit: int) -> bytes | None:
    """Read a regular file up to ``limit`` bytes; records errors in ``info``.

    Opens non-blocking and re-checks type/size on the open descriptor, so a file
    swapped for a FIFO or device after ``stat_file`` cannot hang or flood the read.
    """
    if not info.exists or info.error:
        return None
    if info.mode is not None and not stat_mod.S_ISREG(info.mode):
        info.error, info.error_kind = "not a regular file", "io"
        return None
    if info.size is not None and info.size > limit:
        info.error, info.error_kind = f"file too large ({info.size} bytes > {limit})", "too_large"
        return None
    fd: int | None = None
    try:
        fd = os.open(info.path, _OPEN_FLAGS)
        st = os.fstat(fd)
        if info.ino is not None and (st.st_dev, st.st_ino) != (info.dev, info.ino):
            # swapped between the confinement check and open (TOCTOU): don't trust it
            info.error, info.error_kind = "file changed during scan; not read", "io"
            return None
        if not stat_mod.S_ISREG(st.st_mode):
            info.error, info.error_kind = "not a regular file", "io"
            return None
        if st.st_size > limit:
            info.error, info.error_kind = f"file too large ({st.st_size} bytes > {limit})", "too_large"
            return None
        with os.fdopen(fd, "rb") as fh:
            fd = None
            raw = fh.read(limit + 1)
    except PermissionError as e:
        info.error, info.error_kind = safe_error(e), "permission"
        return None
    except OSError as e:
        info.error, info.error_kind = safe_error(e), "io"
        return None
    finally:
        if fd is not None:
            os.close(fd)
    if len(raw) > limit:
        info.error, info.error_kind = f"file too large (> {limit} bytes)", "too_large"
        return None
    info.readable = True
    return raw


def _reject_constant(name: str) -> Any:
    raise ValueError("non-standard JSON constant")   # NaN/Infinity: JSON.parse rejects these


def _parse_int(s: str) -> int:
    if len(s) > MAX_INT_DIGITS:
        raise ValueError("integer literal too long")
    return int(s)


def read_json(path: str, layer: str, *, limit: int = MAX_BYTES, empty_ok: bool = True,
              confine: str | None = None) -> SettingsDoc:
    info = stat_file(path, confine)
    doc = SettingsDoc(layer=layer, info=info)
    raw = read_bytes_limited(info, limit)
    if raw is None:
        return doc
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        info.error, info.error_kind = "not valid UTF-8", "parse"
        return doc
    if not text.strip():
        if empty_ok:
            doc.data = {}
        else:
            info.error, info.error_kind = "empty file", "parse"
        return doc
    try:
        data = json.loads(text, parse_int=_parse_int, parse_constant=_reject_constant)
    except RecursionError:
        info.error, info.error_kind = "JSON nested too deeply", "too_deep"
        return doc
    except json.JSONDecodeError as e:
        # position only; the message itself can quote file content
        info.error, info.error_kind = f"invalid JSON at line {e.lineno} column {e.colno}", "parse"
        return doc
    except ValueError:
        # integer over the digit limit, NaN/Infinity: fixed message, never the content
        info.error, info.error_kind = "invalid JSON value (overlong number or NaN/Infinity)", "parse"
        return doc
    if not isinstance(data, dict):
        info.error, info.error_kind = f"top level is {type(data).__name__}, not an object", "not_object"
        return doc
    if not _depth_ok(data, MAX_DEPTH):
        info.error, info.error_kind = f"JSON nested deeper than {MAX_DEPTH}", "too_deep"
        return doc
    doc.data = data
    return doc


def read_text_limited(path: str, limit: int = MAX_SCRIPT_BYTES, confine: str | None = None) -> str | None:
    info = stat_file(path, confine)
    raw = read_bytes_limited(info, limit)
    if raw is None:
        return None
    return raw.decode("utf-8", errors="replace")


def list_dir(path: str | None, *, suffix: str | None = None, dirs: bool = False,
             confine: str | None = None, limit: int = MAX_DIR_ENTRIES,
             errors: list[str] | None = None) -> list[str]:
    """Up to ``limit`` entries (sorted). With ``confine``, entries resolving outside it are skipped.

    When the limit is hit, a message goes to ``errors`` (the subset read is arbitrary)."""
    if not path:
        return []
    if confine is not None and os.path.lexists(path) and not inside(path, confine):
        return []
    names: list[str] = []
    try:
        with os.scandir(path) as it:
            for de in it:
                if len(names) >= limit:
                    if errors is not None:
                        errors.append(f"{mask_value(path)}: more than {limit} entries; only {limit} inspected")
                    break
                names.append(de.name)
    except OSError:
        return []
    out = []
    for n in sorted(names):
        p = os.path.join(path, n)
        if confine is not None and not inside(p, confine):
            continue
        if dirs:
            if os.path.isdir(p):
                out.append(p)
        elif (suffix is None or n.endswith(suffix)) and os.path.isfile(p):
            out.append(p)
    return out


# ---------------------------------------------------------------- frontmatter

def _fm_value(val: str) -> str:
    val = val.strip()
    if val[:1] in ("'", '"'):
        end = val.find(val[0], 1)
        if end != -1:
            return val[1:end]                         # anything after the closing quote is a comment
    # unquoted YAML scalar: " #" starts a comment
    hash_at = val.find(" #")
    if hash_at != -1:
        val = val[:hash_at].rstrip()
    return val


def parse_frontmatter(text: str) -> tuple[dict[str, Any], dict[str, str]]:
    """Minimal YAML frontmatter reader (stdlib only, no code execution).

    Returns (scalars, blocks): top-level ``key: value`` scalars and inline lists,
    and nested blocks kept as raw text. Anything more complex is left as raw text.
    """
    lines = text.lstrip("﻿").splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, {}
    body: list[str] = []
    for ln in lines[1:]:
        if ln.strip() == "---":
            break
        body.append(ln)
    scalars: dict[str, Any] = {}
    blocks: dict[str, str] = {}
    cur: str | None = None
    for ln in body:
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        if ln[0] not in " \t-" and ":" in ln:
            key, _, val = ln.partition(":")
            key = key.strip().strip("'\"")
            val = _fm_value(val)
            cur = None
            if val in ("", "|", ">", "|-", ">-"):
                cur = key
                blocks[key] = ""
                scalars[key] = None
            elif val.startswith("[") and val.endswith("]"):
                scalars[key] = [x.strip().strip("'\"") for x in val[1:-1].split(",") if x.strip()]
            else:
                scalars[key] = val
        elif cur is not None:
            blocks[cur] += ln + "\n"
    return scalars, blocks


def read_markdown_def(path: str, kind: str, scope: str, confine: str | None = None) -> MarkdownDef:
    info = stat_file(path, confine)
    raw = read_bytes_limited(info, MAX_MD_BYTES)
    if raw is None:
        return MarkdownDef(kind, scope, path, {}, {}, error=info.error or "unreadable")
    fm, blocks = parse_frontmatter(raw.decode("utf-8", errors="replace"))
    return MarkdownDef(kind, scope, path, fm, blocks)


# ---------------------------------------------------------------- ~/.claude.json

STATE_PROJECT_KEYS = ("mcpServers", "enabledMcpjsonServers", "disabledMcpjsonServers", "hasTrustDialogAccepted")


def extract_user_state(doc: SettingsDoc, project: str | None) -> SettingsDoc:
    """Keep only MCP-related keys. Account details, OAuth data etc. are dropped here."""
    if doc.data is None:
        return doc
    keep: dict[str, Any] = {}
    if isinstance(doc.data.get("mcpServers"), dict):
        keep["mcpServers"] = doc.data["mcpServers"]
    projects = doc.data.get("projects")
    if project and isinstance(projects, dict):
        entry = projects.get(project) or projects.get(os.path.realpath(project))
        if isinstance(entry, dict):
            keep["project"] = {k: entry[k] for k in STATE_PROJECT_KEYS if k in entry}
    doc.data = keep
    return doc


# ---------------------------------------------------------------- plugins

PLUGIN_COMPONENTS = {
    # name in report -> relative path inside plugin dir   (layout per plugins docs; verified=false)
    "hooks": "hooks/hooks.json",
    "mcp": ".mcp.json",
    "lsp": ".lsp.json",
    "bin": "bin",
    "agents": "agents",
    "skills": "skills",
    "commands": "commands",
    "monitors": "monitors",
    "mods": "mods",
    "workflows": "workflows",
}


def collect_plugins(plugins_dir: str, errors: list[str] | None = None) -> list[PluginInfo]:
    # TODO(verify): the active version is recorded by Claude Code (installed plugins state);
    # until that is confirmed we inspect the newest copy and list every cached version.
    """Find installed plugin copies under ~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/.

    Bounded: at most MAX_PLUGINS plugins, small per-directory listings, 1 MB per JSON doc,
    and every read must resolve inside the plugin cache.
    """
    errors = errors if errors is not None else []
    out: list[PluginInfo] = []
    cache = os.path.join(plugins_dir, "cache")
    if not os.path.isdir(cache):
        return out
    root = os.path.realpath(cache)
    for mdir in list_dir(cache, dirs=True, confine=root, limit=100, errors=errors):
        for pdir in list_dir(mdir, dirs=True, confine=root, limit=100, errors=errors):
            if len(out) >= MAX_PLUGINS:
                errors.append(f"plugins: more than {MAX_PLUGINS} plugins; the rest were not inspected")
                return out
            versions = list_dir(pdir, dirs=True, confine=root, limit=20, errors=errors)
            if not versions:
                continue
            try:
                versions.sort(key=lambda p: os.stat(p).st_mtime, reverse=True)
            except OSError:
                continue
            vdir = versions[0]
            pid = f"{os.path.basename(pdir)}@{os.path.basename(mdir)}"
            info = PluginInfo(plugin_id=pid, enabled=False, path=vdir,
                              versions=[os.path.basename(v) for v in versions])
            for comp, rel in PLUGIN_COMPONENTS.items():
                if os.path.exists(os.path.join(vdir, rel)):
                    info.components.append(comp)

            def doc(rel: str) -> SettingsDoc:
                d = read_json(os.path.join(vdir, rel), "plugin", limit=MAX_PLUGIN_DOC_BYTES, confine=root)
                if d.info.error:
                    errors.append(f"plugin {pid}: {rel}: {d.info.error}")
                return d

            m = doc(os.path.join(".claude-plugin", "plugin.json")).data or {}
            m_hooks = m.get("hooks") if isinstance(m.get("hooks"), dict) else None
            m_mcp = m.get("mcpServers") if isinstance(m.get("mcpServers"), dict) else None
            if "hooks" in info.components or m_hooks is not None:
                hd = doc(os.path.join("hooks", "hooks.json")) if "hooks" in info.components else None
                info.hooks_doc = (hd.data if hd is not None and hd.data is not None
                                  else ({"hooks": m_hooks} if m_hooks is not None else {}))
                if "hooks" not in info.components:
                    info.components.append("hooks")
            if "mcp" in info.components or m_mcp is not None:
                md = doc(".mcp.json") if "mcp" in info.components else None
                info.mcp_doc = (md.data if md is not None and md.data is not None
                                else ({"mcpServers": m_mcp} if m_mcp is not None else {}))
                if "mcp" not in info.components:
                    info.components.append("mcp")
            out.append(info)
    return out


# ---------------------------------------------------------------- entry point

def collect_all(paths: PathSet) -> Collection:
    col = Collection(platform=paths.platform, home=paths.home, project=paths.project, managed_dir=paths.managed_dir)
    proj_root = os.path.realpath(paths.project) if paths.project else None

    col.settings["user"] = read_json(paths.user_settings, "user")
    if paths.project_settings:
        col.settings["project"] = read_json(paths.project_settings, "project", confine=proj_root)
    if paths.local_settings:
        col.settings["local"] = read_json(paths.local_settings, "local", confine=proj_root)

    # managed: base file + drop-ins (alphabetical) + MCP file
    col.managed_dir_info = stat_file(paths.managed_dir)
    col.settings["managed"] = read_json(paths.managed_settings, "managed")
    for p in list_dir(paths.managed_dropins, suffix=".json", errors=col.errors):
        col.managed_dropins.append(read_json(p, "managed"))
    col.managed_mcp = read_json(paths.managed_mcp, "managed_mcp")

    if paths.project_mcp:
        col.project_mcp = read_json(paths.project_mcp, "project_mcp", confine=proj_root)
    col.user_state = extract_user_state(read_json(paths.user_state, "user_state", limit=MAX_STATE_BYTES),
                                        paths.project)

    for d, scope, conf in ((paths.user_agents, "user", None), (paths.project_agents, "project", proj_root)):
        for p in list_dir(d, suffix=".md", confine=conf):
            col.agents.append(read_markdown_def(p, "agent", scope, conf))
    for d, scope, conf in ((paths.user_skills, "user", None), (paths.project_skills, "project", proj_root)):
        for sdir in list_dir(d, dirs=True, confine=conf):
            sk = os.path.join(sdir, "SKILL.md")
            if os.path.isfile(sk):
                col.skills.append(read_markdown_def(sk, "skill", scope, conf))
    col.workflows.extend(list_dir(paths.project_workflows, suffix=".js", confine=proj_root))
    col.workflows.extend(list_dir(paths.user_workflows, suffix=".js"))

    plugin_errors: list[str] = []
    col.plugins = collect_plugins(paths.plugins_dir, plugin_errors)

    for doc in [*col.settings.values(), *col.managed_dropins, col.managed_mcp, col.project_mcp, col.user_state]:
        if doc is not None and doc.info.error:
            col.errors.append(f"{doc.layer}: {mask_value(doc.info.path)}: {doc.info.error}")
    for md in [*col.agents, *col.skills]:
        if md.error:
            col.errors.append(f"{md.kind}: {mask_value(md.path)}: {md.error}")
    col.errors.extend(mask_value(e) for e in plugin_errors)
    return col
