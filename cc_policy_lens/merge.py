"""Effective configuration with provenance.

All layer-precedence knowledge lives here (SPEC §3) so a Claude Code change is a
one-file fix. Each rule below carries the doc it came from; anything not confirmed
in code.claude.com docs is marked ``TODO(verify)``.

Model
-----
* Each settings document is flattened to leaves keyed by a tuple path.
  Dicts recurse; scalars and lists are leaves.
* Scalars: the highest-precedence layer wins; lower ones are kept as ``shadowed``.
* Lists: every layer contributes; items are de-duplicated, keeping the first
  (highest-precedence) provenance.  SPEC §3 / settings docs ("array settings are merged").
* Values that Claude Code ignores in a given layer go to ``ignored`` with a reason
  and never reach the effective value.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from .model import LAYER_RANK, Collection, Entry, Provenance, SettingsDoc

Path = tuple[str, ...]

# Precedence, highest first. "cli" (--settings) is not readable from disk and is never present.
PRECEDENCE = ("managed", "cli", "local", "project", "user")

# Keys Claude Code reads only from a managed source. Source: managed-settings docs,
# "Keys only a managed source can set" table, plus settings-reference index Scope = Managed
# (checked 2026-11-09).
_MANAGED_ONLY_KEYS = (
    "allowAllClaudeAiMcps", "allowedChannelPlugins", "allowManagedHooksOnly", "allowManagedMcpServersOnly",
    "allowManagedPermissionRulesOnly", "blockedMarketplaces", "channelsEnabled", "disableCommandPluginSources",
    "disableSideloadFlags", "forceRemoteSettingsRefresh", "managedMcpServers", "managedSourcesBehavior",
    "parentSettingsBehavior", "pluginSuggestionMarketplaces", "pluginTrustMessage", "policyHelper",
    "sandbox.filesystem.allowManagedReadPathsOnly", "sandbox.network.allowManagedDomainsOnly",
    "strictKnownMarketplaces", "strictPluginOnlyCustomization", "wslInheritsWindowsSettings",
    "requiredMinimumVersion", "requiredMaximumVersion",
)
MANAGED_ONLY: dict[Path, str] = {tuple(k.split(".")): "managed-only key" for k in _MANAGED_ONLY_KEYS}
# TODO(verify): allowedMarketplaces is not in the settings index; treated as a managed-only
# alias of strictKnownMarketplaces (fail closed: no effect outside managed).
MANAGED_ONLY[("allowedMarketplaces",)] = "managed-only key (alias, unverified)"

# Expected value types for keys rules depend on. In user/project/local files Claude Code skips
# an entry that fails validation and keeps the rest of the file (settings docs, "Fix a broken
# settings file"), so a wrong type goes to ``ignored``. Managed values have their own fallbacks
# (``_managed_fallback``).
_STAR = "*"
KNOWN_TYPES: dict[Path, type | tuple[type, ...]] = {
    ("permissions", "allow"): list, ("permissions", "ask"): list, ("permissions", "deny"): list,
    ("permissions", "additionalDirectories"): list,
    ("permissions", "defaultMode"): str, ("permissions", "disableBypassPermissionsMode"): str,
    ("sandbox", "enabled"): bool, ("sandbox", "failIfUnavailable"): bool,
    ("sandbox", "allowUnsandboxedCommands"): bool,
    ("sandbox", "network", "allowManagedDomainsOnly"): bool,
    ("allowManagedHooksOnly",): bool, ("allowManagedPermissionRulesOnly",): bool,
    ("allowManagedMcpServersOnly",): bool, ("disableAllHooks",): bool, ("disableSideloadFlags",): bool,
    ("enableAllProjectMcpServers",): bool,
    ("enabledMcpjsonServers",): list, ("disabledMcpjsonServers",): list,
    ("allowedHttpHookUrls",): list, ("httpHookAllowedEnvVars",): list,
    ("strictKnownMarketplaces",): list, ("allowedMarketplaces",): list,
    ("requiredMinimumVersion",): str, ("minimumVersion",): str,
    ("hooks", _STAR): list, ("env", _STAR): str,
    ("enabledPlugins", _STAR): bool,
}
# Allowed string values (checked like types).
KNOWN_VALUES: dict[Path, frozenset[str]] = {
    ("permissions", "disableBypassPermissionsMode"): frozenset({"disable"}),
    # TODO(verify): full mode list; an unknown mode is treated as invalid.
    ("permissions", "defaultMode"): frozenset({"default", "acceptEdits", "plan", "auto", "dontAsk",
                                               "bypassPermissions"}),
}

# Managed fallbacks for values that are present but invalid (managed-settings docs,
# "Keys that fail closed" / "Invalid values inside sandbox", v2.1.282+ / v2.1.283+).
_DROP = object()
_RESTRICTIVE_TRUE = {("allowManagedHooksOnly",), ("allowManagedPermissionRulesOnly",),
                     ("allowManagedMcpServersOnly",), ("disableSideloadFlags",),
                     ("sandbox", "enabled"), ("sandbox", "network", "allowManagedDomainsOnly")}
_MANAGED_FALLBACK: dict[Path, Any] = {
    ("permissions", "disableBypassPermissionsMode"): "disable",
    ("permissions", "defaultMode"): "default",
    ("sandbox", "allowUnsandboxedCommands"): False,
    ("sandbox", "failIfUnavailable"): _DROP,        # never stops the fleet from starting
    ("disableAllHooks",): _DROP,
    ("requiredMinimumVersion",): _DROP,             # fails open by design
    ("requiredMaximumVersion",): _DROP,
    ("allowedHttpHookUrls",): [],                   # empty managed allowlist
    ("httpHookAllowedEnvVars",): [],
    ("strictKnownMarketplaces",): [],
    ("allowedMarketplaces",): [],
    ("permissions", "deny"): _DROP,                 # + withholds managed allow/additionalDirectories
    ("permissions", "ask"): _DROP,
}
_WITHHELD_WHEN_DENY_INVALID = (("permissions", "allow"), ("permissions", "additionalDirectories"))

# Managed sources this tool cannot read. Managed-settings docs: by default ("first-wins")
# Claude Code uses the highest-ranked source with a policy key — server-managed, then MDM
# (macOS plist / HKLM registry), then the managed files — and ignores the rest.
CAVEATS = (
    "server-managed settings and MDM policies (macOS plist, Windows HKLM registry) are not read; "
    "if one delivers a policy, Claude Code uses it instead of the managed files shown here (first-wins)",
    "--settings (cli layer) and environment variables are not visible to this tool",
)

# (path, values, layers, reason): a value Claude Code ignores when it comes from these layers.
IGNORED_VALUES: list[tuple[Path, frozenset[Any], frozenset[str], str]] = [
    (("permissions", "defaultMode"), frozenset({"bypassPermissions", "auto"}), frozenset({"project", "local"}),
     "ignored from project/local settings since v2.1.257"),
]

# TODO(verify): settings-reference "Variables Claude Code ignores in env" lists telemetry export
# variables ignored from project/local env (not yet transcribed). env is merged as-is.


@dataclass
class EffectiveConfig:
    entries: dict[Path, Entry] = field(default_factory=dict)
    layers_present: list[str] = field(default_factory=list)
    managed_parse_error: str | None = None     # Claude Code refuses to start (fail closed)
    managed_withheld: list[str] = field(default_factory=list)   # grants withheld by a managed fallback
    unreadable: list[tuple[str, str]] = field(default_factory=list)   # (layer, masked error)
    raw: dict[str, dict[str, Any]] = field(default_factory=dict)      # layer -> merged raw doc
    caveats: tuple[str, ...] = CAVEATS

    def get(self, dotted: str | Path, default: Any = None) -> Any:
        e = self.entry(dotted)
        return default if e is None else e.value

    def entry(self, dotted: str | Path) -> Entry | None:
        """Dotted strings are a convenience for fixed setting names only. Paths that include
        user-chosen names (MCP servers, env vars, plugin ids) must be passed as tuples."""
        path = tuple(dotted.split(".")) if isinstance(dotted, str) else dotted
        return self.entries.get(path)

    def subtree(self, prefix: str | Path) -> dict[Path, Entry]:
        p = tuple(prefix.split(".")) if isinstance(prefix, str) else prefix
        return {k: v for k, v in self.entries.items() if k[:len(p)] == p}

    def source_layer(self, dotted: str | Path) -> str | None:
        e = self.entry(dotted)
        return e.source.layer if e and e.source else None


# ---------------------------------------------------------------- helpers

def _flatten(obj: Any, prefix: Path = ()) -> Iterable[tuple[Path, Any]]:
    if isinstance(obj, dict) and prefix in KNOWN_TYPES:
        yield prefix, obj                        # an object where a scalar/list is expected: one leaf
    elif isinstance(obj, dict):
        for k, v in obj.items():                 # an empty dict yields nothing (deep-merge no-op)
            yield from _flatten(v, prefix + (str(k),))
    elif prefix:
        yield prefix, obj


def _key(item: Any) -> str:
    try:
        return json.dumps(item, sort_keys=True)
    except (TypeError, ValueError):
        return repr(item)


def _deep_merge(base: dict[str, Any], top: dict[str, Any]) -> dict[str, Any]:
    """Merge for managed drop-ins: later files win for scalars, lists concatenate."""
    out = dict(base)
    for k, v in top.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        elif isinstance(v, list) and isinstance(out.get(k), list):
            out[k] = out[k] + [x for x in v if _key(x) not in {_key(y) for y in out[k]}]
        else:
            out[k] = v
    return out


def _layer_docs(col: Collection) -> list[tuple[str, list[SettingsDoc]]]:
    """Documents per layer, highest precedence first. Managed = base file + drop-ins (alphabetical)."""
    out: list[tuple[str, list[SettingsDoc]]] = []
    for layer in PRECEDENCE:
        if layer == "managed":
            docs = [d for d in [col.settings.get("managed"), *col.managed_dropins] if d is not None]
        else:
            d = col.settings.get(layer)
            docs = [d] if d is not None else []
        out.append((layer, docs))
    return out


# ---------------------------------------------------------------- merge

def merge(col: Collection) -> EffectiveConfig:
    eff = EffectiveConfig()
    # leaves per layer: (path, value, provenance)
    per_layer: list[tuple[str, list[tuple[Path, Any, Provenance]]]] = []

    for layer, docs in _layer_docs(col):
        leaves: list[tuple[Path, Any, Provenance]] = []
        merged_raw: dict[str, Any] = {}
        for doc in docs:
            if doc.info.error:
                eff.unreadable.append((layer, doc.info.error))
                # Managed docs: unparsable or non-object -> refuses to start; an OS permission
                # denial -> starts without that source; other read failures (io) -> exits.
                # too_deep/too_large are this tool's limits, not Claude Code's.
                if layer == "managed" and doc.info.error_kind in ("parse", "not_object", "io"):
                    # managed settings docs: an unparsable managed file stops Claude Code from starting
                    eff.managed_parse_error = doc.info.error
                continue
            if doc.data is None:
                continue
            prov = Provenance(layer, doc.info.path)
            merged_raw = _deep_merge(merged_raw, doc.data)
            # Within managed, a later drop-in overrides an earlier file for the same scalar.
            leaves = [lf for lf in leaves if not _overridden_within_layer(lf, doc.data)]
            leaves.extend((p, v, prov) for p, v in _flatten(doc.data))
        if docs and any(d.data is not None for d in docs):
            eff.layers_present.append(layer)
            eff.raw[layer] = merged_raw
        per_layer.append((layer, leaves))

    higher_leaves: set[Path] = set()      # effective leaf paths from higher layers
    higher_prefixes: set[Path] = set()    # strict prefixes of those paths (objects)
    for layer, leaves in per_layer:
        layer_paths: list[Path] = []
        withhold = False
        if layer == "managed":
            withhold = any(p in (("permissions", "deny"), ("permissions", "ask")) and _type_error(p, v)
                           for p, v, _ in leaves)
        for path, value, prov in leaves:
            e = eff.entries.get(path)
            if e is None:
                e = eff.entries[path] = Entry(key=path, value=None, source=None)
            if layer == "managed":
                if value is None:
                    continue                           # managed docs: null removes the key
                if withhold and path in _WITHHELD_WHEN_DENY_INVALID:
                    e.ignored.append((value, prov, "withheld: managed deny/ask list is invalid"))
                    eff.managed_withheld.append(".".join(path))
                    continue
                value, note = _managed_fallback(path, value)
                if note:
                    e.ignored.append((value if value is not _DROP else None, prov, note))
                if value is _DROP:
                    continue
                reason = _ignore_reason(path, value, layer)
            else:
                reason = _ignore_reason(path, value, layer) or _type_error(path, value)
            if reason:
                e.ignored.append((value, prov, reason))
                continue
            # Deep merge replaces a whole object when a higher layer has a non-object at a
            # prefix (project {"sandbox": false} hides user {"sandbox": {"enabled": true}}),
            # and replaces a lower non-object when a higher layer has an object there.
            if any(path[:i] in higher_leaves for i in range(1, len(path))) or path in higher_prefixes:
                e.shadowed.append((value, prov))
                continue
            layer_paths.append(path)
            if isinstance(value, list):
                _merge_list(e, value, prov)
            elif e.source is None and e.items is None:
                e.value, e.source = value, prov          # first (highest) layer wins
            else:
                e.shadowed.append((value, prov))
        for path in layer_paths:
            higher_leaves.add(path)
            higher_prefixes.update(path[:i] for i in range(1, len(path)))
    # entries that only have ignored/shadowed values keep value=None and source=None
    return eff


def _managed_fallback(path: Path, value: Any) -> tuple[Any, str | None]:
    """Value Claude Code uses for a managed entry, and a note when it differs from the file."""
    if _type_error(path, value) is None:
        return value, None
    expected = KNOWN_TYPES.get(path)
    if expected is bool and isinstance(value, str) and value in ("true", "false") and path != ("disableAllHooks",):
        return value == "true", "quoted boolean in managed settings; read as a boolean"
    if path in _RESTRICTIVE_TRUE:
        return True, "invalid in managed settings; Claude Code treats it as true (fail closed)"
    if path in _MANAGED_FALLBACK:
        fb = _MANAGED_FALLBACK[path]
        if fb is _DROP:
            return _DROP, "invalid in managed settings; dropped"
        return fb, f"invalid in managed settings; Claude Code treats it as {fb!r} (fail closed)"
    return _DROP, "invalid in managed settings; dropped"


def _type_error(path: Path, value: Any) -> str | None:
    expected = KNOWN_TYPES.get(path)
    if expected is None and len(path) == 2:
        expected = KNOWN_TYPES.get((path[0], _STAR))
    if expected is None:
        return None
    # bool is a subclass of int; only accept real bools where bool is expected and vice versa
    ok = isinstance(value, expected) and not (expected is not bool and isinstance(value, bool))
    if ok:
        allowed = KNOWN_VALUES.get(path)
        if allowed is not None and value not in allowed:
            return f"invalid value {value!r}"
        return None
    name = expected.__name__ if isinstance(expected, type) else "/".join(t.__name__ for t in expected)
    return f"invalid type: expected {name}, got {type(value).__name__}"


def _overridden_within_layer(leaf: tuple[Path, Any, Provenance], newer: dict[str, Any]) -> bool:
    """True when a later managed file replaces this leaf (same rules as _deep_merge)."""
    path, value, _ = leaf
    cur: Any = newer
    for part in path:
        if not isinstance(cur, dict):
            return True                                # newer has a non-object at a prefix
        if part not in cur:
            return False
        cur = cur[part]
    if isinstance(cur, dict) and not cur:
        return False                                   # empty object merges as a no-op
    return not (isinstance(value, list) and isinstance(cur, list))   # lists concatenate


def _merge_list(e: Entry, value: list[Any], prov: Provenance) -> None:
    if e.items is None:
        if e.source is not None:                       # higher layer had a scalar here
            e.shadowed.append((value, prov))
            return
        e.items, e.source = [], prov
    seen = {_key(v) for v, _ in e.items}
    for item in value:
        k = _key(item)
        if k not in seen:
            e.items.append((item, prov))
            seen.add(k)
    e.value = [v for v, _ in e.items]


def _ignore_reason(path: Path, value: Any, layer: str) -> str | None:
    if path in MANAGED_ONLY and layer != "managed":
        return f"{MANAGED_ONLY[path]}: no effect in {layer} settings"
    for p, values, layers, reason in IGNORED_VALUES:
        if path == p and layer in layers and isinstance(value, str) and value in values:
            return reason
    return None


def layer_rank(layer: str) -> int:
    return LAYER_RANK.get(layer, -1)
