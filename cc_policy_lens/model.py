"""Data model shared by collect, merge, rules and report."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Settings layers, lowest precedence first. "cli" (--settings) can't be read from disk.
LAYER_ORDER = ("user", "project", "local", "cli", "managed")
LAYER_RANK = {name: i for i, name in enumerate(LAYER_ORDER)}

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class FileInfo:
    """What we learned about one file without trusting its content."""
    path: str
    exists: bool = False
    readable: bool = False
    is_symlink: bool = False
    symlink_target: str | None = None
    size: int | None = None
    dev: int | None = None
    ino: int | None = None
    mode: int | None = None
    uid: int | None = None
    error: str | None = None          # masked, human readable
    error_kind: str | None = None     # "permission" | "too_large" | "parse" | "not_object" | "too_deep" | "io"


@dataclass
class SettingsDoc:
    """One parsed settings-like JSON document."""
    layer: str                        # user | project | local | managed | user_state | project_mcp | managed_mcp | plugin
    info: FileInfo
    data: dict[str, Any] | None = None


@dataclass
class HookDef:
    event: str
    type: str
    command: str = ""                 # command + args, joined for display/pattern checks
    url: str | None = None
    headers: dict[str, Any] = field(default_factory=dict)
    on_failure: str | None = None
    is_async: bool = False
    origin: str = ""                  # user | project | local | managed | plugin:<id> | skill:<scope> | agent:<scope>
    path: str = ""                    # file that defines it
    matcher: str | None = None
    raw_text: str = ""                # for frontmatter hooks: raw YAML block


@dataclass
class McpServer:
    name: str
    origin: str                       # project_mcp | user_state | local_state | plugin:<id> | managed_mcp
    path: str
    config: dict[str, Any]


@dataclass
class MarkdownDef:
    """Subagent / skill definition: only frontmatter is parsed."""
    kind: str                         # agent | skill
    scope: str                        # user | project
    path: str
    frontmatter: dict[str, Any]
    blocks: dict[str, str]            # nested YAML blocks kept as raw text, e.g. {"hooks": "..."}
    error: str | None = None


@dataclass
class PluginInfo:
    plugin_id: str                    # name@marketplace
    enabled: bool
    path: str | None
    components: list[str] = field(default_factory=list)   # hooks, mcp, bin, monitors, mods, agents, skills
    versions: list[str] = field(default_factory=list)     # all cached version dirs (newest first)
    hooks_doc: dict[str, Any] | None = None
    mcp_doc: dict[str, Any] | None = None


@dataclass
class Collection:
    platform: str
    home: str
    project: str | None
    managed_dir: str
    settings: dict[str, SettingsDoc] = field(default_factory=dict)       # user/project/local/managed
    managed_dropins: list[SettingsDoc] = field(default_factory=list)
    managed_dir_info: FileInfo | None = None
    project_mcp: SettingsDoc | None = None
    managed_mcp: SettingsDoc | None = None
    user_state: SettingsDoc | None = None        # extracted subset of ~/.claude.json
    agents: list[MarkdownDef] = field(default_factory=list)
    skills: list[MarkdownDef] = field(default_factory=list)
    workflows: list[str] = field(default_factory=list)
    plugins: list[PluginInfo] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class Provenance:
    layer: str
    path: str


@dataclass
class Entry:
    """Effective value of one leaf key with its origin. ``key`` is the tuple path (unmasked:
    pass through mask before display, since names can be user-chosen)."""
    key: tuple[str, ...]
    value: Any
    source: Provenance | None
    shadowed: list[tuple[Any, Provenance]] = field(default_factory=list)
    items: list[tuple[Any, Provenance]] | None = None      # for merged lists
    ignored: list[tuple[Any, Provenance, str]] = field(default_factory=list)  # (value, where, reason)


@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str                      # language-neutral, already masked
    evidence: str | None = None       # masked setting value / location detail
    source_layer: str | None = None
    source_path: str | None = None


@dataclass
class RuleResult:
    rule_id: str
    status: str                       # fail | pass | na | unknown
    findings: list[Finding] = field(default_factory=list)
    note: str | None = None           # language-neutral evidence for pass/na/unknown

    @property
    def severity(self) -> str | None:
        if not self.findings:
            return None
        return min((f.severity for f in self.findings), key=lambda s: SEV_RANK[s])
