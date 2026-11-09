"""Rule engine: metadata in ``meta``, check logic in ``checks_*`` modules.

A check takes a ``Context`` and returns a ``RuleResult``:
  fail     one or more findings (message/evidence already masked)
  pass     checked, nothing found
  na       the rule does not apply (e.g. no project, no HTTP hooks)
  unknown  could not judge (unreadable input, unsupported platform)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from ..collect import collect_all
from ..mask import mask_value
from ..merge import EffectiveConfig, merge
from ..model import Collection, Finding, HookDef, McpServer, RuleResult
from ..paths import PathSet
from .meta import RULE_META, RULE_ORDER

# error kinds that leave this tool with an incomplete view (Claude Code may still read the file)
INCOMPLETE_KINDS = ("permission", "io", "outside", "too_large", "too_deep")


@dataclass
class Context:
    paths: PathSet
    col: Collection
    eff: EffectiveConfig
    hooks: list[HookDef] = field(default_factory=list)
    mcp: list[McpServer] = field(default_factory=list)

    def incomplete_layers(self) -> list[str]:
        out = []
        for doc in [*self.col.settings.values(), *self.col.managed_dropins]:
            if doc.info.error_kind in INCOMPLETE_KINDS:
                out.append(doc.layer)
        return out


Check = Callable[[Context], RuleResult]
REGISTRY: dict[str, Check] = {}
# rules whose pass verdict depends on the merged settings layers
DEPENDS_ON_SETTINGS: set[str] = set()


def rule(rule_id: str, *, settings: bool = True) -> Callable[[Check], Check]:
    if rule_id not in RULE_META:
        raise KeyError(f"unknown rule id {rule_id}")

    def deco(fn: Check) -> Check:
        REGISTRY[rule_id] = fn
        if settings:
            DEPENDS_ON_SETTINGS.add(rule_id)
        return fn
    return deco


def finding(rule_id: str, message: str, *, severity: str | None = None, evidence: str | None = None,
            layer: str | None = None, path: str | None = None) -> Finding:
    return Finding(rule_id=rule_id, severity=severity or RULE_META[rule_id]["severity"],
                   message=mask_value(message), evidence=mask_value(evidence) if evidence else None,
                   source_layer=layer, source_path=mask_value(path) if path else None)


def result(rule_id: str, findings: list[Finding], *, note: str | None = None, status: str | None = None) -> RuleResult:
    return RuleResult(rule_id=rule_id, status=status or ("fail" if findings else "pass"),
                      findings=findings, note=mask_value(note) if note else None)


def build_context(paths: PathSet) -> Context:
    from .inventory import collect_hooks, collect_mcp
    col = collect_all(paths)
    eff = merge(col)
    ctx = Context(paths=paths, col=col, eff=eff)
    ctx.hooks = collect_hooks(ctx)
    ctx.mcp = collect_mcp(ctx)
    return ctx


def run_rule(rule_id: str, ctx: Context) -> RuleResult:
    _load()
    try:
        res = REGISTRY[rule_id](ctx)
    except Exception as e:  # a broken rule must not hide the others; report as unknown
        from ..mask import safe_error
        return RuleResult(rule_id=rule_id, status="unknown", note=f"rule error: {safe_error(e)}")
    if res.status == "pass" and rule_id in DEPENDS_ON_SETTINGS:
        missing = ctx.incomplete_layers()
        if missing:
            res.status = "unknown"
            res.note = f"could not read all settings layers ({', '.join(sorted(set(missing)))}); " \
                       + (res.note or "no finding in the readable layers")
    return res


def run_all(ctx: Context, only: list[str] | None = None) -> list[RuleResult]:
    _load()
    return [run_rule(rid, ctx) for rid in RULE_ORDER if only is None or rid in only]


_loaded = False


def _load() -> None:
    global _loaded
    if not _loaded:
        from . import checks_cfg_perm, checks_hook, checks_mcp_plg, checks_misc  # noqa: F401  (registers)
        _loaded = True
        missing = set(RULE_ORDER) - set(REGISTRY)
        if missing:
            raise RuntimeError(f"rules without checks: {sorted(missing)}")
