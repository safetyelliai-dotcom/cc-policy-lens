"""Test helpers: build fake home / project / managed trees in a temp dir.

Nothing here touches the real home directory. Fake secrets must be assembled at
runtime by the caller (CLAUDE.md rule 2).
"""
from __future__ import annotations

import json
import os
import tempfile
from typing import Any

from cc_policy_lens.paths import PathSet

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


class FakeEnv:
    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="ccpl-test-")
        self.root = os.path.realpath(self._tmp.name)
        self.home = os.path.join(self.root, "home")
        self.project = os.path.join(self.root, "project")
        self.managed = os.path.join(self.root, "managed")
        for d in (self.home, self.project):
            os.makedirs(d)

    def cleanup(self) -> None:
        # restore permissions changed by tests so cleanup can succeed
        for dirpath, dirnames, filenames in os.walk(self.root):
            for n in dirnames + filenames:
                p = os.path.join(dirpath, n)
                if not os.path.islink(p):
                    try:
                        os.chmod(p, 0o700)
                    except OSError:
                        pass
        self._tmp.cleanup()

    def paths(self, *, project: bool = True, platform: str = "darwin", trusted_uid: int | None = None) -> PathSet:
        return PathSet(platform=platform, home=self.home, project=self.project if project else None,
                       managed_dir=self.managed,
                       trusted_uid=os.getuid() if trusted_uid is None else trusted_uid)

    def write(self, rel: str, content: Any, base: str | None = None, mode: int | None = None) -> str:
        path = os.path.join(base or self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if isinstance(content, (dict, list)):
            content = json.dumps(content, indent=2)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        if mode is not None:
            os.chmod(path, mode)
        return path

    def load_sample(self, name: str = "sample.json") -> None:
        """Materialize tests/fixtures/<name> (a {relpath: content} map) under the temp root."""
        with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
            spec = json.load(fh)
        for rel, content in spec["files"].items():
            if isinstance(content, (dict, list)):
                content = json.dumps(content, indent=2).replace("__PROJECT__", self.project)
            self.write(rel, content)

    # layer shortcuts
    def user(self, data: Any) -> str:
        return self.write(".claude/settings.json", data, self.home)

    def project_settings(self, data: Any) -> str:
        return self.write(".claude/settings.json", data, self.project)

    def local(self, data: Any) -> str:
        return self.write(".claude/settings.local.json", data, self.project)

    def managed_settings(self, data: Any, mode: int = 0o644) -> str:
        os.makedirs(self.managed, exist_ok=True)
        return self.write("managed-settings.json", data, self.managed, mode=mode)

    def mcp(self, servers: dict[str, Any]) -> str:
        return self.write(".mcp.json", {"mcpServers": servers}, self.project)

    def user_state(self, data: Any) -> str:
        return self.write(".claude.json", data, self.home)

    def agent(self, name: str, text: str, scope: str = "project") -> str:
        base = self.project if scope == "project" else self.home
        return self.write(f".claude/agents/{name}.md", text, base)

    def skill(self, name: str, text: str, scope: str = "project") -> str:
        base = self.project if scope == "project" else self.home
        return self.write(f".claude/skills/{name}/SKILL.md", text, base)

    def plugin(self, name: str, marketplace: str, files: dict[str, Any], version: str = "1.0.0") -> str:
        base = os.path.join(self.home, ".claude", "plugins", "cache", marketplace, name, version)
        os.makedirs(base, exist_ok=True)
        for rel, content in files.items():
            if rel.endswith("/"):
                os.makedirs(os.path.join(base, rel), exist_ok=True)
            else:
                self.write(rel, content, base)
        return base


class FakeEnvTestCase:
    """Mixin: provides self.env and cleans it up."""

    def setUp(self):  # noqa: D401
        super().setUp()
        self.env = FakeEnv()
        self.addCleanup(self.env.cleanup)
