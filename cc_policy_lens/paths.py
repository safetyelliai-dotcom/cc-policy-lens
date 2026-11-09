"""OS-specific locations. Everything is injectable so tests never touch real paths."""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass

MANAGED_DIRS = {
    "darwin": "/Library/Application Support/ClaudeCode",
    "linux": "/etc/claude-code",
    "win32": r"C:\Program Files\ClaudeCode",
}

MANAGED_SETTINGS = "managed-settings.json"
MANAGED_DROPIN_DIR = "managed-settings.d"
MANAGED_MCP = "managed-mcp.json"


def platform_key(platform: str | None = None) -> str:
    p = platform or sys.platform
    if p.startswith("linux"):
        return "linux"
    if p.startswith("win"):
        return "win32"
    if p == "darwin":
        return "darwin"
    return p


@dataclass(frozen=True)
class PathSet:
    platform: str
    home: str
    project: str | None
    managed_dir: str
    trusted_uid: int = 0               # owner expected for managed files (root)
    config_dir: str | None = None      # CLAUDE_CONFIG_DIR: replaces ~/.claude and holds .claude.json

    # --- user ---
    @property
    def claude_dir(self) -> str:
        return self.config_dir or os.path.join(self.home, ".claude")

    @property
    def user_settings(self) -> str:
        return os.path.join(self.claude_dir, "settings.json")

    @property
    def user_state(self) -> str:
        if self.config_dir:
            return os.path.join(self.config_dir, ".claude.json")
        return os.path.join(self.home, ".claude.json")

    @property
    def user_agents(self) -> str:
        return os.path.join(self.claude_dir, "agents")

    @property
    def user_skills(self) -> str:
        return os.path.join(self.claude_dir, "skills")

    @property
    def user_workflows(self) -> str:
        return os.path.join(self.claude_dir, "workflows")

    @property
    def plugins_dir(self) -> str:
        return os.path.join(self.claude_dir, "plugins")

    # --- project ---
    def _p(self, *parts: str) -> str | None:
        return os.path.join(self.project, *parts) if self.project else None

    @property
    def project_settings(self) -> str | None:
        return self._p(".claude", "settings.json")

    @property
    def local_settings(self) -> str | None:
        return self._p(".claude", "settings.local.json")

    @property
    def project_mcp(self) -> str | None:
        return self._p(".mcp.json")

    @property
    def project_agents(self) -> str | None:
        return self._p(".claude", "agents")

    @property
    def project_skills(self) -> str | None:
        return self._p(".claude", "skills")

    @property
    def project_workflows(self) -> str | None:
        return self._p(".claude", "workflows")

    # --- managed ---
    @property
    def managed_settings(self) -> str:
        return os.path.join(self.managed_dir, MANAGED_SETTINGS)

    @property
    def managed_dropins(self) -> str:
        return os.path.join(self.managed_dir, MANAGED_DROPIN_DIR)

    @property
    def managed_mcp(self) -> str:
        return os.path.join(self.managed_dir, MANAGED_MCP)


def default_paths(project: str | None, *, home: str | None = None,
                  managed_dir: str | None = None, platform: str | None = None,
                  config_dir: str | None = None) -> PathSet:
    """Real locations. Only the CLI calls this; tests build PathSet directly.

    CLAUDE_CONFIG_DIR is honored only when ``home`` is not overridden, so a scan
    pointed at a fixture home can never fall back to the real config directory.
    """
    plat = platform_key(platform)
    if home is None:
        home = os.path.expanduser("~")
        if config_dir is None:
            config_dir = os.environ.get("CLAUDE_CONFIG_DIR") or None
    if managed_dir is None:
        managed_dir = MANAGED_DIRS.get(plat, MANAGED_DIRS["linux"])
    proj = os.path.abspath(project) if project else None
    return PathSet(platform=plat, home=home, project=proj, managed_dir=managed_dir, config_dir=config_dir)
