"""collect.py tests. All paths live under a temp root; a guard asserts nothing else is opened."""
import builtins
import json
import os
import unittest
from unittest import mock

from cc_policy_lens import collect
from tests.helpers import FakeEnvTestCase

GITHUB = "gh" + "p_" + "a1B2" * 9


class OpenGuard:
    """Records every path opened/stat'ed/listed (resolved through symlinks) outside ``root``."""

    def __init__(self, root):
        self.root = root
        self.outside = []
        self._busy = False

    def _check(self, path):
        if self._busy or isinstance(path, int):
            return
        self._busy = True                 # realpath itself calls os.lstat
        try:
            p = os.path.realpath(os.fspath(path))
        finally:
            self._busy = False
        # ancestors of root are lstat'ed by realpath() while resolving; that reads no content
        is_ancestor = p == os.sep or self.root.startswith(p.rstrip(os.sep) + os.sep)
        if not (p == self.root or p.startswith(self.root + os.sep) or is_ancestor):
            self.outside.append(p)

    def __enter__(self):
        self._patches = []
        for target in ("builtins.open", "os.open", "os.lstat", "os.stat", "os.listdir", "os.scandir"):
            mod, _, name = target.rpartition(".")
            real = getattr(builtins if mod == "builtins" else os, name)

            def wrapper(p, *a, _real=real, **k):
                self._check(p)
                return _real(p, *a, **k)
            self._patches.append(mock.patch(target, wrapper))
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in self._patches:
            p.stop()


class CollectSampleTest(FakeEnvTestCase, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.env.load_sample()

    def test_reads_only_inside_fake_root(self):
        with OpenGuard(self.env.root) as g:
            collect.collect_all(self.env.paths())
        self.assertEqual(g.outside, [], "collector touched paths outside the fake root")

    def test_layers_parsed(self):
        col = collect.collect_all(self.env.paths())
        self.assertEqual(col.settings["user"].data["permissions"]["defaultMode"], "acceptEdits")
        self.assertIn("hooks", col.settings["project"].data)
        self.assertEqual(col.settings["local"].data["permissions"]["allow"], ["Bash(*)"])
        self.assertFalse(col.settings["managed"].info.exists)
        self.assertIn("docs-search", col.project_mcp.data["mcpServers"])
        self.assertEqual(col.errors, [])

    def test_user_state_keeps_only_mcp_subset(self):
        col = collect.collect_all(self.env.paths())
        self.assertEqual(set(col.user_state.data), {"mcpServers", "project"})
        self.assertNotIn("oauthAccount", json.dumps(col.user_state.data))
        self.assertNotIn("history", col.user_state.data["project"])
        self.assertTrue(col.user_state.data["project"]["hasTrustDialogAccepted"])

    def test_agents_skills_plugins(self):
        col = collect.collect_all(self.env.paths())
        agents = {(a.scope, a.frontmatter.get("name")) for a in col.agents}
        self.assertEqual(agents, {("user", "notes"), ("project", "reviewer")})
        skill = col.skills[0]
        self.assertEqual(skill.frontmatter["name"], "release")
        self.assertIn("command: ./scripts/check.sh", skill.blocks["hooks"])
        self.assertEqual([p.plugin_id for p in col.plugins], ["formatter@acme-tools"])
        self.assertIn("hooks", col.plugins[0].components)
        self.assertIn("PostToolUse", col.plugins[0].hooks_doc["hooks"])

    def test_without_project(self):
        col = collect.collect_all(self.env.paths(project=False))
        self.assertNotIn("project", col.settings)
        self.assertIsNone(col.project_mcp)
        self.assertNotIn("project", col.user_state.data)


class CollectEdgeCaseTest(FakeEnvTestCase, unittest.TestCase):
    def test_missing_everything(self):
        col = collect.collect_all(self.env.paths())
        self.assertFalse(col.settings["user"].info.exists)
        self.assertIsNone(col.settings["user"].data)
        self.assertEqual(col.errors, [])

    def test_broken_json(self):
        self.env.user("{ \"permissions\": { \"allow\": [ }")
        doc = collect.collect_all(self.env.paths()).settings["user"]
        self.assertEqual(doc.info.error_kind, "parse")
        self.assertIsNone(doc.data)
        self.assertIn("line 1", doc.info.error)

    def test_parse_error_does_not_echo_content(self):
        self.env.user('{"env": {"GITHUB_TOKEN": "' + GITHUB + '"},,}')
        col = collect.collect_all(self.env.paths())
        self.assertNotIn(GITHUB, " ".join(col.errors))

    def test_not_object(self):
        self.env.user("[1, 2, 3]")
        self.assertEqual(collect.collect_all(self.env.paths()).settings["user"].info.error_kind, "not_object")

    def test_empty_file_is_empty_object(self):
        self.env.user("")
        self.assertEqual(collect.collect_all(self.env.paths()).settings["user"].data, {})

    def test_too_deep(self):
        self.env.user("[" * 2000 + "]" * 2000)
        kind = collect.collect_all(self.env.paths()).settings["user"].info.error_kind
        self.assertIn(kind, ("too_deep", "not_object"))
        deep = {"a": None}
        cur = deep
        for _ in range(collect.MAX_DEPTH + 5):
            cur["a"] = {"a": None}
            cur = cur["a"]
        self.env.user(deep)
        self.assertEqual(collect.collect_all(self.env.paths()).settings["user"].info.error_kind, "too_deep")

    def test_too_large(self):
        path = self.env.user({"x": "y" * 2000})
        doc = collect.read_json(path, "user", limit=1000)
        self.assertEqual(doc.info.error_kind, "too_large")
        self.assertIsNone(doc.data)

    @unittest.skipIf(os.name != "posix" or os.geteuid() == 0, "needs non-root POSIX")
    def test_permission_denied(self):
        path = self.env.user({"a": 1})
        os.chmod(path, 0)
        doc = collect.collect_all(self.env.paths()).settings["user"]
        self.assertTrue(doc.info.exists)
        self.assertEqual(doc.info.error_kind, "permission")

    @unittest.skipIf(os.name != "posix", "symlinks")
    def test_symlink_followed_and_recorded(self):
        target = self.env.write("dotfiles/claude-settings.json", {"model": "x"})
        os.makedirs(os.path.join(self.env.home, ".claude"))
        os.symlink(target, os.path.join(self.env.home, ".claude", "settings.json"))
        doc = collect.collect_all(self.env.paths()).settings["user"]
        self.assertTrue(doc.info.is_symlink)
        self.assertEqual(doc.info.symlink_target, target)
        self.assertEqual(doc.data, {"model": "x"})

    @unittest.skipIf(os.name != "posix", "symlinks")
    def test_broken_symlink(self):
        os.makedirs(os.path.join(self.env.home, ".claude"))
        os.symlink(os.path.join(self.env.root, "nope.json"), os.path.join(self.env.home, ".claude", "settings.json"))
        doc = collect.collect_all(self.env.paths()).settings["user"]
        self.assertEqual(doc.info.error, "broken symlink")

    def test_directory_instead_of_file(self):
        os.makedirs(os.path.join(self.env.home, ".claude", "settings.json"))
        doc = collect.collect_all(self.env.paths()).settings["user"]
        self.assertEqual(doc.info.error, "not a regular file")

    def test_managed_dropins_and_mode(self):
        self.env.managed_settings({"permissions": {"disableBypassPermissionsMode": "disable"}}, mode=0o666)
        self.env.write("managed-settings.d/20-b.json", {"b": 1}, self.env.managed)
        self.env.write("managed-settings.d/10-a.json", {"a": 1}, self.env.managed)
        col = collect.collect_all(self.env.paths())
        self.assertEqual(col.settings["managed"].info.mode & 0o777, 0o666)
        self.assertEqual([os.path.basename(d.info.path) for d in col.managed_dropins], ["10-a.json", "20-b.json"])

    def test_frontmatter_parser(self):
        fm, blocks = collect.parse_frontmatter(
            "---\nname: x\ntools: [Read, Grep]\npermissionMode: bypassPermissions\nmcpServers:\n  - slack\n---\nbody")
        self.assertEqual(fm["tools"], ["Read", "Grep"])
        self.assertEqual(fm["permissionMode"], "bypassPermissions")
        self.assertIn("slack", blocks["mcpServers"])
        self.assertEqual(collect.parse_frontmatter("no frontmatter"), ({}, {}))


class Phase2ReviewRegressionTest(FakeEnvTestCase, unittest.TestCase):
    """Cases from the Phase 2 security review."""

    def test_huge_integer_does_not_crash(self):
        self.env.project_settings('{"a": ' + "1" * 5000 + "}")
        doc = collect.collect_all(self.env.paths()).settings["project"]
        self.assertEqual(doc.info.error_kind, "parse")
        self.assertNotIn("1111", doc.info.error)

    @unittest.skipIf(os.name != "posix", "symlinks")
    def test_project_symlink_outside_is_not_read(self):
        secret_home = self.env.write("elsewhere/.claude.json", {"oauthAccount": {"x": 1}, "mcpServers": {}})
        os.symlink(secret_home, os.path.join(self.env.project, ".mcp.json"))
        os.makedirs(os.path.join(self.env.root, "elsewhere", "agents"))
        self.env.write("elsewhere/agents/evil.md", "---\nname: evil\n---\n")
        os.makedirs(os.path.join(self.env.project, ".claude"))
        os.symlink(os.path.join(self.env.root, "elsewhere", "agents"),
                   os.path.join(self.env.project, ".claude", "agents"))
        col = collect.collect_all(self.env.paths())
        self.assertEqual(col.project_mcp.info.error_kind, "outside")
        self.assertIsNone(col.project_mcp.data)
        self.assertEqual([a for a in col.agents if a.scope == "project"], [])

    @unittest.skipIf(os.name != "posix", "symlinks")
    def test_project_symlink_inside_is_read(self):
        target = self.env.write("shared/mcp.json", {"mcpServers": {"a": {"command": "x"}}}, self.env.project)
        os.symlink(target, os.path.join(self.env.project, ".mcp.json"))
        self.assertIn("a", collect.collect_all(self.env.paths()).project_mcp.data["mcpServers"])

    @unittest.skipIf(not hasattr(os, "mkfifo"), "needs mkfifo")
    def test_fifo_does_not_hang(self):
        os.makedirs(os.path.join(self.env.home, ".claude"))
        os.mkfifo(os.path.join(self.env.home, ".claude", "settings.json"))
        info = collect.stat_file(os.path.join(self.env.home, ".claude", "settings.json"))
        info.mode = 0o100644                      # simulate the stat/open race: looked regular at stat time
        self.assertIsNone(collect.read_bytes_limited(info, 1000))
        self.assertEqual(info.error, "not a regular file")

    def test_plugin_errors_reported_and_empty_docs(self):
        self.env.plugin("big", "mkt", {"hooks/hooks.json": "{ broken", ".mcp.json": "[]"})
        col = collect.collect_all(self.env.paths())
        joined = " ".join(col.errors)
        self.assertIn("plugin big@mkt", joined)
        self.assertEqual(col.plugins[0].hooks_doc, {})
        self.assertEqual(col.plugins[0].mcp_doc, {})

    @unittest.skipIf(os.name != "posix", "symlinks")
    def test_plugin_symlink_outside_cache_not_read(self):
        outside = self.env.write("evil/hooks.json", {"hooks": {"PreToolUse": []}})
        base = self.env.plugin("p", "mkt", {"hooks/": None})
        os.symlink(outside, os.path.join(base, "hooks", "hooks.json"))
        col = collect.collect_all(self.env.paths())
        self.assertEqual(col.plugins[0].hooks_doc, {})
        self.assertIn("outside", " ".join(col.errors))

    def test_quoted_value_then_comment(self):
        fm, _ = collect.parse_frontmatter('---\ntools: "Bash" # all\n---\n')
        self.assertEqual(fm["tools"], "Bash")

    def test_dropin_truncation_reported(self):
        for i in range(collect.MAX_DIR_ENTRIES + 3):
            self.env.write(f"managed-settings.d/{i:04d}.json", {}, self.env.managed)
        col = collect.collect_all(self.env.paths())
        self.assertTrue(any("more than" in e for e in col.errors))

    def test_file_swapped_after_stat_not_read(self):
        a = self.env.user({"a": 1})
        info = collect.stat_file(a)
        os.replace(self.env.write("other.json", {"b": 2}), a)
        self.assertIsNone(collect.read_bytes_limited(info, 1000))
        self.assertIn("changed during scan", info.error)

    def test_plugin_versions_listed(self):
        self.env.plugin("p", "m", {"x.txt": "1"}, version="1.0.0")
        newer = self.env.plugin("p", "m", {"x.txt": "2"}, version="1.1.0")
        os.utime(newer, (2_000_000_000, 2_000_000_000))
        info = collect.collect_all(self.env.paths()).plugins[0]
        self.assertEqual(info.versions, ["1.1.0", "1.0.0"])
        self.assertEqual(info.path, newer)

    def test_frontmatter_evasions(self):
        for text in ("\ufeff---\npermissionMode: bypassPermissions\n---\n",
                     '---\n"permissionMode": bypassPermissions\n---\n',
                     "---\npermissionMode: bypassPermissions # temporary\n---\n"):
            with self.subTest(text=text[:12]):
                fm, _ = collect.parse_frontmatter(text)
                self.assertEqual(fm.get("permissionMode"), "bypassPermissions")
        fm, _ = collect.parse_frontmatter('---\ndescription: "use # carefully"\n---\n')
        self.assertEqual(fm["description"], "use # carefully")


if __name__ == "__main__":
    unittest.main()
