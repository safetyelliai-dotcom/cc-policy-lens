"""merge.py tests: precedence, list merging, shadowing, ignored values, managed drop-ins."""
import unittest

from cc_policy_lens import collect, merge
from tests.helpers import FakeEnvTestCase


class MergeTest(FakeEnvTestCase, unittest.TestCase):
    def eff(self):
        return merge.merge(collect.collect_all(self.env.paths()))

    def test_scalar_precedence_and_shadowed(self):
        self.env.user({"model": "u", "sandbox": {"enabled": False}})
        self.env.project_settings({"model": "p"})
        self.env.local({"sandbox": {"enabled": True}})
        self.env.managed_settings({"model": "m"})
        e = self.eff()
        m = e.entry("model")
        self.assertEqual(m.value, "m")
        self.assertEqual(m.source.layer, "managed")
        self.assertEqual([(v, p.layer) for v, p in m.shadowed], [("p", "project"), ("u", "user")])
        sb = e.entry("sandbox.enabled")
        self.assertIs(sb.value, True)
        self.assertEqual(sb.source.layer, "local")
        self.assertEqual(sb.shadowed[0][1].layer, "user")

    def test_lists_merge_and_dedupe(self):
        self.env.user({"permissions": {"allow": ["Bash(git log *)", "Read"]}})
        self.env.project_settings({"permissions": {"allow": ["Bash(npm test)", "Read"]}})
        self.env.local({"permissions": {"allow": ["Bash(*)"]}})
        e = self.eff()
        allow = e.entry("permissions.allow")
        self.assertEqual(allow.value, ["Bash(*)", "Bash(npm test)", "Read", "Bash(git log *)"])
        by_item = {v: p.layer for v, p in allow.items}
        self.assertEqual(by_item["Read"], "project")       # first (highest) provenance kept
        self.assertEqual(by_item["Bash(git log *)"], "user")

    def test_nested_dicts_merge_by_key(self):
        self.env.user({"env": {"A": "1", "B": "user"}})
        self.env.project_settings({"env": {"B": "project", "C": "3"}})
        e = self.eff()
        self.assertEqual(e.get("env.A"), "1")
        self.assertEqual(e.get("env.B"), "project")
        self.assertEqual(e.get("env.C"), "3")
        self.assertEqual(set(e.subtree("env")), {("env", "A"), ("env", "B"), ("env", "C")})

    def test_bypass_ignored_from_project_and_local(self):
        self.env.user({"permissions": {"defaultMode": "acceptEdits"}})
        self.env.project_settings({"permissions": {"defaultMode": "bypassPermissions"}})
        self.env.local({"permissions": {"defaultMode": "auto"}})
        dm = self.eff().entry("permissions.defaultMode")
        self.assertEqual(dm.value, "acceptEdits")
        self.assertEqual(dm.source.layer, "user")
        self.assertEqual({(v, p.layer) for v, p, _ in dm.ignored},
                         {("bypassPermissions", "project"), ("auto", "local")})

    def test_bypass_from_user_is_effective(self):
        self.env.user({"permissions": {"defaultMode": "bypassPermissions"}})
        self.assertEqual(self.eff().get("permissions.defaultMode"), "bypassPermissions")

    def test_other_modes_from_project_apply(self):
        self.env.project_settings({"permissions": {"defaultMode": "plan"}})
        self.assertEqual(self.eff().get("permissions.defaultMode"), "plan")

    def test_managed_only_keys_ignored_elsewhere(self):
        self.env.user({"allowManagedHooksOnly": True, "requiredMinimumVersion": "2.1.300"})
        e = self.eff()
        self.assertIsNone(e.get("allowManagedHooksOnly"))
        self.assertIn("no effect in user", e.entry("allowManagedHooksOnly").ignored[0][2])
        self.env.managed_settings({"allowManagedHooksOnly": True})
        self.assertIs(self.eff().get("allowManagedHooksOnly"), True)

    def test_managed_dropins_override_base(self):
        self.env.managed_settings({"model": "base", "permissions": {"deny": ["Read(./.env)"]}})
        self.env.write("managed-settings.d/10-a.json", {"model": "a", "permissions": {"deny": ["WebFetch"]}},
                       self.env.managed)
        self.env.write("managed-settings.d/20-b.json", {"model": "b"}, self.env.managed)
        e = self.eff()
        self.assertEqual(e.get("model"), "b")
        self.assertTrue(e.entry("model").source.path.endswith("20-b.json"))
        self.assertEqual(e.get("permissions.deny"), ["Read(./.env)", "WebFetch"])
        self.assertEqual(e.raw["managed"]["model"], "b")

    def test_managed_parse_error_fails_closed(self):
        self.env.managed_settings("{ not json")
        e = self.eff()
        self.assertIsNotNone(e.managed_parse_error)
        self.assertIn(("managed", e.managed_parse_error), e.unreadable)

    def test_unreadable_user_layer_is_reported_not_merged(self):
        self.env.user("[1]")
        self.env.project_settings({"model": "p"})
        e = self.eff()
        self.assertEqual(e.layers_present, ["project"])
        self.assertEqual(e.unreadable[0][0], "user")
        self.assertIsNone(e.managed_parse_error)

    def test_wrong_type_is_ignored_not_effective(self):
        self.env.user({"permissions": {"allow": ["Read"]}})
        self.env.project_settings({"permissions": {"allow": "Read"}})     # malformed scalar
        a = self.eff().entry("permissions.allow")
        self.assertEqual(a.value, ["Read"])
        self.assertEqual(a.source.layer, "user")
        self.assertIn("invalid type", a.ignored[0][2])

    def test_string_deny_and_string_bool_not_effective(self):
        self.env.managed_settings({"permissions": {"deny": "Read(./.env) Bash"}, "sandbox": {"enabled": "false"}})
        e = self.eff()
        self.assertIsNone(e.get("permissions.deny"))
        self.assertIsNone(e.get("sandbox.enabled"))
        self.env.managed_settings({"enabledPlugins": {"x@y": 1}})
        self.assertIsNone(self.eff().get(("enabledPlugins", "x@y")))

    # --- Phase 3 review regressions ---
    def test_higher_scalar_replaces_lower_object(self):
        self.env.user({"sandbox": {"enabled": True, "failIfUnavailable": True}})
        self.env.project_settings({"sandbox": False})
        e = self.eff()
        self.assertIsNone(e.get("sandbox.enabled"))
        self.assertEqual(e.entry("sandbox.enabled").shadowed[0][1].layer, "user")
        self.assertIs(e.get("sandbox"), False)

    def test_higher_object_replaces_lower_scalar(self):
        self.env.user({"sandbox": True})
        self.env.project_settings({"sandbox": {"enabled": False}})
        e = self.eff()
        self.assertIsNone(e.get("sandbox"))
        self.assertIs(e.get("sandbox.enabled"), False)

    def test_empty_object_is_merge_noop(self):
        self.env.user({"sandbox": {"enabled": True}})
        self.env.project_settings({"sandbox": {}})
        self.assertIs(self.eff().get("sandbox.enabled"), True)

    def test_dropin_scalar_replaces_base_object(self):
        self.env.managed_settings({"sandbox": {"enabled": True}})
        self.env.write("managed-settings.d/10-x.json", {"sandbox": False}, self.env.managed)
        self.assertIsNone(self.eff().get("sandbox.enabled"))

    def test_unverified_managed_only_keys_fail_closed(self):
        self.env.user({"allowManagedPermissionRulesOnly": True, "allowManagedMcpServersOnly": True,
                       "sandbox": {"network": {"allowManagedDomainsOnly": True}}})
        e = self.eff()
        for k in ("allowManagedPermissionRulesOnly", "allowManagedMcpServersOnly",
                  "sandbox.network.allowManagedDomainsOnly"):
            self.assertIsNone(e.get(k), k)
            self.assertIn("unverified", e.entry(k).ignored[0][2])

    def test_too_deep_managed_is_not_fail_closed(self):
        deep = cur = {}
        for _ in range(100):
            cur["a"] = {}
            cur = cur["a"]
        self.env.managed_settings(deep)
        e = self.eff()
        self.assertIsNone(e.managed_parse_error)
        self.assertEqual(e.unreadable[0][0], "managed")

    def test_nan_managed_fails_closed(self):
        self.env.managed_settings('{"permissions": {"deny": ["Read"]}, "x": NaN}')
        e = self.eff()
        self.assertIsNotNone(e.managed_parse_error)
        self.assertIsNone(e.get("permissions.deny"))

    def test_dotted_names_need_tuple_paths(self):
        self.env.user_state({"mcpServers": {}})
        self.env.user({"env": {"A.B": "1"}})
        e = self.eff()
        self.assertEqual(e.get(("env", "A.B")), "1")
        self.assertEqual(e.entry(("env", "A.B")).key, ("env", "A.B"))

    def test_caveats_present(self):
        self.assertTrue(any("MDM" in c for c in self.eff().caveats))

    def test_sample_tree(self):
        self.env.load_sample()
        e = self.eff()
        self.assertEqual(e.layers_present, ["local", "project", "user"])
        self.assertIs(e.get("sandbox.enabled"), True)
        self.assertEqual(e.source_layer("sandbox.enabled"), "project")
        self.assertIn("Bash(*)", e.get("permissions.allow"))
        self.assertEqual(e.get("env.NODE_ENV"), "development")


if __name__ == "__main__":
    unittest.main()
