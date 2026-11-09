"""Rule tests driven by tests/fixtures/<RULE-ID>/cases.json (write-check-rule skill, step 4).

Each case lists files (relative to a temp root: home/, project/, managed/), optional file
modes, platform and project flag, and the expected status / severity / finding count.
Placeholders like {{GITHUB}} are replaced by fake secrets assembled at runtime.
"""
import json
import os
import unittest

from cc_policy_lens import rules
from cc_policy_lens.rules import build_context, run_rule
from cc_policy_lens.rules.meta import RULE_META, RULE_ORDER
from tests.helpers import FIXTURES, FakeEnv

# Runtime-assembled fakes (CLAUDE.md rule 2): never written to disk as literals.
FAKES = {
    "{{GITHUB}}": "gh" + "p_" + "Z9y8X7w6" * 5,
    "{{ANTHROPIC}}": "sk-" + "ant-" + "api03-" + "Qw3rTy" * 5,
    "{{LITERAL}}": "Lq7" + "Hn2pVx" + "8Rk4TmW" + "e9Zs3Ya",
}


def _fill(text: str) -> str:
    for k, v in FAKES.items():
        text = text.replace(k, v)
    return text


def materialize(env: FakeEnv, case: dict) -> None:
    for rel, content in case["files"].items():
        text = content if isinstance(content, str) else json.dumps(content, indent=2)
        env.write(rel, _fill(text.replace("__PROJECT__", env.project)))
    # apply deepest paths first so directory modes don't block file chmods
    for rel, mode in sorted(case.get("modes", {}).items(), key=lambda kv: -kv[0].count("/")):
        os.chmod(os.path.join(env.root, rel), int(mode, 8))


def load_cases():
    for rid in RULE_ORDER:
        path = os.path.join(FIXTURES, rid, "cases.json")
        with open(path, encoding="utf-8") as fh:
            spec = json.load(fh)
        assert spec["rule"] == rid, path
        yield rid, spec["cases"]


class RuleCasesTest(unittest.TestCase):
    def test_every_rule_has_at_least_three_cases(self):
        for rid, cases in load_cases():
            with self.subTest(rule=rid):
                self.assertGreaterEqual(len(cases), 3)
                statuses = {c["expect"]["status"] for c in cases}
                self.assertIn("fail", statuses)
                self.assertTrue(statuses & {"pass", "na"}, "needs a non-violation case")

    def test_cases(self):
        for rid, cases in load_cases():
            for case in cases:
                with self.subTest(rule=rid, case=case["name"]):
                    self._run_case(rid, case)

    def _run_case(self, rid, case):
        env = FakeEnv()
        try:
            materialize(env, case)
            paths = env.paths(project=case.get("project", True), platform=case.get("platform", "darwin"))
            res = run_rule(rid, build_context(paths))
        finally:
            env.cleanup()
        exp = case["expect"]
        detail = f"{res.status} {[(f.severity, f.message) for f in res.findings]} note={res.note}"
        self.assertEqual(res.status, exp["status"], detail)
        if "severity" in exp:
            self.assertEqual(res.severity, exp["severity"], detail)
        if "count" in exp:
            self.assertEqual(len(res.findings), exp["count"], detail)
        if "message_contains" in exp:
            self.assertTrue(any(exp["message_contains"] in f.message for f in res.findings), detail)
        dump = repr(res)
        for fake in FAKES.values():
            self.assertNotIn(fake, dump, "secret leaked into rule output")
            self.assertNotIn(fake[-10:], dump, "partial secret leaked into rule output")


class RuleEngineTest(unittest.TestCase):
    def test_metadata_matches_catalog(self):
        path = os.path.join(os.path.dirname(FIXTURES), "..", "docs", "rules-catalog.json")
        with open(path, encoding="utf-8") as fh:
            catalog = {r["id"]: r for r in json.load(fh)["rules"]}
        self.assertEqual(list(catalog), list(RULE_ORDER))
        for rid, meta in RULE_META.items():
            with self.subTest(rule=rid):
                for k in ("title", "domain", "level", "severity", "verified"):
                    self.assertEqual(meta[k], catalog[rid][k], k)
                self.assertTrue(meta["doc_ref"].startswith(catalog[rid]["doc_ref"].split("#")[0]))
                self.assertTrue(meta["rationale"] and meta["remediation"])

    def test_every_rule_registered(self):
        rules._load()
        self.assertEqual(set(rules.REGISTRY), set(RULE_ORDER))

    @unittest.skipIf(os.name != "posix" or os.geteuid() == 0, "needs non-root POSIX")
    def test_unreadable_layer_turns_pass_into_unknown(self):
        env = FakeEnv()
        try:
            env.user({"sandbox": {"enabled": True, "failIfUnavailable": True, "allowUnsandboxedCommands": False}})
            p = env.project_settings({"permissions": {"defaultMode": "plan"}})
            os.chmod(p, 0)
            ctx = build_context(env.paths())
            self.assertEqual(run_rule("SBX-001", ctx).status, "unknown")
            self.assertEqual(run_rule("PERM-002", ctx).status, "fail")      # a fail stays a fail
        finally:
            env.cleanup()

    def test_broken_rule_is_isolated(self):
        env = FakeEnv()
        try:
            ctx = build_context(env.paths())
            rules._load()
            original = rules.REGISTRY["VER-001"]
            rules.REGISTRY["VER-001"] = lambda c: 1 / 0
            try:
                res = run_rule("VER-001", ctx)
            finally:
                rules.REGISTRY["VER-001"] = original
            self.assertEqual(res.status, "unknown")
            self.assertIn("ZeroDivisionError", res.note)
        finally:
            env.cleanup()

    def test_full_run_on_sample_has_no_leaks(self):
        env = FakeEnv()
        try:
            env.load_sample()
            env.user({"env": {"GITHUB_TOKEN": FAKES["{{GITHUB}}"]}})
            results = rules.run_all(build_context(env.paths()))
        finally:
            env.cleanup()
        self.assertEqual(len(results), len(RULE_ORDER))
        self.assertNotIn(FAKES["{{GITHUB}}"], repr(results))
        env_res = next(r for r in results if r.rule_id == "ENV-001")
        self.assertEqual(env_res.status, "fail")


if __name__ == "__main__":
    unittest.main()
