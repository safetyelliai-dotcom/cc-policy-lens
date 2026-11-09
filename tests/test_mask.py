"""mask module tests. Fake secrets are assembled at runtime (CLAUDE.md rule 2)."""
import unittest

from cc_policy_lens import mask

# Runtime-assembled fakes: never write a secret-shaped literal into a file.
ANTHROPIC = "sk-" + "ant-" + "x" * 24
AWS = "AK" + "IA" + "ABCDEFGHIJKLMNOP"
GITHUB = "gh" + "p_" + "a1B2" * 9
SLACK = "xo" + "xb-" + "1234567890-abcdef"
JWT = "ey" + "J" + "a" * 12 + "." + "b" * 12 + "." + "c" * 12
RANDOM = "Zq8" + "rT2vLx9" + "Kp4WmN7s" + "Qa1Bc3De"


class FindSecretTest(unittest.TestCase):
    def test_known_tokens(self):
        for tok, label in [(ANTHROPIC, "anthropic-key"), (AWS, "aws-access-key"), (GITHUB, "github-token"),
                           (SLACK, "slack-token"), (JWT, "jwt")]:
            with self.subTest(label=label):
                self.assertEqual(mask.find_secret(tok), label)
                self.assertEqual(mask.find_secret(f"prefix {tok} suffix"), label)

    def test_bearer_and_url_credentials(self):
        self.assertEqual(mask.find_secret("Bearer " + "abcd" * 5), "bearer-credential")
        self.assertEqual(mask.find_secret("https://user:" + "pw" * 5 + "@example.com/x"), "url-credential")
        self.assertEqual(mask.find_secret("https://x.io/a?token=" + "q" * 10), "url-query-secret")

    def test_high_entropy(self):
        self.assertEqual(mask.find_secret(RANDOM), "high-entropy")

    def test_non_secrets(self):
        for v in ["", "acceptEdits", "Bash(npm run test *)", "https://hooks.example.com/*",
                  "/usr/local/bin/node", "registry.npmjs.org", "2.1.300", "${GITHUB_TOKEN}",
                  "Bearer ${API_KEY}", "@modelcontextprotocol/server-github@0.6.2"]:
            with self.subTest(v=v):
                self.assertIsNone(mask.find_secret(v))

    def test_env_reference(self):
        self.assertTrue(mask.is_env_reference("${A_B}"))
        self.assertTrue(mask.is_env_reference("${A:-default}"))
        self.assertTrue(mask.is_env_reference("$TOKEN"))
        self.assertFalse(mask.is_env_reference("Bearer ${A}"))
        self.assertFalse(mask.is_env_reference(GITHUB))


class MaskValueTest(unittest.TestCase):
    def assertHidden(self, secret, masked):
        self.assertNotIn(secret, masked)
        # no 6+ char run of the secret body survives
        body = secret[-12:]
        self.assertNotIn(body, masked)
        self.assertIn(mask.MASK, masked)

    def test_masks_tokens_in_text(self):
        for tok in (ANTHROPIC, AWS, GITHUB, SLACK, JWT, RANDOM):
            with self.subTest(tok=tok[:4]):
                self.assertHidden(tok, mask.mask_value(f"key={tok} end"))

    def test_keeps_safe_prefix_and_length(self):
        out = mask.mask_value(GITHUB)
        self.assertTrue(out.startswith("ghp_"))
        self.assertIn(f"({len(GITHUB)} chars)", out)

    def test_sensitive_key_masks_plain_password(self):
        out = mask.mask_value("hunter22", key="DB_PASSWORD")
        self.assertNotIn("hunter22", out)

    def test_sensitive_key_keeps_reference_and_scheme(self):
        self.assertEqual(mask.mask_value("${API_TOKEN}", key="API_TOKEN"), "${API_TOKEN}")
        self.assertEqual(mask.mask_value("Bearer ${T}", key="Authorization"), "Bearer ${T}")

    def test_bearer_literal_masked(self):
        secret = "abcd" * 6
        self.assertHidden(secret, mask.mask_value("Bearer " + secret, key="Authorization"))

    def test_url_credentials(self):
        pw = "s3cr" + "etpw"
        out = mask.mask_value(f"https://bob:{pw}@git.example.com/repo.git")
        self.assertNotIn(pw, out)
        self.assertIn("git.example.com", out)

    def test_non_string_passthrough(self):
        self.assertEqual(mask.mask_value(5), 5)
        self.assertIsNone(mask.mask_value(None))

    def test_ordinary_values_unchanged(self):
        for v in ["acceptEdits", "Bash(git log *)", "Read(~/.ssh/**)", "npx -y @acme/docs-mcp"]:
            self.assertEqual(mask.mask_value(v), v)


class MaskObjTest(unittest.TestCase):
    def test_nested(self):
        obj = {"env": {"GITHUB_TOKEN": GITHUB, "NODE_ENV": "dev"},
               "args": ["-y", "pkg", ANTHROPIC], "n": 3, "flag": True}
        out = mask.mask_obj(obj)
        text = repr(out)
        for s in (GITHUB, ANTHROPIC):
            self.assertNotIn(s, text)
        self.assertEqual(out["env"]["NODE_ENV"], "dev")
        self.assertEqual(out["n"], 3)
        self.assertIs(out["flag"], True)

    def test_depth_limit(self):
        deep = cur = {}
        for _ in range(200):
            cur["a"] = {}
            cur = cur["a"]
        mask.mask_obj(deep)  # must not raise

    def test_safe_error(self):
        err = ValueError("bad value " + ANTHROPIC + " x" * 400)
        out = mask.safe_error(err)
        self.assertTrue(out.startswith("ValueError: "))
        self.assertNotIn(ANTHROPIC, out)
        self.assertLessEqual(len(out), 320)


class ReviewRegressionTest(unittest.TestCase):
    """Cases from the Phase 1 security review."""

    def test_private_key_body_masked(self):
        body = "MIIEab/cd/ef" + "Gh12" * 10
        pem = "-----BEGIN RSA " + "PRIVATE KEY-----\n" + body + "\n-----END RSA " + "PRIVATE KEY-----"
        out = mask.mask_value(pem)
        self.assertNotIn(body, out)
        self.assertNotIn(body[:10], out)

    def test_reference_default_is_literal(self):
        pw = "hunter2" + "hunter2"
        self.assertNotIn(pw, mask.mask_value("${API_TOKEN:-" + pw + "}", key="API_TOKEN"))
        self.assertFalse(mask.is_env_reference("${X:-" + GITHUB + "}"))
        self.assertEqual(mask.find_secret("${X:-" + GITHUB + "}"), "github-token")
        self.assertTrue(mask.is_env_reference("${PORT:-8080}"))

    def test_inline_assignment_and_flags(self):
        aws_secret = "wJalrXUtnFEMI/" + "K7MDENG/bPxRfiCY" + "EXAMPLEKEY"
        hex40 = "0123456789abcdef" * 2 + "01234567"
        hex32 = "fedcba9876543210" * 2
        cases = [
            f"AWS_SECRET_ACCESS_KEY={aws_secret} aws s3 ls",
            f"export GITHUB_TOKEN={hex40}",
            f"node server.js --api-key {hex32}",
            f"node server.js --password=hunter2hunter2",
        ]
        for c, secret in zip(cases, [aws_secret, hex40, hex32, "hunter2hunter2"]):
            with self.subTest(c=c[:20]):
                self.assertIsNotNone(mask.find_secret(c))
                self.assertNotIn(secret, mask.mask_value(c))
        # non-sensitive flags and assignments untouched
        self.assertEqual(mask.mask_value("NODE_ENV=production node --port 8080"),
                         "NODE_ENV=production node --port 8080")

    def test_url_userinfo(self):
        for url, leak in [("postgres://bob:p@ss@db.example.com/x", "ss@db"),
                          ("https://bob:ab/cd@host.example.com/", "ab/cd"),
                          ("https://" + "abc123def456" + "@o1.ingest.example.io/42", "abc123def456")]:
            with self.subTest(url=url[:12]):
                out = mask.mask_value(url)
                self.assertNotIn(leak, out)
                self.assertIn(mask.MASK, out)

    def test_more_sensitive_names(self):
        for k in ("DB_PASS", "MYSQL_PWD", "STRIPE_KEY", "SENTRY_DSN", "AUTH_HEADER", "X-Amz-Signature"):
            self.assertTrue(mask.is_sensitive_key(k), k)
        for k in ("author", "NODE_ENV", "PATH", "keybindings"):
            self.assertFalse(mask.is_sensitive_key(k), k)
        out = mask.mask_value("https://x.io/a?private_token=" + "z" * 12 + "&client_secret=" + "y" * 12)
        self.assertNotIn("z" * 12, out)
        self.assertNotIn("y" * 12, out)

    def test_long_hostile_input_is_fast_and_masked(self):
        import time
        for hostile in ("eyJ" * 300000, "a-" * 500000):
            t = time.perf_counter()
            out = mask.mask_value(hostile)
            self.assertLess(time.perf_counter() - t, 1.0)
            self.assertIn(mask.MASK, out)
            self.assertEqual(mask.find_secret(hostile), "oversized-value")

    def test_dollar_prefixed_literal_is_not_a_reference(self):
        self.assertFalse(mask.is_env_reference("$ecretPassw0rd"))
        self.assertNotIn("ecretPassw0rd", mask.mask_value("$ecretPassw0rd", key="DB_PASSWORD"))

    def test_sensitive_parent_covers_children(self):
        out = mask.mask_obj({"credentials": {"value": "hunter22"}})
        self.assertNotIn("hunter22", repr(out))

    def test_default_masked_under_plain_key(self):
        rnd = "aB3dE5fG7hJ9" + "kL1mN3pQ5r"
        out = repr(mask.mask_obj({"args": ["${FOO:-" + rnd + "}"]}))
        self.assertNotIn(rnd, out)
        self.assertIn("${FOO:-", out)

    def test_short_and_numeric_sensitive_values(self):
        self.assertNotIn("abc", mask.mask_value("abc", key="PIN_PASSWORD"))
        self.assertEqual(mask.mask_obj({"DB_PASSWORD": 123456})["DB_PASSWORD"], mask.MASK)
        self.assertIs(mask.mask_obj({"apiKeyEnabled": True})["apiKeyEnabled"], True)

    def test_helper_commands_not_masked(self):
        self.assertEqual(mask.mask_obj({"apiKeyHelper": "/usr/local/bin/get-key"})["apiKeyHelper"],
                         "/usr/local/bin/get-key")

    def test_dict_keys_masked(self):
        out = mask.mask_obj({GITHUB: {"command": "x"}})
        self.assertNotIn(GITHUB, repr(out))

    def test_config_dir_env_ignored_with_home_override(self):
        import os
        from unittest import mock
        from cc_policy_lens.paths import default_paths
        with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": "/real/config"}):
            p = default_paths(None, home="/fixture/home", managed_dir="/fixture/managed")
            self.assertTrue(p.user_state.startswith("/fixture/home"))
            self.assertTrue(p.claude_dir.startswith("/fixture/home"))


if __name__ == "__main__":
    unittest.main()
