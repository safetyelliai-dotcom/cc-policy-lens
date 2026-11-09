"""Secret detection and masking.

Every value that leaves the tool (report, log, exception message) must pass through
``mask_value`` / ``mask_obj``. Detection is heuristic and errs toward masking.
"""
from __future__ import annotations

import math
import re
from typing import Any

MASK = "****"
MAX_SCAN = 8192          # longer strings are masked whole (no regex work on hostile input)

# (pattern, label, number of leading chars that may be shown — only fixed prefixes)
_TOKEN_PATTERNS: list[tuple[re.Pattern[str], str, int]] = [
    (re.compile(r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]{0,40}PRIVATE KEY-----|\Z)"),
     "private-key", 0),
    (re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,512}"), "anthropic-key", 7),
    (re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,512}"), "api-key", 3),
    (re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"), "aws-access-key", 4),
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{30,255}"), "github-token", 4),
    (re.compile(r"github_pat_[A-Za-z0-9_]{30,255}"), "github-token", 11),
    (re.compile(r"glpat-[A-Za-z0-9_\-]{20,255}"), "gitlab-token", 6),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,255}"), "slack-token", 5),
    (re.compile(r"AIza[0-9A-Za-z_\-]{30,255}"), "google-api-key", 4),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,2048}\.[A-Za-z0-9_\-]{10,2048}\.[A-Za-z0-9_\-]{10,2048}"), "jwt", 3),
]

_BEARER = re.compile(r"(?i)\b(bearer|basic|token)\s+([A-Za-z0-9._~+/=\-]{8,2048})")
# userinfo runs to the last '@' of the authority (passwords may contain '@' or '/').
_URL_CRED = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]{0,20}://)([^\s?#]{1,512}?)@(?=[^\s@]*\Z|[^\s@]*[/?#\s\"'])")
_QUERY_SECRET = re.compile(
    r"(?i)([?&][\w\-]{0,40}(?:token|secret|signature|sig|key|password|passwd|pwd|credential)[\w\-]{0,40}=)([^&#\s]+)")
# NAME=value (shell assignments, env-style args) and --flag value / --flag=value
_ASSIGN = re.compile(r"(?<![\w\-])([A-Za-z_][A-Za-z0-9_]{0,80})=(\"[^\"]{0,2048}\"|'[^']{0,2048}'|[^\s;&|\"']{1,2048})")
_FLAG = re.compile(r"(?<![\w\-])(--?[A-Za-z][A-Za-z0-9\-_]{0,60})(=|\s+)(\"[^\"]{0,2048}\"|'[^']{0,2048}'|[^\s;&|\-\"'][^\s;&|]{0,2047})")

SENSITIVE_KEY = re.compile(
    r"(?i)(secret|token|passw(or)?d|passwd|pass$|^pass_|_pass_|pwd|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|_key$|^key$|credential|auth|cookie|session[_-]?id|dsn|signature|bearer)"
)
# Keys whose value is a helper command/path, not a secret (inline secrets in them are still caught).
_NOT_SENSITIVE = re.compile(r"(?i)^(author|authors|authority|key_?name|keybindings?|passthrough|"
                            r"apiKeyHelper|otelHeadersHelper|awsAuthRefresh|awsCredentialExport)$")

# References Claude Code expands: ${NAME}, ${NAME:-default}, $NAME (uppercase env style only)
_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}|\$([A-Z_][A-Z0-9_]*)")
_SCHEME_WORDS = {"bearer", "basic", "token", "digest"}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def is_env_reference(value: str) -> bool:
    """True when the whole value is one reference whose default (if any) holds no secret."""
    m = _REF.fullmatch(value.strip())
    if not m:
        return False
    default = m.group(2)
    return not default or find_secret(default) is None


def strip_references(value: str) -> str:
    """Replace references by their literal default (defaults are literal text, not references)."""
    return _REF.sub(lambda m: m.group(2) or "", value)


def looks_high_entropy(value: str) -> bool:
    v = value.strip().strip("\"'")
    if len(v) < 20 or len(v) > 4096 or v[0] in "/~." or any(c in v for c in " @:\\"):
        return False
    if re.fullmatch(r"[0-9a-f]{32,}", v) or re.fullmatch(r"[0-9A-F]{32,}", v):
        return True                                  # hex tokens
    if not re.fullmatch(r"[A-Za-z0-9+/=_\-.]+", v):
        return False
    has_lower = bool(re.search(r"[a-z]", v))
    has_upper = bool(re.search(r"[A-Z]", v))
    has_digit = bool(re.search(r"[0-9]", v))
    if not (has_lower and has_upper and has_digit):
        return False
    if v.count(".") > 2 or (v.count("/") > 1 and len(v) < 30):
        return False
    return _entropy(v) >= 3.5


def is_sensitive_key(key: str) -> bool:
    k = key or ""
    return bool(SENSITIVE_KEY.search(k)) and not _NOT_SENSITIVE.match(k)


def find_secret(value: str) -> str | None:
    """Return a label if the string contains something that looks like a secret."""
    if not isinstance(value, str) or not value:
        return None
    if len(value) > MAX_SCAN:
        return "oversized-value"
    literal = strip_references(value)
    for rx, label, _ in _TOKEN_PATTERNS:
        if rx.search(literal):
            return label
    if _BEARER.search(literal):
        return "bearer-credential"
    if _URL_CRED.search(literal):
        return "url-credential"
    if _QUERY_SECRET.search(literal):
        return "url-query-secret"
    for m in _ASSIGN.finditer(literal):
        if is_sensitive_key(m.group(1)) and _literal_secret_value(m.group(2)):
            return "inline-assignment"
    for m in _FLAG.finditer(literal):
        if is_sensitive_key(m.group(1).lstrip("-")) and _literal_secret_value(m.group(3)):
            return "inline-flag"
    for tok in re.split(r"[\s\"',;=]+", literal):
        if looks_high_entropy(tok):
            return "high-entropy"
    return None


def _literal_secret_value(v: str) -> bool:
    v = v.strip("\"'")
    if not v or MASK in v:
        return False
    if _REF.fullmatch(v):
        m = _REF.fullmatch(v)
        return bool(m and m.group(2))   # a non-empty default is a literal
    return len(v) >= 4


def _mask_token(tok: str, show: int) -> str:
    show = min(show, max(0, len(tok) // 4))
    return f"{tok[:show]}{MASK}({len(tok)} chars)"


def _mask_ref_defaults(value: str) -> str:
    def repl(m: re.Match[str]) -> str:
        if m.group(2):
            return "${" + m.group(1) + ":-" + MASK + "}"
        return m.group(0)
    return _REF.sub(repl, value)


def _mask_known(value: str) -> str:
    # ${VAR:-default}: the default is literal text and is masked when it looks secret
    out = _REF.sub(lambda m: "${" + m.group(1) + ":-" + MASK + "}"
                   if m.group(2) and find_secret(m.group(2)) else m.group(0), value)
    for rx, _, show in _TOKEN_PATTERNS:
        out = rx.sub(lambda m, s=show: _mask_token(m.group(0), s), out)
    out = _BEARER.sub(lambda m: f"{m.group(1)} {MASK}", out)
    out = _URL_CRED.sub(lambda m: f"{m.group(1)}{MASK}@", out)
    out = _QUERY_SECRET.sub(lambda m: f"{m.group(1)}{MASK}", out)

    def assign(m: re.Match[str]) -> str:
        if is_sensitive_key(m.group(1)) and _literal_secret_value(m.group(2)):
            return f"{m.group(1)}={MASK}"
        return m.group(0)
    out = _ASSIGN.sub(assign, out)

    def flag(m: re.Match[str]) -> str:
        if is_sensitive_key(m.group(1).lstrip("-")) and _literal_secret_value(m.group(3)):
            return f"{m.group(1)}{m.group(2)}{MASK}"
        return m.group(0)
    out = _FLAG.sub(flag, out)

    parts = re.split(r"(\s+|[\"',;=])", out)
    for i, p in enumerate(parts):
        if MASK not in p and not _REF.search(p) and looks_high_entropy(p):
            parts[i] = _mask_token(p, 0)
    return "".join(parts)


def mask_value(value: str, key: str | None = None) -> str:
    """Mask secrets inside a string. Under a sensitive ``key`` every literal word is masked."""
    if not isinstance(value, str) or not value:
        return value
    if len(value) > MAX_SCAN:
        return f"{MASK}(long value, {len(value)} chars)"
    out = _mask_known(value)
    if key is not None and is_sensitive_key(key):
        out = _mask_ref_defaults(out)

        def repl(m: re.Match[str]) -> str:
            tok = m.group(0)
            if MASK in tok or _REF.fullmatch(tok) or tok.lower() in _SCHEME_WORDS:
                return tok
            return _mask_token(tok, 0)
        out = re.sub(r"\$\{[^}]*\}|[^\s]+", repl, out)
    return out


def mask_obj(obj: Any, key: str | None = None, _depth: int = 0) -> Any:
    """Recursively mask a JSON-like structure.

    A sensitive key makes its whole subtree sensitive (``{"credentials": {"value": ...}}``).
    """
    if _depth > 64:
        return MASK
    if isinstance(obj, str):
        return mask_value(obj, key)
    if isinstance(obj, dict):
        parent_sensitive = key is not None and is_sensitive_key(key)
        # keys can be user-chosen (MCP server names, env var names): mask them too
        return {mask_value(str(k)): mask_obj(v, key if parent_sensitive and not is_sensitive_key(str(k)) else str(k),
                                             _depth + 1)
                for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [mask_obj(v, key, _depth + 1) for v in obj]
    if isinstance(obj, (int, float)) and not isinstance(obj, bool) and key is not None and is_sensitive_key(key):
        return MASK                                   # numeric PINs / passwords
    return obj


def safe_error(exc: BaseException) -> str:
    """Exception text for reports: type name plus masked message, length-limited."""
    msg = mask_value(str(exc)[:2000])
    if len(msg) > 300:
        msg = msg[:300] + "…"
    return f"{type(exc).__name__}: {msg}"
