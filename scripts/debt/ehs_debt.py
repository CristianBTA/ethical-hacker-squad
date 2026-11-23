#!/usr/bin/env python3
"""ehs debt — a security-debt ledger for YOUR OWN repository, kept by probes that run.

WHY IT EXISTS
    The squad finds debt; nothing kept it found. A finding lived as long as the
    session that produced it, so "is the debt we found last month still there?"
    had no answer that did not cost another model run. This file is the answer:
    small deterministic probes for the debt that apps built with AI assistants
    leave most often (docs/vibe-debt-next-step.md ranks it, with sources), and a
    ledger in the target that records what each probe decided, when, and at
    which commit. A closed item that comes back is a regression, and saying so
    is the point.

WHAT IT IS FOR, AND WHAT IT REFUSES TO BE (docs/acceptable-use.md)
    Finding and healing weaknesses in code you own or are authorized to audit.
    The refusals below are enforced here, in code, not asked for in a prompt:
      * the target is a LOCAL directory. URLs and remote specs are refused: this
        tool never fetches someone else's code;
      * it never follows a symlink out of the target, and it writes only inside
        <target>/.ehs/;
      * it never prints a secret value or a row of data: secrets are shown as a
        prefix, a length and a fingerprint; network results as status only;
      * the only network probe (Supabase anonymous read) runs only when the
        target carries an ownership attestation (`ehs debt init`), the host is
        listed in it AND referenced by the repository's own code, and the key
        it uses is one found inside the repository. One GET per table, limit 1,
        read-only, rate-limited. No payloads, no brute force, no writes.
    None of this can stop a person who edits this file; it is MIT. It does stop
    the tool from being pointed at a third party by default or by accident, and
    it takes the harvest value out of its output.

WHAT A PROBE RESULT MEANS
    open     the probe sees the pattern now
    closed   it saw it before and does not see it now. That is "no longer
             detected", never "verified fixed": a regression test or an
             independent re-check is what verifies, and the ledger says which
    unknown  the probe could not run (no input of its kind, or not authorized).
             Unknown is not clean, and the report keeps the two apart.

Exit codes: 0 ran, no open item >= the --fail-on severity | 1 ran, open items at
or above it | 2 could not run (bad target, refused scope, unreadable ledger).
"""

from __future__ import annotations

import argparse
import base64
import datetime as _dt
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

SCHEMA = 1
LEDGER_DIR = ".ehs"
LEDGER_FILE = "debt.json"
SCOPE_FILE = "scope.json"
SEVERITIES = {"low": 1, "medium": 2, "high": 3}

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", ".ehs",
    ".mypy_cache", ".pytest_cache", ".tox", ".idea", ".vscode", "Pods",
    ".gradle", ".dart_tool", "target", "vendor", "bower_components",
}
TEXT_EXT = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte",
    ".html", ".htm", ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".env",
    ".sql", ".rules", ".gs", ".php", ".rb", ".go", ".java", ".kt", ".swift",
    ".dart", ".cs", ".sh", ".txt", ".md", ".conf", ".properties", ".xml",
}
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES = 20000

# Procedures in skills/ethical-hacker-squad/references/knowledge that explain each class.
CLASSES = {
    "DEBT-02": ("Secret reachable from client-side code", "MOB-12"),
    "DEBT-04": ("Password stored with a fast hash or in clear", "WEB-19"),
    "DEBT-05": ("JWT accepted without real verification, or signed with a guessable secret", "WEB-01"),
    "DEBT-06": ("Security token generated with a non-cryptographic random", "WEB-19"),
    "DEBT-07": ("Encryption used in a breakable way (ECB, fixed IV, no IV, DES/RC4)", "WEB-19"),
    "DEBT-08": ("Agent / MCP configuration holds secrets or bypasses permissions", "AI-11"),
    "DEBT-09": ("Dependencies not locked", "SUP-01"),
    "DEBT-10": ("Debug mode or wildcard CORS with credentials", "WEB-16"),
    "DEBT-11": ("Credentials or tokens written to logs", "PRV-09"),
    "DEBT-12": ("TLS certificate verification turned off", "WEB-19"),
    "DEBT-N1": ("Supabase table readable with the public anon key (network, opt-in)", "WEB-04"),
}


# --------------------------------------------------------------------------- scope guard

class ScopeError(Exception):
    """Raised when a request falls outside what this tool will do."""


_REMOTE_SPEC = re.compile(r"^(?:[a-z][a-z0-9+.-]*://|git@|[\w.-]+@[\w.-]+:)", re.I)


def resolve_target(raw: str) -> Path:
    """Accept only an existing local directory. Refuse anything that names a remote."""
    if _REMOTE_SPEC.match(raw.strip()):
        raise ScopeError(
            f"'{raw}' names a remote location. ehs debt audits a local checkout of "
            "code you own or are authorized to audit; it never fetches code. "
            "See docs/acceptable-use.md.")
    p = Path(raw).expanduser()
    if not p.exists() or not p.is_dir():
        raise ScopeError(f"'{raw}' is not an existing local directory.")
    return p.resolve()


def iter_files(root: Path) -> Iterable[Path]:
    """Walk the target without following any symlink out of it."""
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS
                             and not os.path.islink(os.path.join(dirpath, d)))
        for name in sorted(filenames):
            fp = Path(dirpath) / name
            if fp.is_symlink():
                continue
            if fp.suffix.lower() not in TEXT_EXT and not name.startswith(".env") \
                    and name not in {"Dockerfile", "Procfile"}:
                continue
            try:
                if fp.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            count += 1
            if count > MAX_FILES:
                return
            yield fp


# --------------------------------------------------------------------------- redaction

def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:10]


def redact(value: str) -> str:
    """Never the value: a prefix that names the kind, the length, a fingerprint."""
    v = value.strip()
    head = v[:4] if len(v) > 12 else ""
    return f"{head}…[{len(v)} chars, fp {fingerprint(v)}]"


def jwt_role(token: str) -> Optional[str]:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        pad = "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + pad))
        role = payload.get("role")
        return role if isinstance(role, str) else None
    except Exception:
        return None


# --------------------------------------------------------------------------- file context

TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|specs|fixtures?|mocks?|examples?)(/|$)|"
                       r"\.(test|spec)\.[a-z]+$|_test\.py$|(^|/)test_[^/]+\.py$", re.I)
EXAMPLE_FILE = re.compile(r"\.(example|sample|template|dist)$|\.env\.(example|sample|template)$", re.I)
CLIENT_DIR = re.compile(r"(^|/)(public|static|www|components|frontend|client|web|dist|build|"
                        r"\.next/static|extension|popup|content-scripts?)(/|$)", re.I)
CLIENT_EXT = {".html", ".htm", ".vue", ".svelte", ".jsx", ".tsx"}
PUBLIC_ENV = re.compile(r"\b(NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|PUBLIC_|NUXT_PUBLIC_)"
                        r"([A-Z0-9_]+)")
SECRET_NAME = re.compile(r"SERVICE_ROLE|SECRET|PRIVATE|PASSWORD|PASSWD|OPENAI|ANTHROPIC|"
                         r"STRIPE_SK|SK_LIVE|ADMIN_KEY|MASTER_KEY|DB_URL|DATABASE_URL|"
                         r"BOT_TOKEN|ACCESS_TOKEN|AUTH_TOKEN|GEMINI_API_KEY|GOOGLE_API_KEY_SERVER")


class Ctx:
    def __init__(self, root: Path):
        self.root = root
        self.rel_cache: Dict[Path, str] = {}
        self.is_extension = any((root / d / "manifest.json").exists() for d in ("", "extension", "src"))
        self.vite = any((root / n).exists() for n in ("vite.config.js", "vite.config.ts", "vite.config.mjs"))

    def rel(self, p: Path) -> str:
        if p not in self.rel_cache:
            self.rel_cache[p] = p.relative_to(self.root).as_posix()
        return self.rel_cache[p]

    def is_client(self, rel: str, text: str) -> bool:
        low = rel.lower()
        first = low.split("/")[0]
        if "/api/" in low or first in {"api", "server", "backend", "functions", "supabase", "scripts"}:
            return False
        if Path(rel).suffix.lower() in CLIENT_EXT:
            return True
        if CLIENT_DIR.search(rel):
            return True
        if self.is_extension and Path(rel).suffix.lower() in {".js", ".ts", ".html"}:
            return True
        if self.vite and low.startswith("src/"):
            return True
        if text.lstrip().startswith(("'use client'", '"use client"')):
            return True
        return False


# --------------------------------------------------------------------------- findings

def finding(cls: str, sev: str, rel: str, line: int, evidence: str, key: str) -> dict:
    return {
        "class": cls,
        "severity": sev,
        "file": rel,
        "line": line,
        "evidence": evidence,
        # the fingerprint survives a line moving; it does not survive the pattern going away
        "id": f"{cls}:{hashlib.sha256((cls + '|' + rel + '|' + key).encode()).hexdigest()[:12]}",
    }


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def comment_line(text: str, pos: int) -> bool:
    start = text.rfind("\n", 0, pos) + 1
    stripped = text[start:pos].lstrip()
    return stripped.startswith(("#", "//", "*", "/*", "<!--", "--"))


# --------------------------------------------------------------------------- secret patterns

PROVIDER_SECRETS = [
    ("aws-access-key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("stripe-live-secret", re.compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{16,})")),
    ("anthropic-key", re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})")),
    ("openai-key", re.compile(r"\b(sk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,})")),
    ("github-token", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,})")),
    ("slack-token", re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,})")),
    ("telegram-bot-token", re.compile(r"\b(\d{8,10}:AA[A-Za-z0-9_\-]{33})\b")),
    ("private-key", re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)")),
    ("sendgrid-key", re.compile(r"\b(SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})")),
]
JWT_RE = re.compile(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})")
PLACEHOLDER = re.compile(r"your[_\-]?|xxx|<[^>]*>|\.\.\.|example|placeholder|replace[_\-]?me|"
                         r"insert[_\-]|dummy|redacted|\*\*\*", re.I)
GENERIC_ASSIGN = re.compile(
    r"""(?ix)\b([A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|API_?KEY|TOKEN|PRIVATE_?KEY|CLAVE|CONTRASENA)[A-Z0-9_]*)\b
        ["']?\s*[:=]\s*["']([^"'\s]{12,})["']""")
ENV_LOOKUP = re.compile(r"os\.environ|getenv|process\.env|import\.meta\.env|ENV\[|config\(|"
                        r"Deno\.env|PropertiesService|secrets\.", re.I)


def probe_secrets(ctx: Ctx, rel: str, text: str, out: List[dict]) -> None:
    if EXAMPLE_FILE.search(rel):
        return
    is_test = bool(TEST_PATH.search(rel))
    client = ctx.is_client(rel, text)
    seen = set()

    def add(kind: str, value: str, pos: int, generic: bool = False) -> None:
        if value in seen or PLACEHOLDER.search(value):
            return
        seen.add(value)
        if is_test:
            return  # planted values in tests are the test's business; SUP-16 covers history
        if not client:
            return  # DEBT-03 (secret anywhere in the source) was DISCARDED on 2026-11-22: precision 0.67
        cls, sev = "DEBT-02", "high"
        out.append(finding(cls, sev, rel, line_of(text, pos),
                           f"{kind} {redact(value)}" + (" in client-side code" if client else ""),
                           fingerprint(value)))

    for kind, rx in PROVIDER_SECRETS:
        for m in rx.finditer(text):
            add(kind, m.group(1), m.start(1))
    for m in JWT_RE.finditer(text):
        role = jwt_role(m.group(1))
        if role == "service_role":
            add("supabase service_role JWT", m.group(1), m.start(1))
    if Path(rel).suffix.lower() in {".md", ".txt"}:
        return
    for m in GENERIC_ASSIGN.finditer(text):
        name, value = m.group(1), m.group(2)
        line_start = text.rfind("\n", 0, m.start()) + 1
        line_end = text.find("\n", m.end())
        line = text[line_start: line_end if line_end != -1 else len(text)]
        if ENV_LOOKUP.search(line) or comment_line(text, m.start()):
            continue
        if re.fullmatch(r"[a-z]+(?:[_.][a-z]+)+", value) or value.startswith(("http", "/", "$", "{", "%")):
            continue  # an identifier, a URL or a template is not a secret value
        if "PUBLIC" in name.upper() or "ANON" in name.upper() or "PUBLISHABLE" in name.upper():
            continue
        add(f"literal assigned to {name}", value, m.start(2), generic=True)

    # A public-prefixed env var whose NAME says it is a secret ships to every browser.
    for m in PUBLIC_ENV.finditer(text):
        name = m.group(2)
        if SECRET_NAME.search(name) and not re.search(r"ANON|PUBLISHABLE|PUBLIC_KEY$", name):
            key = m.group(0)
            if key in seen or is_test:
                continue
            seen.add(key)
            out.append(finding("DEBT-02", "high", rel, line_of(text, m.start()),
                               f"{key} is exposed to the browser by its prefix and its name says it is a secret",
                               key))


# --------------------------------------------------------------------------- BaaS rules
# DEBT-01 (Supabase RLS / Firebase rules, static) was DISCARDED on 2026-11-22: precision 0.60 on the
# sealed corpus. See docs/vibe-debt-next-step.md. The opt-in network probe DEBT-N1 is separate.

# --------------------------------------------------------------------------- code patterns

def _rx(p: str, flags: int = re.I) -> re.Pattern:
    return re.compile(p, flags)


CODE_PROBES: List[Tuple[str, str, re.Pattern, str]] = [
    # DEBT-04 passwords
    ("DEBT-04", "high", _rx(r"hashlib\.(md5|sha1|sha256|sha512)\s*\(\s*[^)]*(?:password|passwd|pwd|contrase(?:n|ñ)a|clave)"), "fast hash applied to a password"),
    ("DEBT-04", "high", _rx(r"createHash\(\s*['\"](md5|sha1|sha256|sha512)['\"]\s*\)\s*\.update\(\s*[^)]*(?:password|passwd|pwd|contrase(?:n|ñ)a|clave)"), "fast hash applied to a password"),
    ("DEBT-04", "high", _rx(r"\b(md5|sha1|sha256)\s*\(\s*[^)]*(?:password|passwd|pwd|contrase(?:n|ñ)a|clave)\b"), "fast hash applied to a password"),
    ("DEBT-04", "high", _rx(r"\b(?:user|usuario|row|record|registro|stored|account|cuenta|result|db_user|found)\w*(?:\.|\[['\"])(?:password|passwd|pwd|contrase(?:n|ñ)a|clave)['\"]?\]?\s*[!=]==?\s*[\w.\[\]'\"]*(?:password|passwd|pwd|contrase(?:n|ñ)a|clave)|(?:password|passwd|pwd|contrase(?:n|ñ)a|clave)[\w.\[\]'\"]*\s*[!=]==?\s*(?:user|usuario|row|record|registro|stored|account|cuenta|result|db_user|found)\w*(?:\.|\[['\"])(?:password|passwd|pwd|contrase(?:n|ñ)a|clave)"),
     "password compared in clear (stored without a hash)"),
    # DEBT-05 JWT
    ("DEBT-05", "high", _rx(r"verify_signature['\"]?\s*:\s*False"), "JWT decoded with signature verification off"),
    ("DEBT-05", "high", _rx(r"jwt\.decode\([^)]*verify\s*=\s*False"), "JWT decoded with verification off"),
    ("DEBT-05", "high", _rx(r"algorithms\s*[=:]\s*\[\s*['\"]none['\"]"), "JWT accepts alg 'none'"),
    ("DEBT-05", "high", _rx(r"jwt\.decode\(\s*[^,)]+\)\s*(?![.,])", re.I), "jwt.decode without verification (jsonwebtoken decode does not verify)"),
    ("DEBT-05", "high", _rx(r"jwt\.(?:sign|encode|verify|decode)\([^)]*,\s*['\"]([^'\"]{0,20})['\"]"), "JWT signed or verified with a short literal secret"),
    # DEBT-06 randomness for secrets
    ("DEBT-06", "medium", _rx(r"(token|otp|code|codigo|reset|session|secret|password|clave|nonce|salt|pin)\w*\s*[:=][^\n;]{0,60}Math\.random\("), "Math.random() used for a security value"),
    ("DEBT-06", "medium", _rx(r"(token|otp|code|codigo|reset|session|secret|password|clave|nonce|salt|pin)\w*\s*=[^\n]{0,60}\brandom\.(random|randint|choice|choices|randrange)\("), "random module used for a security value (use secrets)"),
    # DEBT-07 crypto misuse
    ("DEBT-07", "high", _rx(r"AES\.MODE_ECB|aes-\d{3}-ecb|['\"]AES/ECB"), "AES in ECB mode"),
    ("DEBT-07", "high", _rx(r"crypto\.createCipher\(", 0), "createCipher derives key and IV without salt (deprecated)"),
    ("DEBT-07", "high", _rx(r"\biv\s*=\s*(?:b['\"][^'\"]{8,}['\"]|Buffer\.from\(\s*['\"][^'\"]{8,}['\"]|['\"][^'\"]{16}['\"])"), "fixed IV literal"),
    ("DEBT-07", "medium", _rx(r"\b(DES|RC4|ARC4|Blowfish)\.new\(|['\"](des-ede|des-cbc|rc4)['\"]"), "broken cipher"),
    # DEBT-10 debug / CORS
    ("DEBT-10", "medium", _rx(r"\.run\([^)]*debug\s*=\s*True"), "Flask/werkzeug debug server (remote code execution through the debugger)"),
    ("DEBT-10", "medium", _rx(r"^\s*DEBUG\s*=\s*True\b", re.M), "DEBUG = True in settings"),
    ("DEBT-10", "medium", _rx(r"origin\s*:\s*['\"]\*['\"][^}]{0,80}credentials\s*:\s*true|credentials\s*:\s*true[^}]{0,80}origin\s*:\s*['\"]\*['\"]", re.I | re.S), "CORS wildcard origin with credentials"),
    ("DEBT-10", "medium", _rx(r"CORS\([^)]*supports_credentials\s*=\s*True[^)]*\)|CORS\([^)]*origins\s*=\s*['\"]\*['\"][^)]*supports_credentials", re.I), "CORS with credentials for any origin"),
    # DEBT-11 secrets into logs
    ("DEBT-11", "medium", _rx(r"(console\.(log|info|debug)|print|logger?\.(info|debug|warning|warn|error)|logging\.(info|debug|warning|error))\s*\([^)\n]*(?:[(,+{]|\$\{)\s*(?:[\w]+\.)*(password|passwd|contrasena|clave|token|api_?key|secret|authorization|card_?number|cvv)\b\s*[)}\],+]"), "credential or token written to a log"),
    # DEBT-12 TLS off
    ("DEBT-12", "high", _rx(r"\b(?:requests|session|httpx|client|urllib3|aiohttp)\w*\.\w+\([^)]*verify\s*=\s*False|\bverify_ssl\s*=\s*False|ssl\s*=\s*False", 0), "HTTP request made with certificate verification off"),
    ("DEBT-12", "high", _rx(r"rejectUnauthorized\s*:\s*false", 0), "TLS client accepts any certificate"),
    ("DEBT-12", "high", _rx(r"NODE_TLS_REJECT_UNAUTHORIZED\s*=?\s*['\"]?0", 0), "TLS verification disabled for the whole process"),
    ("DEBT-12", "high", _rx(r"ssl\._create_unverified_context|CERT_NONE", 0), "unverified TLS context"),
]


def probe_code(rel: str, text: str, out: List[dict]) -> None:
    if EXAMPLE_FILE.search(rel) or TEST_PATH.search(rel):
        return
    suffix = Path(rel).suffix.lower()
    if suffix in {".md", ".txt", ".json", ".sql", ".rules", ".xml"}:
        return
    for cls, sev, rx, what in CODE_PROBES:
        for m in rx.finditer(text):
            if comment_line(text, m.start()):
                continue
            if cls == "DEBT-05" and "short literal secret" in what:
                secret = m.group(1)
                if PLACEHOLDER.search(secret) or len(secret) >= 20:
                    continue
                evidence = f"{what}: {redact(secret) if secret else 'empty string'}"
            else:
                evidence = what
            snippet = re.sub(r"\s+", " ", m.group(0))[:80]
            out.append(finding(cls, sev, rel, line_of(text, m.start()), evidence, snippet))


# --------------------------------------------------------------------------- agent configuration

AGENT_CONFIG = re.compile(r"(^|/)(\.mcp\.json|mcp\.json|claude_desktop_config\.json|\.cursor/mcp\.json|"
                          r"\.claude/settings(\.local)?\.json|\.vscode/mcp\.json|\.gemini/settings\.json)$")


def probe_agent_config(rel: str, text: str, out: List[dict]) -> None:
    if not AGENT_CONFIG.search(rel):
        return
    if re.search(r"dangerously-skip-permissions|bypassPermissions|\"defaultMode\"\s*:\s*\"bypass", text):
        out.append(finding("DEBT-08", "high", rel, 1, "agent permissions bypassed in a committed config", "bypass"))
    if re.search(r"curl[^\"\n]*\|\s*(ba)?sh|wget[^\"\n]*\|\s*(ba)?sh", text):
        out.append(finding("DEBT-08", "high", rel, 1, "config pipes a download into a shell", "curlpipe"))
    try:
        data = json.loads(text)
    except Exception:
        return
    servers = data.get("mcpServers") or data.get("servers") or {}
    if not isinstance(servers, dict):
        return
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        env = spec.get("env") or {}
        if isinstance(env, dict):
            for k, v in env.items():
                if isinstance(v, str) and len(v) >= 12 and not v.startswith("${") and not PLACEHOLDER.search(v) \
                        and re.search(r"KEY|TOKEN|SECRET|PASSWORD|ROLE", k, re.I):
                    out.append(finding("DEBT-08", "high", rel, 1,
                                       f"MCP server '{name}' carries {k} inline {redact(v)}", f"env:{name}:{k}"))
        args = spec.get("args") or []
        if isinstance(args, list) and "-y" in args:
            pkgs = [a for a in args if isinstance(a, str) and not a.startswith("-")]
            if pkgs and "@" not in pkgs[0].lstrip("@"):
                out.append(finding("DEBT-08", "medium", rel, 1,
                                   f"MCP server '{name}' runs '{pkgs[0]}' with npx -y and no pinned version", f"npx:{name}"))


# --------------------------------------------------------------------------- dependencies

def probe_deps(ctx: Ctx, out: List[dict], ran: set) -> None:
    for pj in ctx.root.rglob("package.json"):
        rel = ctx.rel(pj)
        if any(part in SKIP_DIRS for part in pj.parts):
            continue
        try:
            data = json.loads(pj.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        deps = {**(data.get("dependencies") or {}), **(data.get("devDependencies") or {})}
        if not deps:
            continue
        ran.add("DEBT-09")
        here = pj.parent
        locks = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock", "npm-shrinkwrap.json")
        if not any((here / f).exists() for f in locks):
            out.append(finding("DEBT-09", "low", rel, 1, f"{len(deps)} npm dependencies and no lockfile", "nolock"))
        for name, ver in deps.items():
            if isinstance(ver, str) and ver.strip() in {"*", "latest", ""}:
                out.append(finding("DEBT-09", "medium", rel, 1, f"'{name}' resolves to whatever is newest ('{ver}')", f"float:{name}"))
    for req in ctx.root.rglob("requirements*.txt"):
        if any(part in SKIP_DIRS for part in req.parts):
            continue
        lines = [l.strip() for l in req.read_text(encoding="utf-8", errors="replace").splitlines()
                 if l.strip() and not l.strip().startswith(("#", "-"))]
        if not lines:
            continue
        ran.add("DEBT-09")
        loose = [l for l in lines if "==" not in l and "@" not in l]
        if loose and len(loose) == len(lines):
            out.append(finding("DEBT-09", "low", ctx.rel(req), 1,
                               f"none of {len(lines)} Python requirements is pinned", "pyloose"))


# --------------------------------------------------------------------------- scan

def ignored_files(root: Path) -> set:
    """Files git would not ship. Without git, the root .gitignore's simple basename patterns."""
    try:
        r = subprocess.run(["git", "-C", str(root), "ls-files", "--others", "--ignored", "--exclude-standard"],
                           capture_output=True, text=True, timeout=30)
        if r.returncode == 0 and (root / ".git").exists():
            return set(l for l in r.stdout.splitlines() if l)
    except Exception:
        pass
    gi = root / ".gitignore"
    if not gi.exists():
        return set()
    import fnmatch
    pats = [l.strip().lstrip("/") for l in gi.read_text(encoding="utf-8", errors="replace").splitlines()
            if l.strip() and not l.strip().startswith(("#", "!")) and "/" not in l.strip().lstrip("/").rstrip("/")]
    hits = set()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for n in filenames:
            if any(fnmatch.fnmatch(n, pt) for pt in pats):
                hits.add((Path(dirpath) / n).relative_to(root).as_posix())
    return hits


def scan(root: Path) -> Tuple[List[dict], Dict[str, str]]:
    ctx = Ctx(root)
    out: List[dict] = []
    ran = set()
    saw = {"agent": False}
    ignored = ignored_files(root)
    for fp in iter_files(root):
        rel = ctx.rel(fp)
        if rel in ignored:
            continue  # a file git ignores is not shipped; a local .env kept out of git is the right practice
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        probe_secrets(ctx, rel, text, out)
        probe_code(rel, text, out)
        if AGENT_CONFIG.search(rel):
            saw["agent"] = True
            probe_agent_config(rel, text, out)
    probe_deps(ctx, out, ran)
    coverage = {}
    for cls in CLASSES:
        coverage[cls] = "ran"
    if not saw["agent"]:
        coverage["DEBT-08"] = "no input (no agent configuration file)"
    if "DEBT-09" not in ran:
        coverage["DEBT-09"] = "no input (no package.json or requirements with dependencies)"
    coverage["DEBT-N1"] = "not run (network probe is opt-in: --network after `ehs debt init`)"
    # de-duplicate by id, keep first
    uniq: Dict[str, dict] = {}
    for f in out:
        uniq.setdefault(f["id"], f)
    return sorted(uniq.values(), key=lambda f: (-SEVERITIES[f["severity"]], f["file"], f["line"])), coverage


# --------------------------------------------------------------------------- network probe (opt-in, scope-checked)

def load_scope(root: Path) -> Optional[dict]:
    p = root / LEDGER_DIR / SCOPE_FILE
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        raise ScopeError(f"{p} is not valid JSON; refusing to guess what it authorizes.")


def host_referenced(root: Path, host: str) -> bool:
    for fp in iter_files(root):
        if LEDGER_DIR in fp.relative_to(root).parts:
            continue
        try:
            if host in fp.read_text(encoding="utf-8", errors="replace"):
                return True
        except OSError:
            continue
    return False


def _is_loopback(host: str) -> bool:
    return host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".localhost")


def network_probe(root: Path, coverage: Dict[str, str], out: List[dict], max_tables: int = 25) -> None:
    scope = load_scope(root)
    if not scope or not scope.get("attestation"):
        raise ScopeError("No ownership attestation in .ehs/scope.json. Run `ehs debt init <dir> --owner NAME "
                         "--host HOST --i-own-this` first; the network probe never runs without it.")
    allowed = set(scope.get("hosts") or [])
    texts = []
    for fp in iter_files(root):
        if LEDGER_DIR in fp.relative_to(root).parts:
            continue
        try:
            texts.append(fp.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            pass
    blob = "\n".join(texts)
    urls = set(re.findall(r"https?://[a-z0-9.\-]+\.supabase\.co|http://(?:localhost|127\.0\.0\.1):\d+", blob, re.I))
    anon = None
    for m in JWT_RE.finditer(blob):
        if jwt_role(m.group(1)) == "anon":
            anon = m.group(1)
            break
    tables = sorted(set(re.findall(r"\.from\(\s*['\"]([a-zA-Z_][a-zA-Z0-9_]*)['\"]\s*\)", blob)))[:max_tables]
    if not urls or not anon or not tables:
        coverage["DEBT-N1"] = "not run (no Supabase URL, anon key or table reference inside the repository)"
        return
    probed = 0
    for base in sorted(urls):
        host = urllib.parse.urlparse(base).hostname or ""
        if host not in allowed:
            coverage["DEBT-N1"] = f"refused for {host}: not listed in .ehs/scope.json"
            continue
        if not _is_loopback(host) and not base.lower().startswith("https://"):
            coverage["DEBT-N1"] = f"refused for {host}: plain http to a non-local host"
            continue
        for t in tables:
            req = urllib.request.Request(f"{base}/rest/v1/{urllib.parse.quote(t)}?select=*&limit=1", method="GET",
                                         headers={"apikey": anon, "Authorization": f"Bearer {anon}",
                                                  "Accept": "application/json", "User-Agent": "ehs-debt-probe"})
            status, rows = None, None
            try:
                with urllib.request.urlopen(req, timeout=10) as r:  # nosec - host checked against the attestation
                    status = r.status
                    body = r.read(65536)
                    try:
                        data = json.loads(body)
                        rows = len(data) if isinstance(data, list) else None
                    except Exception:
                        rows = None
            except urllib.error.HTTPError as e:
                status = e.code
            except Exception:
                status = "error"
            probed += 1
            if status == 200 and rows:
                # status and a count only: the row itself is never read into the report
                out.append(finding("DEBT-N1", "high", f"{host}/rest/v1/{t}", 0,
                                   "anonymous read returned data (row content not recorded)", f"anon:{host}:{t}"))
            time.sleep(1.0)
    if probed:
        coverage["DEBT-N1"] = f"ran: {probed} read-only request(s), limit 1, row content never recorded"


# --------------------------------------------------------------------------- ledger

def now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def git_head(root: Path) -> Optional[str]:
    try:
        r = subprocess.run(["git", "-C", str(root), "rev-parse", "--short", "HEAD"],
                           capture_output=True, text=True, timeout=10)
        return r.stdout.strip() or None if r.returncode == 0 else None
    except Exception:
        return None


def ledger_path(root: Path) -> Path:
    return root / LEDGER_DIR / LEDGER_FILE


def read_ledger(root: Path) -> dict:
    p = ledger_path(root)
    if not p.exists():
        return {"schema": SCHEMA, "items": {}, "runs": []}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        raise ScopeError(f"{p} is not readable JSON ({e}); not overwriting a ledger I cannot read.")
    if data.get("schema") != SCHEMA:
        raise ScopeError(f"{p} has schema {data.get('schema')}, this tool writes {SCHEMA}.")
    return data


def update_ledger(root: Path, findings: List[dict], coverage: Dict[str, str]) -> dict:
    led = read_ledger(root)
    items = led["items"]
    stamp, head = now(), git_head(root)
    seen = set()
    transitions = {"new": 0, "still_open": 0, "closed": 0, "regression_detected": 0}
    for f in findings:
        seen.add(f["id"])
        it = items.get(f["id"])
        if it is None:
            items[f["id"]] = {**f, "status": "open", "first_seen": stamp, "last_seen": stamp,
                              "history": [{"at": stamp, "commit": head, "status": "open"}]}
            transitions["new"] += 1
        else:
            if it["status"] == "closed":
                it["status"] = "regression_detected"
                transitions["regression_detected"] += 1
                it["history"].append({"at": stamp, "commit": head, "status": "regression_detected"})
            else:
                transitions["still_open"] += 1
                if it["status"] == "regression_detected":
                    pass
                else:
                    it["status"] = "open"
            it.update({k: f[k] for k in ("severity", "file", "line", "evidence")})
            it["last_seen"] = stamp
    for iid, it in items.items():
        if iid in seen or it["status"] == "closed":
            continue
        cov = coverage.get(it["class"], "ran")
        if cov != "ran" and not cov.startswith("ran"):
            continue  # a probe that did not run cannot close anything
        it["status"] = "closed"
        it["closed_at"] = stamp
        it["closed_means"] = "no longer detected by the probe; not verified fixed"
        it["history"].append({"at": stamp, "commit": head, "status": "closed"})
        transitions["closed"] += 1
    led["runs"].append({"at": stamp, "commit": head, "coverage": coverage, "transitions": transitions})
    led["runs"] = led["runs"][-50:]
    p = ledger_path(root)
    p.parent.mkdir(exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(led, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(p)
    gi = p.parent / ".gitignore"
    if not gi.exists():
        gi.write_text("# the ledger holds no secret values; the scope attestation is yours to commit or not\n*.tmp\n",
                      encoding="utf-8")
    return transitions


# --------------------------------------------------------------------------- output

def print_report(root: Path, findings: List[dict], coverage: Dict[str, str], fmt: str,
                 transitions: Optional[dict] = None) -> None:
    if fmt == "json":
        print(json.dumps({"target": root.name, "findings": findings, "coverage": coverage,
                          "transitions": transitions}, indent=1, ensure_ascii=False))
        return
    print(f"=== ehs debt — {root.name} ===")
    print("SCOPE : the local checkout above; static probes, nothing executed, nothing sent")
    print("OUT   : whether the app is secure. A probe that sees nothing has not proven absence.")
    print()
    by_cls: Dict[str, List[dict]] = {}
    for f in findings:
        by_cls.setdefault(f["class"], []).append(f)
    for cls, (title, proc) in CLASSES.items():
        fs = by_cls.get(cls, [])
        cov = coverage.get(cls, "ran")
        state = f"{len(fs)} open" if fs else ("nothing seen" if cov.startswith("ran") else "UNKNOWN")
        print(f"{cls}  {title}  [{proc}]  -> {state}")
        if not cov.startswith("ran"):
            print(f"         {cov}")
        for f in fs[:20]:
            print(f"         {f['severity']:<6} {f['file']}:{f['line']}  {f['evidence']}")
        if len(fs) > 20:
            print(f"         ... and {len(fs) - 20} more")
    if transitions:
        print()
        print("LEDGER: " + " · ".join(f"{k} {v}" for k, v in transitions.items()) +
              f"  ({LEDGER_DIR}/{LEDGER_FILE})")
    print()
    print("Closing an item: fix it, add a test that fails without the fix, re-run. `closed` means the probe no")
    print("longer sees it; the squad's verifier, or your test, is what makes it verified.")


# --------------------------------------------------------------------------- commands

def cmd_scan(a: argparse.Namespace) -> int:
    root = resolve_target(a.target)
    findings, coverage = scan(root)
    if a.network:
        network_probe(root, coverage, findings)
    transitions = update_ledger(root, findings, coverage) if a.ledger else None
    print_report(root, findings, coverage, a.format, transitions)
    bar = SEVERITIES[a.fail_on]
    return 1 if any(SEVERITIES[f["severity"]] >= bar for f in findings) else 0


def cmd_status(a: argparse.Namespace) -> int:
    root = resolve_target(a.target)
    led = read_ledger(root)
    if not led["items"]:
        print("no ledger yet: run `ehs debt scan <dir> --ledger`")
        return 2
    counts: Dict[str, int] = {}
    for it in led["items"].values():
        counts[it["status"]] = counts.get(it["status"], 0) + 1
    last = led["runs"][-1] if led["runs"] else {}
    print(f"=== ehs debt ledger — {root.name} ===")
    print("last run: " + str(last.get("at")) + " at commit " + str(last.get("commit")))
    print(" · ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    for it in sorted(led["items"].values(), key=lambda i: (i["status"] != "regression_detected", i["status"] != "open",
                                                          -SEVERITIES[i["severity"]])):
        if it["status"] in ("open", "regression_detected"):
            print(f"  {it['status']:<20} {it['severity']:<6} {it['class']} {it['file']}:{it['line']}  {it['evidence']}")
    unknown = {k: v for k, v in (last.get("coverage") or {}).items() if not str(v).startswith("ran")}
    for k, v in unknown.items():
        print(f"  UNKNOWN {k}: {v}")
    return 1 if counts.get("open") or counts.get("regression_detected") else 0


def cmd_init(a: argparse.Namespace) -> int:
    root = resolve_target(a.target)
    if not a.i_own_this:
        raise ScopeError("Refusing without --i-own-this: the attestation is the reason the network probe may run.")
    hosts = []
    for h in a.host or []:
        h = h.strip().lower()
        if "/" in h or ":" in h and not h.startswith("["):
            h = urllib.parse.urlparse(h if "://" in h else "https://" + h).hostname or h
        if not host_referenced(root, h):
            raise ScopeError(f"'{h}' is not referenced anywhere in this repository. A host the code does not "
                             "talk to is not this repository's to probe.")
        hosts.append(h)
    p = root / LEDGER_DIR / SCOPE_FILE
    p.parent.mkdir(exist_ok=True)
    p.write_text(json.dumps({
        "attestation": f"{a.owner} states that they own, or are authorized to test, this repository and the hosts listed.",
        "owner": a.owner, "at": now(), "hosts": hosts,
        "limits": "read-only GET, limit 1 per table, 1 request per second, row content never recorded",
    }, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {LEDGER_DIR}/{SCOPE_FILE}: hosts {hosts or 'none'}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="ehs debt", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd")
    s = sub.add_parser("scan", help="run the probes on a local checkout you own")
    s.add_argument("target")
    s.add_argument("--ledger", action="store_true", help="record the result in <target>/.ehs/debt.json")
    s.add_argument("--network", action="store_true", help="also run the opt-in Supabase anon-read probe (needs `init`)")
    s.add_argument("--format", choices=("text", "json"), default="text")
    s.add_argument("--fail-on", choices=tuple(SEVERITIES), default="high")
    st = sub.add_parser("status", help="show what the ledger holds")
    st.add_argument("target")
    i = sub.add_parser("init", help="write the ownership attestation the network probe requires")
    i.add_argument("target")
    i.add_argument("--owner", required=True)
    i.add_argument("--host", action="append")
    i.add_argument("--i-own-this", action="store_true")
    a = ap.parse_args(argv)
    if not a.cmd:
        ap.print_help()
        return 2
    try:
        return {"scan": cmd_scan, "status": cmd_status, "init": cmd_init}[a.cmd](a)
    except ScopeError as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
