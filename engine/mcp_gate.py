"""
MCP / AI-Agent Pre-Deployment Gate
===================================
Static security review for an MCP server (or any AI agent) BEFORE it gets
permission to run inside an organization. Returns a verdict
(`approve` | `request_changes` | `block`) plus a structured list of
findings, each one tagged with severity, evidence, and remediation.

Five layers of review (no live execution required):

    1. Static manifest         signed binary?, publisher, transport
    2. Auth posture            categorize how the MCP authenticates,
                               where its secrets live
    3. Permission-vs-purpose   declared tools vs inferred capabilities
    4. Tool-poisoning scan     hidden instruction tokens, zero-width
                               chars, base64 blobs in tool descriptions
    5. Secret exposure         plaintext API keys / tokens in env

A behavioral probe (sandboxed runtime exercise) is intentionally out of
scope for v1 — those five static layers catch the majority of real
issues with no Docker / netns dependency.

Persists results to Neo4j as :McpApproval (one per review) and
:McpFinding (one per surfaced issue).

Public API:
    review_config(server)       -> McpReview
    review_inventory()          -> list[McpReview]   (uses ingest.inventory.mcp)
    shadow_check(approved)      -> dict              (diff installed vs approved)
    persist(review)             -> None
    list_approvals()            -> list[dict]
    get_approval(target_name)   -> dict | None
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Iterable

from .graph import run_read, run_write
from .phi_detector import has_phi


Verdict = str  # 'approve' | 'request_changes' | 'block'
Severity = str  # 'critical' | 'high' | 'medium' | 'low' | 'info'

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class McpFinding:
    check_id: str
    severity: Severity
    title: str
    description: str
    evidence: str = ""
    remediation: str = ""


@dataclass
class McpReview:
    target_name: str
    target_hash: str
    findings: list[McpFinding] = field(default_factory=list)
    auth_method: str = "unknown"  # none | api_key | oauth | mtls | signed | unknown
    inferred_permissions: list[str] = field(default_factory=list)
    declared_tools: list[str] = field(default_factory=list)
    transport: str = ""           # stdio | sse | http | ws | unknown
    reviewed_at: str = ""
    verdict: Verdict = "approve"

    def add(self, *args, **kwargs) -> None:
        if args and isinstance(args[0], McpFinding):
            self.findings.append(args[0])
        else:
            self.findings.append(McpFinding(*args, **kwargs))

    def worst_severity(self) -> Severity:
        if not self.findings:
            return "info"
        return max(self.findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 0)).severity


# ---------------------------------------------------------------------------
# Static manifest review
# ---------------------------------------------------------------------------
_TRUSTED_LAUNCHERS = {"npx", "uvx", "uv", "pipx", "pnpm", "yarn", "bun"}
_RAW_SCRIPT_EXT = (".py", ".sh", ".bash", ".js", ".mjs", ".ts", ".rb", ".pl")
_RISKY_LAUNCHERS = {"bash", "sh", "zsh", "powershell", "pwsh", "cmd", "wsl"}


def _check_static_manifest(server: dict, review: McpReview) -> None:
    cmd = (server.get("command") or "").strip()
    args = list(server.get("args") or [])
    cmd_l = cmd.lower()
    base = os.path.basename(cmd_l)

    # No command at all + no URL = malformed
    if not cmd and not server.get("url"):
        review.add("static.no_entrypoint", "high",
                   "No command or URL declared",
                   "MCP config has neither command nor url; cannot run.",
                   evidence=json.dumps(server)[:300],
                   remediation="Declare command + args (stdio transport) or url (sse/http transport).")
        return

    # Generic shell launcher = arbitrary command via args
    if base in _RISKY_LAUNCHERS:
        review.add("static.shell_launcher", "high",
                   f"Launched via raw shell ({base})",
                   "MCP launches via a generic shell so its real entrypoint "
                   "is whatever the args evaluate to. Review behavior is "
                   "limited to the static args at this point.",
                   evidence=f"{cmd} {' '.join(map(str, args))}"[:300],
                   remediation="Replace with a direct executable or trusted "
                               "launcher (npx/uvx/uv/pipx) so the entrypoint is auditable.")

    # Raw script invocation (dev / unsigned territory)
    is_raw_script = any(str(a).lower().endswith(_RAW_SCRIPT_EXT) for a in args) \
        or cmd_l.endswith(_RAW_SCRIPT_EXT)
    if is_raw_script and base not in _TRUSTED_LAUNCHERS:
        review.add("static.unsigned_script", "medium",
                   "Runs a raw script (likely unsigned)",
                   "Direct .py/.sh/.js execution skips ecosystem signing "
                   "and trusted-launcher checks.",
                   evidence=f"{cmd} {' '.join(map(str, args))}"[:300],
                   remediation="Package the MCP as an npm/PyPI/cargo distribution "
                               "and launch via npx/uvx/cargo so provenance is verifiable.")

    # Detect probable publisher from the package coordinate inside args.
    pub = _publisher_from_args(args)
    if pub:
        review.declared_tools  # touch — keep deterministic field order in dump
    else:
        review.add("static.no_publisher", "low",
                   "Could not infer publisher from command/args",
                   "Without an identifiable npm/PyPI/cargo coordinate, trust "
                   "scoring + revocation cannot be enforced.",
                   evidence=f"{cmd} {' '.join(map(str, args))}"[:300],
                   remediation="Use a coordinate-style invocation, e.g. "
                               "`npx @modelcontextprotocol/server-filesystem` "
                               "or `uvx mcp-server-fetch`.")

    review.transport = (server.get("transport")
                        or ("sse" if server.get("url", "").startswith("http") else "stdio"))


def _publisher_from_args(args: list) -> str | None:
    for a in args:
        s = str(a)
        if s.startswith("@") and "/" in s:           # npm scoped
            return s.split("@")[0] + "/" + s.split("/")[1].split("@")[0]
        if "/" in s and not s.startswith(("/", ".", "-")):
            head = s.split("/")[0]
            if re.fullmatch(r"[A-Za-z0-9_\-\.]+", head):
                return s
        if re.fullmatch(r"[a-z0-9_\-]+", s.lower()) and len(s) > 3 and "." not in s:
            # simple pypi/cargo style coordinate
            return s
    return None


# ---------------------------------------------------------------------------
# Auth posture
# ---------------------------------------------------------------------------
_SECRET_KEY_HINTS = ("token", "key", "secret", "password", "credential",
                     "auth", "apikey", "bearer", "session", "cookie")
_OAUTH_KEY_HINTS = ("client_id", "client_secret", "refresh_token", "oauth")


def _check_auth(server: dict, review: McpReview) -> None:
    env = (server.get("env") or {}) if isinstance(server.get("env"), dict) else {}
    env_keys_l = [str(k).lower() for k in env.keys()]
    args_blob = " ".join(str(a) for a in (server.get("args") or [])).lower()
    url = (server.get("url") or "").lower()

    has_oauth = any(any(h in k for h in _OAUTH_KEY_HINTS) for k in env_keys_l)
    has_secret = any(any(h in k for h in _SECRET_KEY_HINTS) for k in env_keys_l)
    has_mtls = any(h in args_blob for h in ("--cert", "--key", "client.crt", "client.pem"))
    is_remote = url.startswith(("http://", "https://", "ws://", "wss://"))

    if has_oauth:
        review.auth_method = "oauth"
    elif has_mtls:
        review.auth_method = "mtls"
    elif has_secret:
        review.auth_method = "api_key"
    elif is_remote:
        review.auth_method = "none"
    else:
        review.auth_method = "none" if not env else "unknown"

    if review.auth_method == "none" and is_remote:
        review.add("auth.remote_no_auth", "critical",
                   "Remote MCP with no authentication",
                   "Remote-transport MCP exposes its tools without "
                   "verifiable authentication. Anyone reaching the URL "
                   "can call its tools.",
                   evidence=f"url={url}",
                   remediation="Require API key, mTLS, or signed JWT. "
                               "Bind to localhost-only if not intentionally remote.")
    elif review.auth_method == "none" and review.transport == "stdio":
        review.add("auth.stdio_no_auth", "low",
                   "stdio MCP with no auth (acceptable for localhost)",
                   "stdio MCPs run as a child process of the host. Auth "
                   "is implicit in OS-level process isolation. Flagged so "
                   "a future move to remote transport gets re-reviewed.",
                   evidence="transport=stdio")

    if url.startswith("http://"):
        review.add("auth.cleartext_transport", "high",
                   "Cleartext HTTP transport",
                   "MCP traffic is unencrypted. Tool inputs/outputs are "
                   "exposed to any network observer.",
                   evidence=f"url={url}",
                   remediation="Switch to HTTPS / WSS.")

    # Look for plaintext-looking secrets directly in env values (not just keys)
    for k, v in env.items():
        if not isinstance(v, str) or len(v) < 12:
            continue
        if _looks_like_secret_value(v):
            review.add("auth.plaintext_secret", "critical",
                       f"Plaintext secret in env: {k}",
                       "Config file contains what looks like a real secret "
                       "(API key, token, password) embedded as a string. "
                       "Anyone with read access to the config has the secret.",
                       evidence=f"{k}={_mask(v)}",
                       remediation="Move the secret to OS keystore / 1Password "
                                   "/ Vault and reference via $-expansion or "
                                   "the MCP host's secrets API.")


_SECRET_VALUE_PATTERNS = [
    re.compile(r"^sk-[A-Za-z0-9]{20,}"),                  # OpenAI
    re.compile(r"^xox[baprs]-[A-Za-z0-9-]{10,}"),         # Slack
    re.compile(r"^ghp_[A-Za-z0-9]{30,}"),                 # GitHub PAT
    re.compile(r"^gho_[A-Za-z0-9]{30,}"),                 # GitHub OAuth
    re.compile(r"^ghs_[A-Za-z0-9]{30,}"),                 # GitHub server
    re.compile(r"^github_pat_[A-Za-z0-9_]{30,}"),         # GitHub fine-grained
    re.compile(r"^AKIA[0-9A-Z]{16}$"),                    # AWS access key id
    re.compile(r"^AIza[0-9A-Za-z_-]{30,}"),               # Google API key
    re.compile(r"^sk-ant-[A-Za-z0-9_-]{20,}"),            # Anthropic
    re.compile(r"^[A-Za-z0-9+/=]{40,}={0,2}$"),           # generic base64-ish blob
]


def _looks_like_secret_value(s: str) -> bool:
    if any(p.match(s) for p in _SECRET_VALUE_PATTERNS):
        return True
    # JWT shape: three base64-url segments separated by dots
    if s.count(".") == 2 and all(re.fullmatch(r"[A-Za-z0-9_\-=]+", p)
                                 for p in s.split(".")):
        return True
    return False


def _mask(v: str) -> str:
    if len(v) <= 8:
        return "***"
    return v[:4] + "…" + v[-4:]


# ---------------------------------------------------------------------------
# Permission-vs-purpose diff
# ---------------------------------------------------------------------------
# What a tool *implies* it should be allowed to do, by category.
_TOOL_NAME_TO_NEEDED_PERMS: list[tuple[re.Pattern[str], set[str]]] = [
    (re.compile(r"\b(?:read|get|list|search|find|fetch|describe|show)\b", re.I),
        {"read"}),
    (re.compile(r"\b(?:write|create|put|update|edit|set|patch)\b", re.I),
        {"write"}),
    (re.compile(r"\b(?:delete|remove|drop|destroy|purge|rm)\b", re.I),
        {"write", "destructive"}),
    (re.compile(r"\b(?:exec|run|shell|spawn|invoke|command)\b", re.I),
        {"shell"}),
    (re.compile(r"\b(?:fetch|http|request|browse|crawl|api)\b", re.I),
        {"network.outbound"}),
    (re.compile(r"\b(?:file|fs|path|directory|folder)\b", re.I),
        {"filesystem"}),
]


def _needed_perms_for_tool(tool_name: str, description: str = "") -> set[str]:
    needed: set[str] = set()
    for pat, perms in _TOOL_NAME_TO_NEEDED_PERMS:
        if pat.search(tool_name) or (description and pat.search(description)):
            needed |= perms
    return needed


def _check_permission_diff(server: dict, review: McpReview) -> None:
    inferred = set(server.get("permissions") or _infer_permissions_from_command(server))
    review.inferred_permissions = sorted(inferred)
    tools = server.get("tools") or []
    if not tools:
        # Without tool list, we can only flag obviously-broad permissions.
        if "shell" in inferred and "filesystem.write" in inferred and "network.outbound" in inferred:
            review.add("perm.triple_threat", "high",
                       "Shell + filesystem-write + outbound network",
                       "MCP holds the three capabilities most commonly chained "
                       "in supply-chain attacks (run code, write files, exfiltrate).",
                       evidence=str(sorted(inferred)),
                       remediation="Split into multiple smaller MCPs or drop one of the three.")
        return

    review.declared_tools = [t.get("name", "") for t in tools if isinstance(t, dict)]
    needed_union: set[str] = set()
    for t in tools:
        if not isinstance(t, dict):
            continue
        needed_union |= _needed_perms_for_tool(t.get("name", ""),
                                               t.get("description", ""))

    # capability vocabulary normalization
    inferred_norm = _normalize_caps(inferred)
    needed_norm = _normalize_caps(needed_union) | {"read"}  # read is implicit baseline

    excess = inferred_norm - needed_norm
    if excess:
        review.add("perm.over_broad", "high",
                   "Granted permissions exceed what declared tools imply",
                   "MCP holds capabilities its tool descriptions do not appear "
                   "to need. Extra capability = extra blast radius.",
                   evidence=f"inferred={sorted(inferred_norm)} "
                            f"needed_by_tools={sorted(needed_norm)} "
                            f"excess={sorted(excess)}",
                   remediation="Remove the excess capabilities, or add tool "
                               "descriptions that justify them.")


def _normalize_caps(caps: Iterable[str]) -> set[str]:
    out = set()
    for c in caps:
        c = c.lower()
        if c.startswith("filesystem"):
            out.add("filesystem")
            if "write" in c:
                out.add("write")
            else:
                out.add("read")
        elif c == "shell":
            out.update({"shell", "filesystem", "write", "network.outbound"})
        elif c.startswith("network"):
            out.add("network.outbound")
        elif c == "credentials":
            out.add("credentials")
        else:
            out.add(c)
    return out


def _infer_permissions_from_command(server: dict) -> list[str]:
    """Mirror the heuristic in ingest/inventory/mcp.py."""
    perms: list[str] = []
    cmd = " ".join([server.get("command", "")] +
                   list(server.get("args", []) or [])).lower()
    env = " ".join((server.get("env", {}) or {}).keys()).lower()
    if any(p in cmd for p in ("sh ", "bash", "powershell", "cmd ", "exec")):
        perms.append("shell")
    if any(p in cmd for p in ("write", "filesystem", "fs-write", "edit", "modify")):
        perms.append("filesystem.write")
    if (any(p in cmd for p in ("filesystem", "files", "fs-read"))
            and "filesystem.write" not in perms):
        perms.append("filesystem.read")
    if any(p in cmd for p in ("http", "fetch", "browser", "scrape", "api")):
        perms.append("network.outbound")
    if any(s in env for s in _SECRET_KEY_HINTS):
        perms.append("credentials")
    if "url" in server and isinstance(server["url"], str):
        perms.append("network.outbound")
    return perms


# ---------------------------------------------------------------------------
# Tool-poisoning scan (Invariant Labs class of attacks)
# ---------------------------------------------------------------------------
_POISON_PATTERNS = [
    (re.compile(r"<\s*(?:system|important|override|instruction[s]?|admin|"
                r"developer|context|secret|hidden|prompt)\s*>",
                re.IGNORECASE),
     "Hidden instruction tag in tool description"),
    (re.compile(r"\[\s*(?:INST|SYSTEM|IMPORTANT|OVERRIDE|RULE)\s*\]",
                re.IGNORECASE),
     "Instruction-style bracket tag"),
    (re.compile(r"^\s*###\s+(?:system|instructions?|rules?)",
                re.IGNORECASE | re.MULTILINE),
     "Heading-style instruction injection"),
    (re.compile(r"\bignore\s+(?:previous|all|prior|the)\s+(?:instructions?|prompts?|rules?)",
                re.IGNORECASE),
     "Classic prompt-override phrasing"),
    (re.compile(r"\bwhen\s+(?:calling|using|invoking)\s+(?:the\s+)?\b\w+\s+(?:tool|function)",
                re.IGNORECASE),
     "Cross-tool instruction (tries to influence other tools)"),
    (re.compile(r"\b(?:exfil|exfiltrate|send\s+to|post\s+to|upload\s+to)\b",
                re.IGNORECASE),
     "Data-exfiltration verb in description"),
]
_ZERO_WIDTH = re.compile(r"[​-‏ - ⁠-⁯﻿]")
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")


def _check_tool_poisoning(server: dict, review: McpReview) -> None:
    tools = server.get("tools") or []
    for t in tools:
        if not isinstance(t, dict):
            continue
        name = t.get("name", "<unnamed>")
        desc = t.get("description", "") or ""

        # Pattern hits
        for pat, label in _POISON_PATTERNS:
            m = pat.search(desc)
            if m:
                review.add("poison.instruction_injection", "critical",
                           f"Tool '{name}' description: {label}",
                           "Tool descriptions are concatenated into the host "
                           "LLM's context. Hidden instructions in the description "
                           "execute as system-level prompts.",
                           evidence=desc[max(0, m.start()-30):m.end()+30],
                           remediation="Remove the hidden tag/phrase from the "
                                       "tool description, or reject this MCP.")
                break  # one finding per tool is enough

        # Zero-width chars
        if _ZERO_WIDTH.search(desc):
            review.add("poison.zero_width", "critical",
                       f"Tool '{name}' description: zero-width characters",
                       "Zero-width / control characters are invisible to humans "
                       "but parsed by the LLM. Common smuggle vector.",
                       evidence=repr(desc[:200]),
                       remediation="Strip U+200B / U+200C / U+200D / U+FEFF / "
                                   "U+2060 from the description.")

        # Suspiciously large base64 blob
        m = _BASE64_BLOB.search(desc)
        if m:
            review.add("poison.base64_blob", "high",
                       f"Tool '{name}' description: large base64 blob",
                       "Long base64-looking blobs in tool descriptions are a "
                       "common payload-smuggling vector.",
                       evidence=m.group(0)[:80] + ("…" if len(m.group(0)) > 80 else ""),
                       remediation="Remove the blob. Don't embed binary data "
                                   "in human-facing descriptions.")

        # Description longer than reasonable
        if len(desc) > 2000:
            review.add("poison.oversize_description", "medium",
                       f"Tool '{name}' description: {len(desc)} chars",
                       "Unusually long tool descriptions consume host LLM "
                       "context budget and are a soft signal of smuggled content.",
                       evidence=f"length={len(desc)}",
                       remediation="Shorten to a one-paragraph human description.")

        # PHI in a tool description = always wrong
        if has_phi(desc):
            review.add("poison.phi_in_description", "critical",
                       f"Tool '{name}' description contains PHI patterns",
                       "Tool descriptions should never contain PHI; presence "
                       "indicates either a copy-paste leak or a prompt-injection "
                       "vector.",
                       evidence="(redacted)",
                       remediation="Remove PHI from the tool description immediately.")


# ---------------------------------------------------------------------------
# Verdict aggregation
# ---------------------------------------------------------------------------
def _aggregate_verdict(review: McpReview) -> Verdict:
    sevs = {f.severity for f in review.findings}
    if "critical" in sevs:
        return "block"
    if "high" in sevs:
        return "request_changes"
    return "approve"


# ---------------------------------------------------------------------------
# Public review function
# ---------------------------------------------------------------------------
def review_config(server: dict) -> McpReview:
    """Run all five static layers against one MCP config dict.

    `server` accepts the same shape that `ingest.inventory.mcp.scan_mcp_servers`
    emits, plus an optional `tools` key (list of {name, description}) for
    runtime-collected tool metadata. Tool metadata is required for the
    poisoning scan; without it we still run the other four layers."""
    name = server.get("name") or server.get("id") or "unknown-mcp"
    blob = json.dumps(server, sort_keys=True, default=str).encode("utf-8", errors="replace")
    target_hash = hashlib.sha256(blob).hexdigest()

    review = McpReview(
        target_name=name,
        target_hash=target_hash,
        reviewed_at=datetime.now(timezone.utc).isoformat(),
    )

    _check_static_manifest(server, review)
    _check_auth(server, review)
    _check_permission_diff(server, review)
    _check_tool_poisoning(server, review)

    review.verdict = _aggregate_verdict(review)
    return review


def review_dict_from_json(text: str) -> McpReview:
    server = json.loads(text)
    if isinstance(server, dict) and "mcpServers" in server:
        # Claude Desktop config; review each entry, return the worst verdict
        merged = McpReview(target_name="claude-desktop-config", target_hash="",
                           reviewed_at=datetime.now(timezone.utc).isoformat())
        for k, v in server["mcpServers"].items():
            v = dict(v); v.setdefault("name", k)
            sub = review_config(v)
            for f in sub.findings:
                merged.findings.append(McpFinding(
                    check_id=f"{k}.{f.check_id}", severity=f.severity,
                    title=f"[{k}] {f.title}", description=f.description,
                    evidence=f.evidence, remediation=f.remediation,
                ))
        merged.verdict = _aggregate_verdict(merged)
        return merged
    return review_config(server)


def review_inventory() -> list[McpReview]:
    """Run review against every MCP server enumerated by the inventory scanner."""
    try:
        from ingest.inventory.mcp import scan_mcp_servers
    except Exception:
        return []
    out: list[McpReview] = []
    try:
        servers = scan_mcp_servers()
    except Exception:
        return out
    for s in servers:
        d = s if isinstance(s, dict) else getattr(s, "__dict__", {})
        if not d:
            continue
        out.append(review_config(d))
    return out


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
def persist(review: McpReview) -> str:
    """Write :McpApproval + :McpFinding nodes. Returns approval id."""
    approval_id = f"mcpapr:{uuid.uuid4().hex[:16]}"
    run_write(
        """
        MERGE (a:McpApproval {id: $aid})
          SET a.target_name = $name,
              a.target_hash = $hash,
              a.status = $verdict,
              a.auth_method = $auth,
              a.transport = $transport,
              a.inferred_permissions = $perms,
              a.declared_tools = $tools,
              a.reviewed_at = datetime($ts),
              a.findings_count = $fcount
        WITH a
        UNWIND $findings AS f
        MERGE (fn:McpFinding {id: f.id})
          SET fn.check_id = f.check_id,
              fn.severity = f.severity,
              fn.title = f.title,
              fn.description = f.description,
              fn.evidence = f.evidence,
              fn.remediation = f.remediation
        MERGE (a)-[:HAS_FINDING]->(fn)
        """,
        aid=approval_id,
        name=review.target_name,
        hash=review.target_hash,
        verdict=review.verdict,
        auth=review.auth_method,
        transport=review.transport,
        perms=review.inferred_permissions,
        tools=review.declared_tools,
        ts=review.reviewed_at,
        fcount=len(review.findings),
        findings=[
            {**asdict(f),
             "id": f"mcpf:{review.target_hash[:12]}:{i}:{f.check_id}"}
            for i, f in enumerate(review.findings)
        ],
    )
    # Tag the corresponding :Application if it exists
    run_write(
        """
        MATCH (app:Application {key: $name})
        SET app.mcp_gate_status = $verdict,
            app.mcp_gate_last_reviewed = datetime($ts)
        """,
        name=review.target_name, verdict=review.verdict, ts=review.reviewed_at,
    )
    return approval_id


def list_approvals(status: str | None = None, limit: int = 200) -> list[dict]:
    if status:
        cypher = """
        MATCH (a:McpApproval) WHERE a.status = $status
        RETURN a.id AS id, a.target_name AS target_name,
               a.status AS status, a.auth_method AS auth_method,
               a.transport AS transport,
               a.findings_count AS findings_count,
               toString(a.reviewed_at) AS reviewed_at
        ORDER BY a.reviewed_at DESC LIMIT $limit
        """
        return run_read(cypher, status=status, limit=limit)
    cypher = """
    MATCH (a:McpApproval)
    RETURN a.id AS id, a.target_name AS target_name,
           a.status AS status, a.auth_method AS auth_method,
           a.transport AS transport,
           a.findings_count AS findings_count,
           toString(a.reviewed_at) AS reviewed_at
    ORDER BY a.reviewed_at DESC LIMIT $limit
    """
    return run_read(cypher, limit=limit)


def get_approval(target_name: str) -> dict | None:
    cypher = """
    MATCH (a:McpApproval {target_name: $name})
    OPTIONAL MATCH (a)-[:HAS_FINDING]->(f:McpFinding)
    WITH a, collect({
      check_id: f.check_id, severity: f.severity, title: f.title,
      description: f.description, evidence: f.evidence,
      remediation: f.remediation
    }) AS findings
    RETURN a.id AS id, a.target_name AS target_name,
           a.status AS status, a.auth_method AS auth_method,
           a.transport AS transport,
           a.inferred_permissions AS inferred_permissions,
           a.declared_tools AS declared_tools,
           a.findings_count AS findings_count,
           toString(a.reviewed_at) AS reviewed_at,
           [f IN findings WHERE f.check_id IS NOT NULL] AS findings
    ORDER BY a.reviewed_at DESC LIMIT 1
    """
    rows = run_read(cypher, name=target_name)
    return rows[0] if rows else None


def shadow_check(approved_names: Iterable[str]) -> dict:
    """Return MCPs in current inventory that are NOT in the approved list."""
    approved = set(approved_names)
    try:
        from ingest.inventory.mcp import scan_mcp_servers
        servers = scan_mcp_servers()
    except Exception as e:
        return {"error": str(e), "shadow": [], "approved": sorted(approved)}
    installed = []
    for s in servers:
        d = s if isinstance(s, dict) else getattr(s, "__dict__", {})
        if d:
            installed.append(d.get("name") or d.get("id") or "unknown")
    shadow = [n for n in installed if n not in approved]
    return {
        "approved_count": len(approved),
        "installed_count": len(installed),
        "shadow_count": len(shadow),
        "installed": sorted(set(installed)),
        "shadow": sorted(set(shadow)),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _cli() -> int:
    import argparse
    import sys
    p = argparse.ArgumentParser(prog="engine.mcp_gate",
                                description="Pre-deployment review for MCP servers")
    sub = p.add_subparsers(dest="cmd", required=True)
    p_rev = sub.add_parser("review", help="Review one MCP config (file or stdin)")
    p_rev.add_argument("--config", help="Path to config JSON (default: stdin)")
    p_rev.add_argument("--persist", action="store_true",
                       help="Persist the review to Neo4j")
    p_inv = sub.add_parser("review-installed",
                           help="Review every MCP currently in inventory")
    p_inv.add_argument("--persist", action="store_true")
    p_list = sub.add_parser("list-approvals", help="List persisted approvals")
    p_list.add_argument("--status", choices=["approve", "request_changes", "block"])
    p_shadow = sub.add_parser("shadow-check",
                              help="Compare installed MCPs against an approved list")
    p_shadow.add_argument("--approved", required=True,
                          help="Path to a YAML/JSON file with an `approved` list of names, "
                               "or comma-separated names directly")

    args = p.parse_args()

    if args.cmd == "review":
        text = (open(args.config, encoding="utf-8").read()
                if args.config else sys.stdin.read())
        review = review_dict_from_json(text)
        print(json.dumps({
            "verdict": review.verdict,
            "target_name": review.target_name,
            "auth_method": review.auth_method,
            "transport": review.transport,
            "inferred_permissions": review.inferred_permissions,
            "declared_tools": review.declared_tools,
            "findings": [asdict(f) for f in review.findings],
        }, indent=2, default=str))
        if args.persist:
            persist(review)
        return 0 if review.verdict == "approve" else 2

    if args.cmd == "review-installed":
        reviews = review_inventory()
        for r in reviews:
            if args.persist:
                persist(r)
        print(json.dumps([{
            "target_name": r.target_name, "verdict": r.verdict,
            "auth_method": r.auth_method,
            "findings": len(r.findings),
            "worst_severity": r.worst_severity(),
        } for r in reviews], indent=2, default=str))
        return 0 if all(r.verdict == "approve" for r in reviews) else 2

    if args.cmd == "list-approvals":
        rows = list_approvals(status=args.status)
        print(json.dumps(rows, indent=2, default=str))
        return 0

    if args.cmd == "shadow-check":
        if os.path.isfile(args.approved):
            text = open(args.approved, encoding="utf-8").read()
            try:
                doc = json.loads(text)
                names = doc.get("approved", []) if isinstance(doc, dict) else doc
            except json.JSONDecodeError:
                # naive YAML: lines with `- name`
                names = [l.strip("- \t") for l in text.splitlines()
                         if l.strip().startswith("-")]
        else:
            names = [s.strip() for s in args.approved.split(",") if s.strip()]
        print(json.dumps(shadow_check(names), indent=2, default=str))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(_cli())


__all__ = [
    "Verdict", "Severity",
    "McpFinding", "McpReview",
    "review_config", "review_dict_from_json", "review_inventory",
    "persist", "list_approvals", "get_approval", "shadow_check",
]
