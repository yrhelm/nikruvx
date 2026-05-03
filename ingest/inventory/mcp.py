"""
MCP server / AI-agent inventory ingester.

Walks the configuration files of the major MCP-enabled tools and
upserts every configured server as an Application{category: mcp_server}.

Sources covered:
    Claude Desktop      claude_desktop_config.json
    Cursor              ~/.cursor/mcp.json (or settings.json)
    Claude Code         ~/.claude/settings.json + per-plugin .mcp.json
    Continue.dev        ~/.continue/config.json
    Zed                 ~/.config/zed/settings.json
    OpenAI ChatGPT app  (no public config file path; left for later)

Each entry yields:
    name, command/url, args, env (minus secrets), implied permissions.
"""
from __future__ import annotations
import json
import os
import platform
from pathlib import Path

from engine.application_model import Application, make_id
from engine.trust_scoring import score_dict, count_high_risk


# ---------------------------------------------------------------------------
# Permission inference -- heuristic but useful
# ---------------------------------------------------------------------------
def _infer_permissions(server: dict) -> list[str]:
    perms: list[str] = []
    cmd = " ".join([server.get("command", "")] + list(server.get("args", []) or []))
    cmd_l = cmd.lower()
    env = " ".join((server.get("env", {}) or {}).keys()).lower()

    if any(p in cmd_l for p in ("sh ", "bash", "powershell", "cmd ", "exec")):
        perms.append("shell")
    if any(p in cmd_l for p in ("write", "filesystem", "fs-write", "edit", "modify")):
        perms.append("filesystem.write")
    if any(p in cmd_l for p in ("filesystem", "files", "fs-read")) and "filesystem.write" not in perms:
        perms.append("filesystem.read")
    if any(p in cmd_l for p in ("http", "fetch", "browser", "scrape", "api")):
        perms.append("network.outbound")
    if any(s in env for s in ("token", "key", "secret", "password", "credential")):
        perms.append("credentials")
    if "url" in server and isinstance(server["url"], str):
        perms.append("network.outbound")
    return perms


# ---------------------------------------------------------------------------
# Per-tool config discovery
# ---------------------------------------------------------------------------
def _claude_desktop_paths() -> list[Path]:
    home = Path.home()
    sysname = platform.system()
    if sysname == "Windows":
        base = Path(os.getenv("APPDATA", str(home / "AppData/Roaming")))
        return [base / "Claude" / "claude_desktop_config.json"]
    if sysname == "Darwin":
        return [home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"]
    return [home / ".config" / "Claude" / "claude_desktop_config.json"]


def _cursor_paths() -> list[Path]:
    home = Path.home()
    return [
        home / ".cursor" / "mcp.json",
        home / ".cursor" / "settings.json",
    ]


def _claude_code_paths() -> list[Path]:
    home = Path.home()
    candidates = [
        home / ".claude" / "settings.json",
        home / ".claude" / "claude.json",
    ]
    candidates.extend(home.glob(".claude/.mcp.json"))
    candidates.extend(home.glob(".claude/plugins/*/.mcp.json"))
    return [p for p in candidates if p.exists()]


def _continue_paths() -> list[Path]:
    return [Path.home() / ".continue" / "config.json"]


def _zed_paths() -> list[Path]:
    home = Path.home()
    sysname = platform.system()
    if sysname == "Windows":
        return [Path(os.getenv("APPDATA", "")) / "Zed" / "settings.json"]
    if sysname == "Darwin":
        return [home / ".config" / "zed" / "settings.json"]
    return [home / ".config" / "zed" / "settings.json"]


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------
def _parse_mcp_servers(servers: dict, source: str) -> list[Application]:
    apps: list[Application] = []
    for name, srv in (servers or {}).items():
        if not isinstance(srv, dict):
            continue
        # Drop env values - keep only key NAMES so we don't ingest secrets
        srv_redacted = {**srv, "env": list((srv.get("env") or {}).keys())}
        perms = _infer_permissions(srv)
        sig = {
            "publisher_verified": False,
            "signed": False,
            "permissions_high_risk": count_high_risk(perms, "mcp_server"),
        }
        s = score_dict(sig)
        publisher = None
        if isinstance(srv.get("command"), str) and "/" in srv["command"]:
            publisher = srv["command"].split("/")[0]
        apps.append(Application(
            id=make_id("mcp_server", source, name),
            name=name, version=None, publisher=publisher,
            source_url=srv.get("url"),
            category="mcp_server", provenance="third_party",
            permissions=perms, trust_signals=sig, trust_score=s["score"],
            raw={"source": source, "config": srv_redacted},
        ))
    return apps


def _read_json_safely(path: Path) -> dict | None:
    try: return json.loads(path.read_text(encoding="utf-8"))
    except Exception: return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def scan_mcp_servers() -> list[Application]:
    apps: list[Application] = []

    # Claude Desktop
    for path in _claude_desktop_paths():
        if not path.exists(): continue
        data = _read_json_safely(path)
        if data:
            apps += _parse_mcp_servers(data.get("mcpServers", {}), "ClaudeDesktop")

    # Cursor
    for path in _cursor_paths():
        if not path.exists(): continue
        data = _read_json_safely(path)
        if data:
            apps += _parse_mcp_servers(data.get("mcpServers", {}), "Cursor")

    # Claude Code (.claude/...)
    for path in _claude_code_paths():
        data = _read_json_safely(path)
        if data:
            apps += _parse_mcp_servers(data.get("mcpServers", {}), f"ClaudeCode/{path.parent.name}")

    # Continue.dev
    for path in _continue_paths():
        if not path.exists(): continue
        data = _read_json_safely(path)
        if data and "mcpServers" in data:
            apps += _parse_mcp_servers(data["mcpServers"], "Continue.dev")

    # Zed
    for path in _zed_paths():
        if not path.exists(): continue
        data = _read_json_safely(path)
        if data and "mcp_servers" in data:
            apps += _parse_mcp_servers(data["mcp_servers"], "Zed")

    by_id: dict[str, Application] = {}
    for a in apps: by_id.setdefault(a.id, a)
    return list(by_id.values())
