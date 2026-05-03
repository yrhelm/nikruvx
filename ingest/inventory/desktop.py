"""
Desktop binary inventory ingester.

Cross-platform:
    Windows  - winget list (preferred), then registry fallback
    macOS    - brew list + /Applications enumeration
    Linux    - dpkg -l / pacman -Q / rpm -qa (whichever is available)

Each installed program becomes an Application{category: desktop_binary}.
"""
from __future__ import annotations
import json
import platform
import re
import shutil
import subprocess
from pathlib import Path

from engine.application_model import Application, make_id
from engine.trust_scoring import score_dict


def _signals(publisher: str | None, version: str | None) -> dict:
    """Best-effort default signals when we don't know much about the binary."""
    return {
        "publisher_verified": bool(publisher),
        "signed": None,           # would need OS-specific code-sign verification
        "install_count": 0,
        "age_days": 0,
        "last_update_days": 0,
    }


def _make_app(name: str, version: str | None, publisher: str | None,
              source_url: str | None = None, raw: dict | None = None) -> Application:
    sig = _signals(publisher, version)
    s = score_dict(sig)
    return Application(
        id=make_id("desktop_binary", publisher or "?", name, version or ""),
        name=name, version=version, publisher=publisher,
        source_url=source_url,
        category="desktop_binary",
        provenance="third_party",
        trust_signals=sig,
        trust_score=s["score"],
        raw=raw or {},
    )


# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------
def _scan_winget() -> list[Application]:
    if not shutil.which("winget"):
        return []
    try:
        # `--accept-source-agreements` to avoid interactive prompt
        out = subprocess.run(
            ["winget", "list", "--accept-source-agreements"],
            capture_output=True, text=True, timeout=120, check=False,
        ).stdout
    except Exception:
        return []

    apps: list[Application] = []
    in_table = False
    for line in out.splitlines():
        if not in_table:
            if line.startswith("---"):
                in_table = True
            continue
        # Columns: Name | Id | Version | Available | Source
        parts = re.split(r"\s{2,}", line.strip())
        if len(parts) < 3:
            continue
        name, pkg_id, version = parts[0], parts[1], parts[2]
        if not name or name.lower() == "name":
            continue
        publisher = pkg_id.split(".")[0] if "." in pkg_id else None
        apps.append(_make_app(name, version, publisher,
                              raw={"source": "winget", "id": pkg_id}))
    return apps


# ---------------------------------------------------------------------------
# macOS
# ---------------------------------------------------------------------------
def _scan_brew() -> list[Application]:
    if not shutil.which("brew"):
        return []
    apps: list[Application] = []
    for cmd, kind in [(["brew", "list", "--versions"], "formula"),
                      (["brew", "list", "--cask", "--versions"], "cask")]:
        try:
            out = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=60, check=False).stdout
        except Exception:
            continue
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            name, version = parts[0], (parts[1] if len(parts) > 1 else None)
            apps.append(_make_app(name, version, "homebrew",
                                  raw={"source": f"brew-{kind}"}))
    return apps


def _scan_macos_applications() -> list[Application]:
    base = Path("/Applications")
    if not base.exists():
        return []
    apps: list[Application] = []
    for app in base.glob("*.app"):
        info_plist = app / "Contents" / "Info.plist"
        name = app.stem
        version = None
        publisher = None
        if info_plist.exists():
            try:
                import plistlib
                pl = plistlib.loads(info_plist.read_bytes())
                name = pl.get("CFBundleDisplayName") or pl.get("CFBundleName") or name
                version = pl.get("CFBundleShortVersionString") or pl.get("CFBundleVersion")
                publisher = pl.get("CFBundleIdentifier", "").split(".")[1] if pl.get("CFBundleIdentifier") else None
            except Exception:
                pass
        apps.append(_make_app(name, version, publisher,
                              raw={"source": "macos_applications", "path": str(app)}))
    return apps


# ---------------------------------------------------------------------------
# Linux
# ---------------------------------------------------------------------------
def _scan_dpkg() -> list[Application]:
    if not shutil.which("dpkg"):
        return []
    try:
        out = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package}\\t${Version}\\t${Maintainer}\\n"],
            capture_output=True, text=True, timeout=60, check=False,
        ).stdout
    except Exception:
        return []
    apps: list[Application] = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            name, version = parts[0], parts[1]
            publisher = parts[2] if len(parts) > 2 else None
            apps.append(_make_app(name, version, publisher,
                                  raw={"source": "dpkg"}))
    return apps


def _scan_pacman() -> list[Application]:
    if not shutil.which("pacman"):
        return []
    try:
        out = subprocess.run(["pacman", "-Q"], capture_output=True, text=True,
                             timeout=30, check=False).stdout
    except Exception:
        return []
    apps: list[Application] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            apps.append(_make_app(parts[0], parts[1], "arch-linux",
                                  raw={"source": "pacman"}))
    return apps


def _scan_rpm() -> list[Application]:
    if not shutil.which("rpm"):
        return []
    try:
        out = subprocess.run(["rpm", "-qa", "--queryformat", "%{NAME}\\t%{VERSION}\\t%{VENDOR}\\n"],
                             capture_output=True, text=True, timeout=60, check=False).stdout
    except Exception:
        return []
    apps: list[Application] = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            name, version = parts[0], parts[1]
            vendor = parts[2] if len(parts) > 2 else None
            apps.append(_make_app(name, version, vendor, raw={"source": "rpm"}))
    return apps


# ---------------------------------------------------------------------------
# scoop (Windows alt package manager)
# ---------------------------------------------------------------------------
def _scan_scoop() -> list[Application]:
    if not shutil.which("scoop"):
        return []
    try:
        out = subprocess.run(["scoop", "list"], capture_output=True, text=True,
                             timeout=30, check=False).stdout
    except Exception:
        return []
    apps: list[Application] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and not parts[0].startswith("-") and parts[0].lower() != "name":
            apps.append(_make_app(parts[0], parts[1], "scoop", raw={"source": "scoop"}))
    return apps


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def scan_desktop() -> list[Application]:
    sysname = platform.system()
    apps: list[Application] = []
    if sysname == "Windows":
        apps += _scan_winget()
        apps += _scan_scoop()
    elif sysname == "Darwin":
        apps += _scan_brew()
        apps += _scan_macos_applications()
    elif sysname == "Linux":
        apps += _scan_dpkg()
        apps += _scan_pacman()
        apps += _scan_rpm()
    # Dedupe by id
    by_id: dict[str, Application] = {}
    for a in apps:
        by_id.setdefault(a.id, a)
    return list(by_id.values())
