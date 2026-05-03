"""
Browser extension inventory ingester.

Walks every Chrome / Edge / Brave / Firefox profile directory on the
current host. Each extension manifest yields name + version + permissions.
Cross-platform: handles Windows / macOS / Linux profile paths.
"""
from __future__ import annotations
import json
import os
import platform
from pathlib import Path

from engine.application_model import Application, make_id
from engine.trust_scoring import score_dict, count_high_risk


# ---------------------------------------------------------------------------
# Profile path discovery
# ---------------------------------------------------------------------------
def _chromium_roots() -> list[tuple[str, Path]]:
    """Return list of (browser_label, root_path) pairs that exist."""
    sysname = platform.system()
    home = Path.home()
    candidates: dict[str, list[Path]] = {
        "Chrome": [], "Edge": [], "Brave": [], "Vivaldi": [], "Opera": [],
    }
    if sysname == "Windows":
        local = Path(os.getenv("LOCALAPPDATA", str(home / "AppData" / "Local")))
        candidates["Chrome"].append(local / "Google" / "Chrome" / "User Data")
        candidates["Edge"].append(local / "Microsoft" / "Edge" / "User Data")
        candidates["Brave"].append(local / "BraveSoftware" / "Brave-Browser" / "User Data")
        candidates["Vivaldi"].append(local / "Vivaldi" / "User Data")
        candidates["Opera"].append(home / "AppData" / "Roaming" / "Opera Software" / "Opera Stable")
    elif sysname == "Darwin":
        appsup = home / "Library" / "Application Support"
        candidates["Chrome"].append(appsup / "Google" / "Chrome")
        candidates["Edge"].append(appsup / "Microsoft Edge")
        candidates["Brave"].append(appsup / "BraveSoftware" / "Brave-Browser")
        candidates["Vivaldi"].append(appsup / "Vivaldi")
        candidates["Opera"].append(appsup / "com.operasoftware.Opera")
    else:    # Linux
        config = home / ".config"
        candidates["Chrome"].append(config / "google-chrome")
        candidates["Edge"].append(config / "microsoft-edge")
        candidates["Brave"].append(config / "BraveSoftware" / "Brave-Browser")
        candidates["Vivaldi"].append(config / "vivaldi")
    out: list[tuple[str, Path]] = []
    for label, paths in candidates.items():
        for p in paths:
            if p.exists():
                out.append((label, p))
    return out


def _firefox_profiles() -> list[Path]:
    sysname = platform.system()
    home = Path.home()
    if sysname == "Windows":
        base = Path(os.getenv("APPDATA", str(home / "AppData" / "Roaming"))) / "Mozilla" / "Firefox" / "Profiles"
    elif sysname == "Darwin":
        base = home / "Library" / "Application Support" / "Firefox" / "Profiles"
    else:
        base = home / ".mozilla" / "firefox"
    return list(base.glob("*.default*")) if base.exists() else []


# ---------------------------------------------------------------------------
# Manifest parsing
# ---------------------------------------------------------------------------
def _parse_chromium_extension(manifest_path: Path, browser: str) -> Application | None:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    name = manifest.get("name", "")
    version = manifest.get("version")
    if name.startswith("__MSG_"):
        # Localized name -- best effort: use folder name
        name = manifest_path.parent.parent.name
    perms = list(manifest.get("permissions", []) or []) + \
            list(manifest.get("host_permissions", []) or []) + \
            list(manifest.get("optional_permissions", []) or [])
    publisher = manifest.get("author")
    if isinstance(publisher, dict):
        publisher = publisher.get("name") or publisher.get("email")
    sig = {
        "publisher_verified": False,
        "signed": True,            # webstore extensions are signed by the store
        "install_count": 0,        # we'd need a webstore lookup
        "permissions_high_risk": count_high_risk(perms, "browser_ext"),
    }
    s = score_dict(sig)
    return Application(
        id=make_id("browser_ext", browser, name, version or ""),
        name=name or "(unknown)", version=version, publisher=publisher,
        category="browser_ext", provenance="third_party",
        permissions=perms, trust_signals=sig, trust_score=s["score"],
        raw={"browser": browser, "path": str(manifest_path)},
    )


def _parse_firefox_extension(rdf_or_xpi: Path) -> Application | None:
    # Firefox extensions live in an `extensions/` dir as .xpi files plus
    # an `extensions.json` index. We use the index for speed/accuracy.
    try:
        data = json.loads(rdf_or_xpi.read_text(encoding="utf-8"))
    except Exception:
        return None
    apps: list[Application] = []
    for ext in data.get("addons", []) or []:
        if ext.get("type") not in ("extension", "theme"):
            continue
        name = ext.get("defaultLocale", {}).get("name") or ext.get("id")
        version = ext.get("version")
        publisher = ext.get("defaultLocale", {}).get("creator")
        perms = ext.get("userPermissions", {}).get("permissions", []) + \
                ext.get("userPermissions", {}).get("origins", [])
        sig = {
            "publisher_verified": bool(ext.get("signedState", 0) > 0),
            "signed": bool(ext.get("signedState", 0) > 0),
            "permissions_high_risk": count_high_risk(perms, "browser_ext"),
        }
        s = score_dict(sig)
        apps.append(Application(
            id=make_id("browser_ext", "Firefox", name, version or ""),
            name=name, version=version, publisher=publisher,
            category="browser_ext", provenance="third_party",
            permissions=perms, trust_signals=sig, trust_score=s["score"],
            raw={"browser": "Firefox", "id": ext.get("id")},
        ))
    return apps


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def scan_browser_extensions() -> list[Application]:
    apps: list[Application] = []

    # Chromium-family
    for browser, root in _chromium_roots():
        for prof in [d for d in root.iterdir() if d.is_dir() and d.name.startswith(("Default", "Profile"))]:
            ext_root = prof / "Extensions"
            if not ext_root.exists():
                continue
            for ext_dir in ext_root.iterdir():
                if not ext_dir.is_dir():
                    continue
                for version_dir in ext_dir.iterdir():
                    manifest = version_dir / "manifest.json"
                    if manifest.exists():
                        a = _parse_chromium_extension(manifest, browser)
                        if a: apps.append(a)

    # Firefox
    for prof in _firefox_profiles():
        idx = prof / "extensions.json"
        if idx.exists():
            res = _parse_firefox_extension(idx)
            if isinstance(res, list):
                apps.extend(res)

    # Dedupe by id
    by_id: dict[str, Application] = {}
    for a in apps:
        by_id.setdefault(a.id, a)
    return list(by_id.values())
