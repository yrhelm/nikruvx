"""
IDE extension inventory ingester.

Walks the on-disk extension directories for:
    VS Code        ~/.vscode/extensions/
    Cursor         ~/.cursor/extensions/   (or per-platform)
    VS Code (Insiders)  ~/.vscode-insiders/extensions/
    JetBrains plugins   ~/.<IDE><version>/config/plugins  (best-effort)

Each plugin's package.json yields name, publisher, version, permissions
(sandboxed activationEvents are not really permissions but useful signal).
"""
from __future__ import annotations
import json
import os
import platform
from pathlib import Path

from engine.application_model import Application, make_id
from engine.trust_scoring import score_dict, count_high_risk


def _vscode_roots() -> list[tuple[str, Path]]:
    home = Path.home()
    return [
        ("VS Code",          home / ".vscode" / "extensions"),
        ("VS Code Insiders", home / ".vscode-insiders" / "extensions"),
        ("Cursor",           home / ".cursor" / "extensions"),
        ("Windsurf",         home / ".windsurf" / "extensions"),
        ("VSCodium",         home / ".vscode-oss" / "extensions"),
    ]


def _scan_vscode_family() -> list[Application]:
    apps: list[Application] = []
    for label, root in _vscode_roots():
        if not root.exists():
            continue
        for ext_dir in root.iterdir():
            if not ext_dir.is_dir():
                continue
            pkg = ext_dir / "package.json"
            if not pkg.exists():
                continue
            try:
                data = json.loads(pkg.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                continue
            name = data.get("displayName") or data.get("name") or ext_dir.name
            version = data.get("version")
            publisher = data.get("publisher")
            perms = list(data.get("activationEvents", []) or [])
            engines = data.get("engines", {}) or {}

            sig = {
                "publisher_verified": bool(publisher),    # marketplace requires a publisher
                "signed": True,                           # marketplace signs
                "install_count": 0,                       # would need marketplace API call
                "last_update_days": 0,
                "permissions_high_risk": count_high_risk(perms, "ide_ext"),
            }
            s = score_dict(sig)
            apps.append(Application(
                id=make_id("ide_ext", label, publisher or "", name, version or ""),
                name=name, version=version, publisher=publisher,
                category="ide_ext", provenance="third_party",
                permissions=perms, trust_signals=sig, trust_score=s["score"],
                raw={"ide": label, "engines": engines, "path": str(ext_dir)},
            ))
    return apps


def _scan_jetbrains() -> list[Application]:
    home = Path.home()
    sysname = platform.system()
    if sysname == "Windows":
        roots = [Path(os.getenv("APPDATA", str(home / "AppData/Roaming"))) / "JetBrains"]
    elif sysname == "Darwin":
        roots = [home / "Library" / "Application Support" / "JetBrains"]
    else:
        roots = [home / ".config" / "JetBrains"]
    apps: list[Application] = []
    for r in roots:
        if not r.exists():
            continue
        for ide_dir in r.iterdir():
            plugins = ide_dir / "plugins"
            if not plugins.exists():
                continue
            for plug in plugins.iterdir():
                if not plug.is_dir():
                    continue
                # JetBrains plugin descriptor lives in lib/META-INF/plugin.xml
                meta = next((p for p in plug.rglob("plugin.xml")), None)
                name = plug.name
                version = None
                publisher = None
                if meta:
                    try:
                        import xml.etree.ElementTree as ET
                        root = ET.fromstring(meta.read_text(encoding="utf-8", errors="ignore"))
                        name = (root.findtext("name") or name).strip()
                        version = (root.findtext("version") or "").strip() or None
                        ven = root.find("vendor")
                        if ven is not None:
                            publisher = (ven.text or "").strip() or None
                    except Exception: pass
                sig = {"publisher_verified": bool(publisher), "signed": True}
                s = score_dict(sig)
                apps.append(Application(
                    id=make_id("ide_ext", "JetBrains", publisher or "", name, version or ""),
                    name=name, version=version, publisher=publisher,
                    category="ide_ext", provenance="third_party",
                    trust_signals=sig, trust_score=s["score"],
                    raw={"ide": "JetBrains", "ide_dir": ide_dir.name},
                ))
    return apps


def scan_ide_extensions() -> list[Application]:
    apps = _scan_vscode_family() + _scan_jetbrains()
    by_id: dict[str, Application] = {}
    for a in apps: by_id.setdefault(a.id, a)
    return list(by_id.values())
