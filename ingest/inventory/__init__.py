"""
Application inventory ingesters.

scan_all() walks every supported source on the host and upserts
Application nodes. Each per-category function can also be run standalone.
"""
from __future__ import annotations
from rich.console import Console

from .desktop import scan_desktop
from .browser_ext import scan_browser_extensions
from .ide_ext import scan_ide_extensions
from .mcp import scan_mcp_servers
from engine.application_model import upsert as upsert_apps

console = Console()


def scan_all() -> dict:
    """Run every host-side scanner and return a summary."""
    summary: dict[str, int] = {}
    apps = []

    for label, fn in [
        ("desktop_binary", scan_desktop),
        ("browser_ext",    scan_browser_extensions),
        ("ide_ext",        scan_ide_extensions),
        ("mcp_server",     scan_mcp_servers),
    ]:
        try:
            found = fn()
            apps += found
            summary[label] = len(found)
            console.print(f"[green]  {label}: {len(found)} app(s)")
        except Exception as e:
            summary[label] = 0
            console.print(f"[yellow]  {label}: {e}")

    n = upsert_apps(apps)
    summary["total_upserted"] = n
    return summary


__all__ = [
    "scan_all", "scan_desktop", "scan_browser_extensions",
    "scan_ide_extensions", "scan_mcp_servers",
]
