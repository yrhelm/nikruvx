"""
Folder-watch policy importer
============================
Drop a JSON / .rules / .conf into a watched folder; Cyber Nexus auto-detects
the format, parses, and upserts the resulting Policy/Control nodes.

Usage:
    python -m ingest.policies.folder_watch ./policies          # one-shot
    python -m ingest.policies.folder_watch ./policies --watch  # watch loop

No external deps - uses os.stat polling so it works without `watchdog`.
"""
from __future__ import annotations
import argparse
import os
import time
from pathlib import Path
from rich.console import Console

from . import parse_any, upsert_policies

console = Console()
SUPPORTED = {".json", ".txt", ".rules", ".conf", ".nft", ".xml"}


def _scan_once(folder: Path, seen: dict[Path, float] | None = None) -> int:
    seen = seen if seen is not None else {}
    total = 0
    for p in folder.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in SUPPORTED:
            continue
        mtime = p.stat().st_mtime
        if seen.get(p) == mtime:
            continue
        try:
            content = p.read_text(encoding="utf-8", errors="ignore")
            policies = parse_any(content, hint=p.name)
            n = upsert_policies(policies)
            if n:
                console.print(f"[green]Imported {n} policy from {p}")
                total += n
            else:
                console.print(f"[yellow]No policy detected in {p}")
            seen[p] = mtime
        except Exception as e:
            console.print(f"[red]  {p}: {e}")
    return total


def watch(folder: Path, interval: float = 3.0) -> None:
    seen: dict[Path, float] = {}
    console.print(f"[cyan]Watching {folder}... Ctrl+C to stop")
    try:
        while True:
            _scan_once(folder, seen)
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("[cyan]stopped.")


def main() -> None:
    p = argparse.ArgumentParser(description="Folder-watch policy importer")
    p.add_argument("folder", type=Path, help="Folder to scan / watch")
    p.add_argument("--watch", action="store_true", help="Keep watching for changes")
    p.add_argument("--interval", type=float, default=3.0)
    args = p.parse_args()
    if not args.folder.exists():
        console.print(f"[red]{args.folder} does not exist")
        return
    if args.watch:
        watch(args.folder, args.interval)
    else:
        n = _scan_once(args.folder)
        console.print(f"[green]One-shot import: {n} policies")


if __name__ == "__main__":
    main()
