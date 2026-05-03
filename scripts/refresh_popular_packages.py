"""
Refresh the bundled popular-package fixtures used by the typosquat detector.

Pulls live top-N from each registry and overwrites
data/popular_packages/<eco>.json with the freshest data available.

Usage:
    python scripts/refresh_popular_packages.py            # all ecosystems
    python scripts/refresh_popular_packages.py --eco npm  # just npm
    python scripts/refresh_popular_packages.py --top 5000 # bigger lists

Sources used:
    npm        https://hugovk.github.io/top-pypi-packages/  (mirror, 5000)
               BUT for npm we use https://api.npmjs.org/downloads/range  loop
               OR a public top-1000 mirror (anvaka)
    pypi       https://hugovk.github.io/top-pypi-packages/top-pypi-packages.json
    crates.io  https://crates.io/api/v1/crates?sort=downloads&per_page=100
    rubygems   https://rubygems.org/api/v1/owners/-/gems  (limited)
    go         https://pkg.go.dev/  (no top-N API, kept manual)
    maven      https://mvnrepository.com  (scrape; limited; kept manual)
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import httpx
import sys

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "popular_packages"
DATA.mkdir(parents=True, exist_ok=True)


def _save(eco_file: str, names: list[str]) -> int:
    names = [n for n in dict.fromkeys(names) if n]   # dedupe, preserve order
    (DATA / eco_file).write_text(json.dumps(names, indent=2), encoding="utf-8")
    print(f"  wrote {len(names)} -> {eco_file}")
    return len(names)


def fetch_pypi(top: int = 5000) -> int:
    print("[PyPI] fetching hugovk top list...")
    url = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.json"
    with httpx.Client(timeout=30) as c:
        r = c.get(url)
        r.raise_for_status()
        rows = r.json().get("rows", [])
    names = [row["project"].lower() for row in rows[:top] if row.get("project")]
    return _save("pypi.json", names)


def fetch_npm(top: int = 1000) -> int:
    print("[npm] fetching anvaka top list...")
    # Public mirror of top-1000 npm packages by downloads.
    url = "https://anvaka.github.io/npmrank/online/npmrank.json"
    try:
        with httpx.Client(timeout=30) as c:
            r = c.get(url)
            r.raise_for_status()
            data = r.json()
    except Exception as e:
        print(f"  anvaka mirror unreachable ({e}) - keeping bundled fixture")
        return 0
    # Sort by gravity (combination of downloads + dependents)
    items = sorted(data.items(), key=lambda kv: -kv[1].get("rank", 0))
    names = [k for k, _ in items[:top]]
    return _save("npm.json", names)


def fetch_crates(top: int = 1000) -> int:
    print("[crates.io] fetching downloads-sorted top...")
    names: list[str] = []
    page = 1
    per_page = 100
    with httpx.Client(timeout=30) as c:
        while len(names) < top:
            r = c.get("https://crates.io/api/v1/crates",
                      params={"sort": "downloads", "page": page, "per_page": per_page},
                      headers={"User-Agent": "NikruvX/refresh"})
            if r.status_code != 200: break
            data = r.json()
            crates = data.get("crates", [])
            if not crates: break
            names += [c["name"].lower() for c in crates]
            if len(crates) < per_page: break
            page += 1
    return _save("cratesio.json", names[:top])


def fetch_rubygems(top: int = 500) -> int:
    print("[RubyGems] fetching owner-curated lists (no public top-N API)...")
    # RubyGems doesn't expose a top-by-downloads API, so we just refresh from
    # its 'just_updated' endpoint as a best-effort signal of activity.
    names: list[str] = []
    with httpx.Client(timeout=30) as c:
        for endpoint in ["just_updated", "most_downloaded"]:
            try:
                r = c.get(f"https://rubygems.org/api/v1/activity/{endpoint}.json")
                if r.status_code == 200:
                    names += [g["name"].lower() for g in r.json() if g.get("name")]
            except Exception:
                continue
    if not names:
        print("  no activity data fetched - keeping bundled fixture")
        return 0
    return _save("rubygems.json", names[:top])


def fetch_go() -> int:
    print("[Go] no public top-N API; fixture is hand-maintained.")
    return 0


def fetch_maven() -> int:
    print("[Maven] no public top-N API; fixture is hand-maintained.")
    return 0


FETCHERS = {
    "npm": fetch_npm,
    "pypi": fetch_pypi,
    "cratesio": fetch_crates,
    "crates.io": fetch_crates,
    "rubygems": fetch_rubygems,
    "go": fetch_go,
    "maven": fetch_maven,
}


def main() -> None:
    p = argparse.ArgumentParser(description="Refresh popular-package fixtures.")
    p.add_argument("--eco", help="single ecosystem (npm/pypi/cratesio/rubygems/go/maven)")
    p.add_argument("--top", type=int, default=1000)
    args = p.parse_args()
    targets = [args.eco] if args.eco else ["npm","pypi","cratesio","rubygems","go","maven"]
    total = 0
    for t in targets:
        fn = FETCHERS.get(t)
        if not fn:
            print(f"unknown ecosystem: {t}")
            continue
        try:
            n = fn(args.top) if "top" in fn.__code__.co_varnames else fn()
            total += n
        except Exception as e:
            print(f"  {t} fetch failed: {e}")
    print(f"\nDone. {total} entries refreshed across all targets.")


if __name__ == "__main__":
    main()
