"""
Cross-reference Application inventory with:
   - GitHub Security Advisory database (GHSA)
   - OSV.dev (already used elsewhere)
   - OpenSSF Scorecard (https://api.scorecard.dev/projects/github.com/<owner>/<repo>)

Also exposes a single `enrich_all()` that re-walks every Application node
in the graph and updates its trust_signals + trust_score with whatever
external evidence it can gather. Designed to be re-runnable.
"""
from __future__ import annotations
import re
from rich.console import Console

from engine.graph import run_read, session
from engine.trust_scoring import score_dict
import httpx

console = Console()

GHSA_API = "https://api.github.com/advisories"
SCORECARD_API = "https://api.scorecard.dev/projects/github.com"


# ---------------------------------------------------------------------------
# OpenSSF Scorecard
# ---------------------------------------------------------------------------
def fetch_scorecard(owner: str, repo: str) -> float | None:
    """Return Scorecard 0-10 score for github.com/<owner>/<repo>, or None."""
    try:
        with httpx.Client(timeout=10.0) as c:
            r = c.get(f"{SCORECARD_API}/{owner}/{repo}")
            if r.status_code != 200:
                return None
            return float(r.json().get("score", 0.0))
    except Exception:
        return None


_GH_RE = re.compile(r"github\.com[/:]([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+?)(?:\.git)?(?:/|$)")


def _extract_github_owner_repo(url: str | None) -> tuple[str, str] | None:
    if not url: return None
    m = _GH_RE.search(url)
    if m: return m.group(1), m.group(2)
    return None


def enrich_with_scorecard(limit: int = 100) -> int:
    """For every Application with a GitHub source_url, fetch Scorecard."""
    rows = run_read("""
        MATCH (a:Application)
        WHERE a.source_url IS NOT NULL AND a.source_url CONTAINS 'github.com'
        RETURN a.id AS id, a.source_url AS url
        LIMIT $limit
    """, limit=limit)
    n = 0
    for r in rows:
        gh = _extract_github_owner_repo(r["url"])
        if not gh: continue
        sc = fetch_scorecard(*gh)
        if sc is None: continue
        with session() as s:
            s.run("""
                MATCH (a:Application {id: $id})
                SET a.scorecard = $score
            """, id=r["id"], score=sc)
        n += 1
    console.print(f"[green]Scorecard enriched {n} Application(s)")
    return n


# ---------------------------------------------------------------------------
# GHSA: cross-reference Application names against advisories
# ---------------------------------------------------------------------------
def cross_reference_ghsa(pages: int = 3) -> int:
    """Scan recent GHSA advisories and link any that mention an Application
    name we have in our graph (best-effort substring match)."""
    apps = run_read("""
        MATCH (a:Application) RETURN a.id AS id, a.name AS name LIMIT 500
    """)
    name_to_id = {a["name"].lower(): a["id"] for a in apps if a.get("name")}
    if not name_to_id:
        return 0
    matched = 0
    headers = {"Accept": "application/vnd.github+json"}
    with httpx.Client(timeout=20.0, headers=headers) as c:
        for page in range(1, pages + 1):
            r = c.get(GHSA_API, params={"per_page": 100, "page": page})
            if r.status_code != 200: break
            advisories = r.json()
            if not advisories: break
            for adv in advisories:
                summary = (adv.get("summary") or "").lower()
                description = (adv.get("description") or "").lower()
                cve_id = adv.get("cve_id") or adv.get("ghsa_id")
                if not cve_id: continue
                hay = summary + " " + description
                for name, app_id in name_to_id.items():
                    if len(name) >= 4 and name in hay:
                        with session() as s:
                            s.run("""
                                MERGE (c:CVE {id: $cve})
                                SET c.from_ghsa_inventory_match = true
                                WITH c
                                MATCH (a:Application {id: $app})
                                MERGE (c)-[:AFFECTS]->(a)
                            """, cve=cve_id, app=app_id)
                        matched += 1
    console.print(f"[green]GHSA matched {matched} Application↔CVE links")
    return matched


# ---------------------------------------------------------------------------
# Recompute trust scores after enrichment
# ---------------------------------------------------------------------------
def recompute_trust_scores() -> int:
    """Re-run trust scoring for every Application using up-to-date signals
    (cve_count from graph, scorecard from property, etc.)."""
    rows = run_read("""
        MATCH (a:Application)
        OPTIONAL MATCH (c:CVE)-[:AFFECTS]->(a)
        OPTIONAL MATCH (c2:CVE)-[:AFFECTS]->(a)
          WHERE c2.exploited_kev = true
        RETURN a.id AS id, a.permissions AS perms, a.category AS category,
               a.scorecard AS scorecard,
               a.trust_signals_json AS sig_json,
               count(DISTINCT c) AS cve_count,
               count(DISTINCT c2) > 0 AS in_kev
    """)
    import json
    n = 0
    for r in rows:
        try:
            sig = json.loads(r.get("sig_json") or "{}")
        except Exception:
            sig = {}
        sig["cve_count"] = r["cve_count"]
        sig["in_kev"] = bool(r["in_kev"])
        if r.get("scorecard") is not None:
            sig["scorecard"] = r["scorecard"]
        s = score_dict(sig)
        with session() as ses:
            ses.run("""
                MATCH (a:Application {id: $id})
                SET a.trust_signals_json = $sig_json,
                    a.trust_score = $score,
                    a.trust_band = $band
            """, id=r["id"], sig_json=json.dumps(sig),
                score=s["score"], band=s["band"])
        n += 1
    console.print(f"[green]Recomputed trust scores for {n} Application(s)")
    return n


def enrich_all() -> dict:
    sc = enrich_with_scorecard()
    gh = cross_reference_ghsa()
    rs = recompute_trust_scores()
    return {"scorecard_enriched": sc, "ghsa_matches": gh, "scores_recomputed": rs}
