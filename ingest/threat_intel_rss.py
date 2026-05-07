"""
Threat-intel RSS ingester with LLM-assisted TTP extraction.
============================================================
Polls a curated set of threat-intelligence feeds, deduplicates by URL
hash, and extracts ATT&CK technique IDs / OSI layer / severity /
behavioral indicators from each new entry.

Two extraction strategies, in priority order:

    1. LLM-assisted (engine.llm)  — Ollama llama3.1 prompted for
                                    structured extraction; validated
                                    against the catalog.
    2. Keyword/regex fallback     — fast, deterministic, used when
                                    Ollama isn't available or fails.

Curated feed list:
    Project Zero            googleprojectzero.blogspot.com
    Microsoft MSTIC         microsoft.com/en-us/security/blog
    CrowdStrike             crowdstrike.com/blog
    Mandiant                cloud.google.com/blog/topics/threat-intelligence
    Unit 42                 unit42.paloaltonetworks.com
    Trail of Bits           blog.trailofbits.com
    Anthropic Research      anthropic.com/research
    Big Sleep / Project Zero AI

Run modes:
    `import_feed(url)`               — pull one feed, return entries
    `ingest_all()`                   — sweep every curated feed
    `background_loop()`              — daemon-thread driver (matches
                                        engine.threat_feeds pattern)
    `extract_ttps_for_entry(entry)`  — LLM + fallback extraction
    `auto_file_zero_day(entry)`      — turn high-confidence finds into
                                        :ZeroDayPattern nodes
"""
from __future__ import annotations
import hashlib
import json
import logging
import re
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from xml.etree import ElementTree as ET

try:
    from engine.graph import run_read, run_write
except Exception:    # bare module import in tests
    def run_read(*_a, **_k): return []  # type: ignore[no-redef]
    def run_write(*_a, **_k): return None  # type: ignore[no-redef]

try:
    from engine import llm as _llm
except Exception:
    _llm = None  # type: ignore[assignment]

log = logging.getLogger(__name__)

# Curated feeds. Small + high-signal by design.
# URLs verified against current redirect targets (May 2026).
DEFAULT_FEEDS: list[dict[str, str]] = [
    {"id": "project_zero",
     "name": "Google Project Zero",
     "url": "https://projectzero.google/feed.xml"},
    {"id": "mstic",
     "name": "Microsoft MSTIC",
     "url": "https://www.microsoft.com/en-us/security/blog/feed/"},
    {"id": "crowdstrike",
     "name": "CrowdStrike Counter Adversary",
     "url": "https://www.crowdstrike.com/blog/feed"},
    {"id": "unit42",
     "name": "Palo Alto Unit 42",
     "url": "https://unit42.paloaltonetworks.com/feed/"},
    {"id": "tob",
     "name": "Trail of Bits",
     "url": "https://blog.trailofbits.com/index.xml"},
    {"id": "schneier",
     "name": "Schneier on Security",
     "url": "https://www.schneier.com/feed/atom/"},
    {"id": "krebs",
     "name": "Krebs on Security",
     "url": "https://krebsonsecurity.com/feed/"},
]


@dataclass
class RssEntry:
    feed_id: str
    feed_name: str
    title: str
    url: str
    published: str
    summary: str
    content_hash: str
    techniques: list[str] = field(default_factory=list)
    layer: int = 7
    severity: str = "medium"
    indicators: list[str] = field(default_factory=list)
    ai_discovered: bool = False
    extraction_method: str = "fallback"   # 'llm' | 'fallback'


# ---------------------------------------------------------------------------
# RSS / Atom parsing
# ---------------------------------------------------------------------------
_NS = {
    "atom": "http://www.w3.org/2005/Atom",
    "content": "http://purl.org/rss/1.0/modules/content/",
}


def _strip_tags(html: str) -> str:
    """Naive HTML strip — good enough for summary extraction; not safe
    for rendering."""
    text = re.sub(r"<[^>]+>", " ", html or "")
    return re.sub(r"\s+", " ", text).strip()


def _parse_feed(xml_bytes: bytes, feed_id: str, feed_name: str) -> list[RssEntry]:
    """Parse RSS 2.0 or Atom 1.0. Returns RssEntry list (no extraction yet)."""
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as e:
        log.warning("rss parse error %s: %s", feed_name, e)
        return []
    out: list[RssEntry] = []
    # RSS 2.0
    for item in root.findall(".//channel/item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        pub = (item.findtext("pubDate") or "").strip()
        desc = item.findtext("description") or ""
        body = item.findtext("{http://purl.org/rss/1.0/modules/content/}encoded") or desc
        body_text = _strip_tags(body)
        out.append(RssEntry(
            feed_id=feed_id, feed_name=feed_name, title=title, url=link,
            published=pub, summary=body_text[:6000],
            content_hash=hashlib.sha256(
                f"{link}|{title}".encode("utf-8")).hexdigest(),
        ))
    # Atom
    for entry in root.findall(".//atom:entry", _NS):
        title = (entry.findtext("atom:title", default="", namespaces=_NS) or "").strip()
        link_el = entry.find("atom:link", _NS)
        link = link_el.get("href", "") if link_el is not None else ""
        pub = entry.findtext("atom:published", default="", namespaces=_NS) \
              or entry.findtext("atom:updated", default="", namespaces=_NS) or ""
        body = entry.findtext("atom:content", default="", namespaces=_NS) \
               or entry.findtext("atom:summary", default="", namespaces=_NS) or ""
        body_text = _strip_tags(body)
        out.append(RssEntry(
            feed_id=feed_id, feed_name=feed_name, title=title, url=link,
            published=pub, summary=body_text[:6000],
            content_hash=hashlib.sha256(
                f"{link}|{title}".encode("utf-8")).hexdigest(),
        ))
    return out


def _fetch(url: str, timeout: float = 30.0, max_redirects: int = 5) -> bytes:
    """Fetch a URL with HTTP redirect following enabled (most feeds 301
    to a canonical form). Returns empty bytes on failure."""
    try:
        import httpx
        r = httpx.get(
            url, timeout=timeout,
            follow_redirects=True,
            headers={
                "User-Agent": "NikruvX/1.0 threat-intel-poller (+https://github.com/yrhelm/nikruvx)",
                "Accept": "application/atom+xml, application/rss+xml, application/xml, text/xml, */*",
            },
        )
        r.raise_for_status()
        # If the server returned HTML (some feeds 200 with a soft-redirect
        # HTML page), reject early so the parser doesn't fail noisily.
        ctype = r.headers.get("content-type", "").lower()
        if ctype.startswith("text/html"):
            log.warning("fetch %s returned HTML, not feed (Content-Type: %s)", url, ctype)
            return b""
        return r.content
    except Exception as e:
        log.warning("fetch failed %s: %s", url, e)
        return b""


# ---------------------------------------------------------------------------
# TTP extraction — LLM + fallback
# ---------------------------------------------------------------------------
_TTP_REGEX = re.compile(r"\b(T\d{4}(?:\.\d{3})?|AML\.T\d{4})\b")
_AI_DISCOVERED_HINTS = re.compile(
    r"\b(?:big sleep|naptime|ai-discovered|llm-assisted|llm-driven|"
    r"oss-fuzz.*(?:llm|ai)|gpt-driven|claude-discovered|"
    r"agent-driven fuzzer|atheris|atheris with llm)\b",
    re.IGNORECASE,
)
_SEVERITY_HINTS = [
    (re.compile(r"\b(?:critical|cisa emergency|in-the-wild|actively exploited|"
                r"unauth(?:enticated)? rce|pre-auth rce|kev)\b", re.I), "critical"),
    (re.compile(r"\b(?:high(?: severity)?|high impact|wide-scale|scalable)\b",
                re.I), "high"),
    (re.compile(r"\b(?:medium severity|moderate impact)\b", re.I), "medium"),
]


def _layer_from_text(text: str) -> int:
    t = (text or "").lower()
    if any(s in t for s in ("ssh", "rdp", "smb", "session", "kerberos", "ntlm")):
        return 5
    if any(s in t for s in ("tls", "certificate", "cert pinning", "ssl")):
        return 6
    if any(s in t for s in ("arp", "vlan", "wifi", "wi-fi")):
        return 2
    if any(s in t for s in ("ip", "icmp", "routing", "bgp", "dns")):
        return 3
    if any(s in t for s in ("tcp", "udp", "smuggl", "desync")):
        return 4
    if any(s in t for s in ("hardware", "physical", "side-channel", "timing",
                            "spectre", "meltdown", "dmp", "gpu memory")):
        return 1
    return 7  # application is the default


def _extract_severity(text: str) -> str:
    for pat, sev in _SEVERITY_HINTS:
        if pat.search(text or ""):
            return sev
    return "medium"


def _extract_indicators(text: str) -> list[str]:
    """Extract sentences that look like detection signals."""
    candidates = re.findall(
        r"(?:[A-Z][^.!?]*(?:log|process|connection|request|payload|"
        r"command|hash|registry|file|outbound|exfil|inject|shell)[^.!?]*[.!?])",
        text or "", flags=re.IGNORECASE,
    )
    return [c.strip() for c in candidates[:5] if 20 < len(c) < 200]


def _llm_extract(entry: RssEntry, timeout: float = 15.0) -> dict | None:
    """Try LLM extraction with a hard per-call timeout. Returns dict on
    success, None on any failure (including timeout)."""
    if _llm is None or not getattr(_llm, "is_available", lambda: False)():
        return None
    prompt = (
        "You are a security analyst extracting structured data from a "
        "threat-intelligence article. Return STRICT JSON only. No prose.\n\n"
        f"Title: {entry.title}\n\n"
        f"Article: {entry.summary[:3500]}\n\n"
        "Required JSON schema:\n"
        '{"techniques": ["T1190","AML.T0051",...],\n'
        ' "layer": 1-7,\n'
        ' "severity": "critical|high|medium|low",\n'
        ' "indicators": ["…","…"],\n'
        ' "ai_discovered": true|false}\n\n'
        "Rules:\n"
        "- Use only valid MITRE ATT&CK technique IDs (T#### or AML.T####)\n"
        "- Pick the OSI layer where the attack manifests primarily\n"
        '- Set ai_discovered=true if the bug was found by Big Sleep, '
        'OSS-Fuzz with LLM input, naptime, or any AI agent\n'
        "- Indicators should be specific log/network signs, not generic prose"
    )
    # Run the LLM call in a worker thread with a hard timeout so a slow /
    # hung Ollama can't stall the sweep.
    from concurrent.futures import ThreadPoolExecutor, TimeoutError as _Timeout
    try:
        with ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(
                _llm.generate, prompt,
                system="You are a precise security data extractor.",
            )
            resp = fut.result(timeout=timeout)
        m = re.search(r"\{[\s\S]+\}", resp or "")
        if not m:
            return None
        return json.loads(m.group(0))
    except _Timeout:
        log.warning("llm extraction timed out after %.1fs (entry: %s) — using fallback",
                    timeout, entry.title[:60])
        return None
    except Exception as e:
        log.debug("llm extraction failed: %s", e)
        return None


def extract_ttps_for_entry(entry: RssEntry,
                           use_llm: bool = False,
                           llm_timeout: float = 15.0) -> RssEntry:
    """Mutate entry with extracted techniques / layer / severity /
    indicators / ai_discovered.

    Default is the fast regex/keyword fallback (no LLM call). Pass
    `use_llm=True` to attempt LLM extraction first; the result is
    validated against the catalog and the fallback runs if anything
    fails or times out (`llm_timeout` seconds, default 15s).
    """
    blob = f"{entry.title}\n{entry.summary}"
    llm_out = _llm_extract(entry, timeout=llm_timeout) if use_llm else None
    if llm_out:
        try:
            from engine.attack_catalog import by_id as att_by_id
            techs = [t for t in llm_out.get("techniques", [])
                     if isinstance(t, str) and att_by_id(t)]
            entry.techniques = techs[:8]
            entry.layer = int(llm_out.get("layer", 7))
            entry.severity = str(llm_out.get("severity", "medium")).lower()
            entry.indicators = [str(s) for s in (llm_out.get("indicators") or [])][:5]
            entry.ai_discovered = bool(llm_out.get("ai_discovered", False))
            entry.extraction_method = "llm"
            return entry
        except Exception as e:
            log.debug("llm output parse fail: %s", e)
    # Fallback
    entry.techniques = sorted(set(_TTP_REGEX.findall(blob)))[:8]
    entry.layer = _layer_from_text(blob)
    entry.severity = _extract_severity(blob)
    entry.indicators = _extract_indicators(blob)
    entry.ai_discovered = bool(_AI_DISCOVERED_HINTS.search(blob))
    entry.extraction_method = "fallback"
    return entry


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
def _persist_entry(e: RssEntry) -> None:
    run_write(
        """
        MERGE (a:ThreatAdvisory {content_hash: $h})
          SET a.title = $title,
              a.url = $url,
              a.feed_id = $fid,
              a.feed_name = $fname,
              a.published = $pub,
              a.severity = $sev,
              a.layer = $layer,
              a.summary = $summary,
              a.indicators = $ind,
              a.ai_discovered = $ai,
              a.extraction_method = $method,
              a.last_seen = datetime()
        WITH a
        UNWIND $techs AS tid
        OPTIONAL MATCH (t:AttackTechnique {id: tid})
        FOREACH (_ IN CASE WHEN t IS NOT NULL THEN [1] ELSE [] END |
          MERGE (a)-[:USES_TECHNIQUE]->(t)
        )
        """,
        h=e.content_hash, title=e.title, url=e.url,
        fid=e.feed_id, fname=e.feed_name, pub=e.published,
        sev=e.severity, layer=e.layer, summary=e.summary[:2000],
        ind=e.indicators, ai=e.ai_discovered, method=e.extraction_method,
        techs=e.techniques,
    )


def auto_file_zero_day(e: RssEntry) -> str | None:
    """If an entry is high-signal (≥1 valid technique + critical/high severity),
    create a corresponding :ZeroDayPattern node so the pattern surfaces in
    the recommender + landscape views.

    Returns the new pattern id, or None if criteria not met."""
    if not e.techniques or e.severity not in ("critical", "high"):
        return None
    pat_id = f"ZD-RSS-{e.content_hash[:12].upper()}"
    run_write(
        """
        MERGE (z:ZeroDayPattern {id: $pid})
          ON CREATE SET z.created_at = datetime()
          SET z.name = $name,
              z.description = $desc,
              z.severity = $sev,
              z.layer = $layer,
              z.cve_ids = [],
              z.first_seen = $pub,
              z.source = $src,
              z.ai_discovered = $ai,
              z.ai_anticipated = false,
              z.predicted = false,
              z.mitigation_window = CASE WHEN $sev = 'critical' THEN 'immediate'
                                          WHEN $sev = 'high'     THEN 'weeks'
                                          ELSE '' END,
              z.public_disclosure = true,
              z.behavioral_indicators = $ind,
              z.references = [$url],
              z.updated_at = datetime()
        WITH z
        UNWIND $techs AS tid
        OPTIONAL MATCH (t:AttackTechnique {id: tid})
        FOREACH (_ IN CASE WHEN t IS NOT NULL THEN [1] ELSE [] END |
          MERGE (z)-[:USES_TECHNIQUE]->(t)
        )
        """,
        pid=pat_id, name=e.title[:240],
        desc=e.summary[:800], sev=e.severity, layer=e.layer,
        pub=e.published, src=f"{e.feed_name} (RSS)",
        ai=e.ai_discovered, ind=e.indicators, url=e.url,
        techs=e.techniques,
    )
    return pat_id


# ---------------------------------------------------------------------------
# Public ingest API
# ---------------------------------------------------------------------------
def import_feed(feed: dict[str, str], auto_file: bool = True,
                use_llm: bool = False, llm_timeout: float = 15.0) -> dict:
    """Pull one feed, extract, persist. Returns counts.

    `use_llm=False` (default) runs the fast regex/keyword extractor.
    `use_llm=True` attempts an Ollama call per entry with a per-call
    `llm_timeout` ceiling so a slow LLM can't hang the sweep.
    """
    raw = _fetch(feed["url"])
    if not raw:
        return {"feed": feed["id"], "fetched": 0, "new": 0, "filed": 0}
    entries = _parse_feed(raw, feed["id"], feed["name"])
    new_count = 0
    filed_count = 0
    for e in entries:
        # dedup against existing graph
        existing = run_read(
            "MATCH (a:ThreatAdvisory {content_hash: $h}) RETURN a.title AS title LIMIT 1",
            h=e.content_hash,
        )
        if existing:
            continue
        e = extract_ttps_for_entry(e, use_llm=use_llm, llm_timeout=llm_timeout)
        _persist_entry(e)
        new_count += 1
        if auto_file:
            pid = auto_file_zero_day(e)
            if pid:
                filed_count += 1
    return {
        "feed": feed["id"], "feed_name": feed["name"],
        "fetched": len(entries), "new": new_count, "filed": filed_count,
    }


def ingest_all(feeds: list[dict[str, str]] | None = None,
               auto_file: bool = True,
               use_llm: bool = False,
               llm_timeout: float = 15.0) -> dict:
    feeds = feeds or DEFAULT_FEEDS
    summary = {"feeds": [], "new_total": 0, "filed_total": 0}
    for f in feeds:
        r = import_feed(f, auto_file=auto_file,
                        use_llm=use_llm, llm_timeout=llm_timeout)
        summary["feeds"].append(r)
        summary["new_total"] += r["new"]
        summary["filed_total"] += r["filed"]
    return summary


def list_recent_advisories(limit: int = 50) -> list[dict]:
    cypher = """
    MATCH (a:ThreatAdvisory)
    OPTIONAL MATCH (a)-[:USES_TECHNIQUE]->(t:AttackTechnique)
    WITH a, collect(t.id) AS techs
    RETURN a.title AS title, a.url AS url, a.feed_name AS feed_name,
           a.published AS published, a.severity AS severity,
           a.layer AS layer, a.ai_discovered AS ai_discovered,
           a.extraction_method AS extraction_method,
           a.indicators AS indicators, techs AS techniques
    ORDER BY a.last_seen DESC LIMIT $limit
    """
    return run_read(cypher, limit=limit)


# ---------------------------------------------------------------------------
# Background loop (matches engine.threat_feeds pattern)
# ---------------------------------------------------------------------------
def background_loop(stop_event: threading.Event,
                    interval_seconds: int = 6 * 3600,
                    auto_file: bool = True) -> None:
    log.info("threat-intel rss loop starting; interval=%ds", interval_seconds)
    while not stop_event.is_set():
        try:
            res = ingest_all(auto_file=auto_file)
            log.info("threat-intel rss sweep: new=%d filed=%d",
                     res["new_total"], res["filed_total"])
        except Exception as e:    # noqa: BLE001
            log.warning("threat-intel rss sweep failed: %s", e)
        if stop_event.wait(timeout=interval_seconds):
            break


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _cli() -> int:
    import argparse
    p = argparse.ArgumentParser(prog="ingest.threat_intel_rss",
        description="Threat-intel RSS ingester with LLM-assisted TTP extraction.")
    sub = p.add_subparsers(dest="cmd", required=True)
    p_ing = sub.add_parser("ingest", help="Sweep all feeds")
    p_ing.add_argument("--no-auto-file", action="store_true",
                       help="Don't auto-create :ZeroDayPattern nodes")
    p_ing.add_argument("--llm", action="store_true",
                       help="Use Ollama for TTP extraction (slow; default off)")
    p_ing.add_argument("--llm-timeout", type=float, default=15.0,
                       help="Per-entry LLM call timeout (default 15s)")
    p_one = sub.add_parser("one", help="Sweep one feed")
    p_one.add_argument("--id", required=True, choices=[f["id"] for f in DEFAULT_FEEDS])
    p_one.add_argument("--llm", action="store_true",
                       help="Use Ollama for TTP extraction")
    p_one.add_argument("--llm-timeout", type=float, default=15.0)
    sub.add_parser("recent", help="List recent advisories")
    args = p.parse_args()

    if args.cmd == "ingest":
        print(json.dumps(
            ingest_all(auto_file=not args.no_auto_file,
                       use_llm=args.llm, llm_timeout=args.llm_timeout),
            indent=2, default=str))
    elif args.cmd == "one":
        feed = next(f for f in DEFAULT_FEEDS if f["id"] == args.id)
        print(json.dumps(
            import_feed(feed, use_llm=args.llm,
                        llm_timeout=args.llm_timeout),
            indent=2, default=str))
    elif args.cmd == "recent":
        print(json.dumps(list_recent_advisories(50), indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())


__all__ = [
    "RssEntry", "DEFAULT_FEEDS",
    "import_feed", "ingest_all", "extract_ttps_for_entry",
    "auto_file_zero_day", "list_recent_advisories", "background_loop",
]
