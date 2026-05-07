"""Tests for v2 of Zero-Day Defense — SIEM generator, personalized risk,
RSS ingester, Model Gate cross-reference."""
from __future__ import annotations
import pytest


# ===========================================================================
# SIEM generator
# ===========================================================================
class TestSiemGenerator:
    def test_indicator_to_all_formats(self):
        from engine.siem_generator import generate_for_indicator
        d = generate_for_indicator(
            "user-controlled string with ${jndi:ldap://...} appears in any log",
            "T1190", severity="critical")
        assert d.sigma and d.kql and d.splunk and d.elastic and d.falcon_fql
        assert "T1190" in d.kql
        assert "jndi" in d.sigma  # keyword extraction caught the sigil
        # Sigma rule must include attack tag
        assert "attack.t1190" in d.sigma.lower()

    def test_log_source_classification(self):
        from engine.siem_generator import generate_for_indicator
        d = generate_for_indicator(
            "ssh latency increase ~500ms+ on affected hosts", "T1195.002")
        assert d.log_source in ("linux_ssh", "linux_auth")

    def test_pattern_generates_one_rule_per_indicator_x_technique(self):
        from engine.siem_generator import generate_for_pattern
        # ZD-2024-XZ-UTILS has 3 indicators × 3 techniques (T1195.002, T1190, T1078)
        rules = generate_for_pattern("ZD-2024-XZ-UTILS")
        assert len(rules) >= 6, "expected indicators × techniques expansion"
        for r in rules:
            assert r.sigma and r.kql

    def test_pattern_with_no_indicators_uses_description(self):
        from engine.siem_generator import generate_for_pattern
        rules = generate_for_pattern("ZD-2024-IVANTI")
        # description fallback still produces something
        assert len(rules) >= 1

    def test_unknown_pattern_returns_empty(self):
        from engine.siem_generator import generate_for_pattern
        assert generate_for_pattern("ZD-NOT-A-REAL-PATTERN") == []

    def test_keyword_extraction_handles_no_quotes(self):
        from engine.siem_generator import generate_for_indicator
        d = generate_for_indicator(
            "Memory corruption signatures in ASan / Valgrind", "T1499.004")
        # Should extract ASan or Valgrind as a token
        assert "ASan" in d.sigma or "Valgrind" in d.sigma or "Memory" in d.sigma


# ===========================================================================
# Personalized risk
# ===========================================================================
class TestPersonalizedRisk:
    def test_compute_exposure_returns_list(self, fake_graph):
        from engine.personalized_risk import compute_exposure
        # No apps in fake graph → exposure list may be small but should
        # still include patterns-only entries
        out = compute_exposure(top_n=10)
        assert isinstance(out, list)

    def test_summary_shape(self, fake_graph):
        from engine.personalized_risk import summary
        s = summary()
        for k in ("techniques_at_risk", "immediate_action_techniques",
                  "ai_anticipated_techniques", "techniques_with_no_installed_defense",
                  "top_5_by_score"):
            assert k in s

    def test_score_increases_with_severity(self, fake_graph):
        from engine.personalized_risk import _SEVERITY_WEIGHTS, _WINDOW_WEIGHTS
        # Sanity-check the weight table
        assert _SEVERITY_WEIGHTS["critical"] > _SEVERITY_WEIGHTS["high"]
        assert _SEVERITY_WEIGHTS["high"] > _SEVERITY_WEIGHTS["medium"]
        assert _WINDOW_WEIGHTS["immediate"] > _WINDOW_WEIGHTS["weeks"]


# ===========================================================================
# RSS ingester
# ===========================================================================
class TestRssIngester:
    def test_parse_atom_returns_entries(self):
        from ingest.threat_intel_rss import _parse_feed
        atom = b"""<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>Big Sleep finds stack underflow in SQLite</title>
    <link href="https://example.com/big-sleep-sqlite"/>
    <published>2024-11-01T00:00:00Z</published>
    <summary>Google's Big Sleep AI agent identified a stack-buffer underflow.
       Behavioral indicator: ASan crash in SQLite parser. T1499.004 applies.</summary>
  </entry>
</feed>
"""
        entries = _parse_feed(atom, "test", "Test Feed")
        assert len(entries) == 1
        assert "Big Sleep" in entries[0].title
        assert entries[0].url.startswith("https://")

    def test_parse_rss20_returns_entries(self):
        from ingest.threat_intel_rss import _parse_feed
        rss = b"""<?xml version="1.0"?>
<rss version="2.0"><channel>
  <title>Test</title>
  <item>
    <title>Critical RCE in foo-server</title>
    <link>https://example.com/foo-rce</link>
    <pubDate>Mon, 01 Jan 2025 00:00:00 GMT</pubDate>
    <description>Pre-auth RCE T1190. Outbound HTTP to attacker host.</description>
  </item>
</channel></rss>
"""
        entries = _parse_feed(rss, "test", "Test Feed")
        assert len(entries) == 1

    def test_fallback_extraction_finds_techniques_and_severity(self):
        from ingest.threat_intel_rss import RssEntry, extract_ttps_for_entry
        e = RssEntry(
            feed_id="t", feed_name="T", title="Pre-auth RCE chain in Acme",
            url="https://example.com/x", published="2025-01-01",
            summary="Adversaries chain T1190 with T1059 to gain shell. "
                    "Outbound HTTP request to attacker-controlled host. "
                    "This is critical.",
            content_hash="x",
        )
        out = extract_ttps_for_entry(e)
        assert "T1190" in out.techniques
        assert "T1059" in out.techniques
        assert out.severity == "critical"
        assert out.layer == 7
        assert out.extraction_method == "fallback"

    def test_fallback_detects_ai_discovered(self):
        from ingest.threat_intel_rss import RssEntry, extract_ttps_for_entry
        e = RssEntry(
            feed_id="t", feed_name="T", title="Big Sleep find: T1499.004 in libpng",
            url="https://example.com/x", published="2025-01-01",
            summary="Google's Big Sleep AI agent found a stack underflow "
                    "in libpng — first AI-discovered memory bug in this lib.",
            content_hash="x",
        )
        out = extract_ttps_for_entry(e)
        assert out.ai_discovered is True

    def test_default_feed_list_curated(self):
        from ingest.threat_intel_rss import DEFAULT_FEEDS
        assert len(DEFAULT_FEEDS) >= 5
        for f in DEFAULT_FEEDS:
            assert f["url"].startswith(("https://", "http://"))
            assert f["id"] and f["name"]
        # IDs unique
        ids = [f["id"] for f in DEFAULT_FEEDS]
        assert len(ids) == len(set(ids))


# ===========================================================================
# Model Gate cross-reference
# ===========================================================================
class TestModelGateImport:
    def test_import_returns_counts(self, fake_graph):
        from engine.zero_day_defense import import_from_model_gate
        # No data in fake graph → 0 scanned
        fake_graph["data"] = []
        out = import_from_model_gate(min_severity="high", max_age_days=30)
        assert "scanned" in out
        assert out["scanned"] == 0

    def test_import_files_critical_failures(self, fake_graph):
        from engine.zero_day_defense import import_from_model_gate
        fake_graph["data"] = [
            {"probe_id": "dpi.classic_ignore_previous",
             "category": "direct_prompt_injection", "severity": "critical",
             "title": "Classic 'ignore previous instructions' override",
             "reason": "leaked HUNTER2-CANARY-9X8B",
             "model_spec": "openai:gpt-5", "ts": "2026-05-04T12:00:00Z"},
        ]
        out = import_from_model_gate(min_severity="high", max_age_days=30)
        assert out["scanned"] == 1
        assert out["filed_new"] == 1
        # Should have written a :ZeroDayPattern node
        write_cyphers = [c for c, _ in fake_graph["writes"]]
        assert any("MERGE (z:ZeroDayPattern" in c for c in write_cyphers)

    def test_import_skips_low_severity(self, fake_graph):
        from engine.zero_day_defense import import_from_model_gate
        fake_graph["data"] = [
            {"probe_id": "x.low", "category": "refusal_calibration",
             "severity": "low", "title": "minor", "reason": "x",
             "model_spec": "openai:gpt-5", "ts": "2026-05-04T12:00:00Z"},
        ]
        out = import_from_model_gate(min_severity="high", max_age_days=30)
        assert out["filed_new"] == 0
