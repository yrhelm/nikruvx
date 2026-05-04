"""Tests for engine.phi_detector and engine.phi_lineage.

The graph-touching functions are exercised through the `fake_graph`
fixture (defined in conftest.py) which monkey-patches `run_read` /
`run_write` with in-memory stand-ins. No live Neo4j needed.
"""
from __future__ import annotations
import pytest

from engine import phi_detector, phi_lineage
from engine.phi_lineage import (
    CANONICAL_BAA_TERMS,
    REQUIRED_TERMS_FOR_PHI,
    CallEvent,
    _ensure_ids,
    find_broken_baa_chains,
    record_call,
    register_baa,
    register_vendor,
    replay_incident,
    seed_baa_terms,
    stats,
    vendor_coverage_report,
)


# ===========================================================================
# PHI detector
# ===========================================================================
class TestPHIDetector:
    """The Safe Harbor 18-identifier scanner — pure regex, no graph."""

    def test_clean_text_returns_no_detections(self):
        assert phi_detector.detect("The quick brown fox") == []
        assert phi_detector.has_phi("The quick brown fox") is False
        assert phi_detector.summarize("hello world")["has_phi"] is False

    def test_ssn_caught(self):
        d = {x.identifier_type for x in phi_detector.detect("SSN: 123-45-6789")}
        assert "ssn" in d

    def test_phone_email_url_ip(self):
        text = ("Contact: (415) 555-0199 or jane@example.com. "
                "Visit https://example.org from 10.0.0.1.")
        types = {x.identifier_type for x in phi_detector.detect(text)}
        assert {"phone", "email", "url", "ipv4"} <= types

    def test_mrn_pattern(self):
        text = "MRN: 7829341 admitted today."
        types = {x.identifier_type for x in phi_detector.detect(text)}
        assert "mrn" in types

    def test_name_heuristic(self):
        text = "Patient Mrs. Jane Doe presented with cough."
        types = {x.identifier_type for x in phi_detector.detect(text)}
        assert "name" in types

    def test_dob_heuristic(self):
        text = "DOB: 04/12/1962 with htn."
        types = {x.identifier_type for x in phi_detector.detect(text)}
        assert "dob" in types

    def test_dates_iso_and_full(self):
        text = "Followup 2026-04-30 also see 04/30/2026."
        types = {x.identifier_type for x in phi_detector.detect(text)}
        assert {"date_iso", "date_full"} <= types

    def test_credit_card_requires_luhn(self):
        # 4111111111111111 passes Luhn (Visa test card)
        valid = phi_detector.detect("Card 4111111111111111 on file")
        assert any(d.identifier_type == "credit_card" for d in valid)
        # 4111111111111112 fails Luhn
        invalid = phi_detector.detect("Card 4111111111111112 on file")
        assert all(d.identifier_type != "credit_card" for d in invalid)

    def test_summarize_returns_count_per_type(self):
        text = "Mrs. Jane Doe MRN: 1234567 SSN: 123-45-6789"
        out = phi_detector.summarize(text)
        assert out["has_phi"] is True
        assert out["total_hits"] >= 3
        types_set = {d["identifier_type"] for d in out["detections"]}
        assert {"name", "mrn", "ssn"} <= types_set


# ===========================================================================
# _ensure_ids — pure data-massaging, no graph
# ===========================================================================
class TestEnsureIds:
    def test_fills_missing_ts_session_model_source_hash(self):
        ev = CallEvent(prompt_text="hello", vendor_name="OpenAI",
                       model_name="gpt-4o")
        out = _ensure_ids(ev)
        assert out.ts != ""
        assert out.session_id and out.session_id.startswith("sess:")
        assert out.vendor_id == "openai"
        assert out.model_id == "openai:gpt-4o"
        assert out.source_id == "unknown-source"
        assert len(out.raw_payload_hash) == 64  # sha256 hex

    def test_existing_values_preserved(self):
        ev = CallEvent(prompt_text="x", session_id="sess:custom",
                       vendor_id="anthropic", vendor_name="Anthropic",
                       model_id="anthropic:claude-3-5-sonnet",
                       source_id="my-emr")
        out = _ensure_ids(ev)
        assert out.session_id == "sess:custom"
        assert out.model_id == "anthropic:claude-3-5-sonnet"
        assert out.source_id == "my-emr"


# ===========================================================================
# Catalog upserts — fake_graph captures the writes
# ===========================================================================
class TestSeedBAATerms:
    def test_seeds_canonical_count(self, fake_graph):
        n = seed_baa_terms()
        assert n == len(CANONICAL_BAA_TERMS) == 12
        assert len(fake_graph["writes"]) == 1
        cypher, params = fake_graph["writes"][0]
        assert "MERGE (t:BAATerm" in cypher
        assert len(params["rows"]) == 12
        # Every row has the required keys
        for row in params["rows"]:
            assert {"id", "clause", "citation"} <= set(row.keys())

    def test_term_citations_reference_hipaa_or_baa_or_gdpr(self):
        for tid, _clause, citation in CANONICAL_BAA_TERMS:
            up = citation.upper()
            assert ("164." in citation) or ("BAA" in up) or ("GDPR" in up) \
                or ("HITECH" in up), f"{tid} has bare citation: {citation}"

    def test_required_terms_subset_of_catalog(self):
        catalog_ids = {tid for tid, *_ in CANONICAL_BAA_TERMS}
        assert set(REQUIRED_TERMS_FOR_PHI) <= catalog_ids


class TestRegisterVendor:
    def test_writes_vendor_with_regions(self, fake_graph):
        register_vendor(vendor_id="openai", name="OpenAI",
                        operates_in_regions=["us-east-1", "us-west-2"])
        assert any("MERGE (v:AIVendor" in c for c, _ in fake_graph["writes"])
        params = fake_graph["writes"][0][1]
        assert params["vendor_id"] == "openai"
        assert "us-east-1" in params["regions"]

    def test_subprocessors_emit_second_query(self, fake_graph):
        register_vendor(vendor_id="acme-llm", name="Acme",
                        subprocessors=["aws", "datadog"])
        # 2 writes: vendor itself + subprocessor edges
        assert len(fake_graph["writes"]) == 2
        sub_cypher = fake_graph["writes"][1][0]
        assert "USES_SUBPROCESSOR" in sub_cypher


class TestRegisterBAA:
    def test_baa_writes_terms(self, fake_graph):
        register_baa(baa_id="baa-1",
                     counterparty_vendor_id="openai",
                     effective="2026-01-01",
                     expires="2027-01-01",
                     term_ids=["baa_signed", "encryption_at_rest"])
        assert len(fake_graph["writes"]) == 1
        cypher, params = fake_graph["writes"][0]
        assert "MERGE (b:BAA" in cypher
        assert "INCLUDES_TERM" in cypher
        assert params["terms"] == ["baa_signed", "encryption_at_rest"]


# ===========================================================================
# record_call — verify it builds the right Cypher params + emits sinks
# ===========================================================================
class TestRecordCall:
    def test_record_call_with_phi_writes_correct_params(self, fake_graph):
        ev = CallEvent(
            prompt_text="Patient Mrs. Jane Doe MRN: 7829341 on lisinopril.",
            response_text="Monitor BP weekly.",
            actor_id="clinician:doe@hosp.org",
            application_name="clinical-copilot",
            model_name="gpt-4o-2024-11-20",
            vendor_id="openai", vendor_name="OpenAI",
            region_code="us-east-1",
            source_name="epic-emr-prod",
            sinks=[{"id": "openai-traffic-logs", "kind": "log",
                    "encrypted": True}],
        )
        result = record_call(ev)
        assert result["prompt_id"].startswith("prompt:")
        assert result["response_id"].startswith("resp:")
        assert result["phi_in_prompt"]["has_phi"] is True
        # PHI detector should pick up at least name + mrn from the prompt
        prompt_types = result["phi_in_prompt"]["types"]
        assert "name" in prompt_types and "mrn" in prompt_types

    def test_record_call_writes_main_and_sinks(self, fake_graph):
        ev = CallEvent(
            prompt_text="Patient Mrs. Jane Doe.",
            vendor_id="openai", vendor_name="OpenAI",
            model_name="gpt-4o", region_code="us-east-1",
            source_name="emr",
            sinks=[{"id": "log-1", "kind": "log"}],
        )
        record_call(ev)
        # First write is the main MERGE chain; second is the sinks query
        assert len(fake_graph["writes"]) == 2
        main_cypher = fake_graph["writes"][0][0]
        assert "MERGE (p:Prompt" in main_cypher
        assert "MERGE (m:AIModel" in main_cypher
        sink_cypher = fake_graph["writes"][1][0]
        assert "LOGGED_IN" in sink_cypher

    def test_record_call_no_sinks_writes_only_main(self, fake_graph):
        ev = CallEvent(prompt_text="hi", vendor_id="openai",
                       vendor_name="OpenAI", model_name="gpt-4o",
                       region_code="us-east-1", source_name="emr")
        record_call(ev)
        assert len(fake_graph["writes"]) == 1


# ===========================================================================
# Audit queries — exercise the read path + ensure results pass through
# ===========================================================================
class TestFindBrokenBAAChains:
    def test_returns_seeded_rows(self, fake_graph):
        fake_graph["data"] = [
            {"prompt_id": "prompt:abc", "ts": "2026-05-03T12:00:00Z",
             "vendor": "OpenAI", "model": "gpt-4o", "gap_kind": "NO_BAA",
             "baa_id": "", "missing_terms": REQUIRED_TERMS_FOR_PHI},
        ]
        rows = find_broken_baa_chains(window_hours=1)
        assert len(rows) == 1
        assert rows[0]["gap_kind"] == "NO_BAA"
        assert rows[0]["vendor"] == "OpenAI"

    def test_empty_when_nothing_seeded(self, fake_graph):
        fake_graph["data"] = []
        assert find_broken_baa_chains() == []


class TestReplayIncident:
    def test_returns_first_row(self, fake_graph):
        fake_graph["data"] = [{
            "prompt_id": "prompt:abc",
            "ts": "2026-05-03T12:00:00Z",
            "hops": [
                {"label": "Application", "id": "clinical-copilot",
                 "name": "clinical-copilot", "kind": "", "baa": "", "baa_terms": []},
                {"label": "AIModel", "id": "openai:gpt-4o",
                 "name": "gpt-4o", "kind": "", "baa": "", "baa_terms": []},
                {"label": "AIVendor", "id": "openai",
                 "name": "OpenAI", "kind": "", "baa": "baa-openai-2026",
                 "baa_terms": ["baa_signed", "encryption_at_rest"]},
            ],
        }]
        out = replay_incident("prompt:abc")
        assert out["prompt_id"] == "prompt:abc"
        assert len(out["hops"]) == 3
        assert out["hops"][2]["baa"] == "baa-openai-2026"

    def test_unknown_prompt_returns_empty_hops(self, fake_graph):
        fake_graph["data"] = []
        out = replay_incident("prompt:nonexistent")
        assert out["prompt_id"] == "prompt:nonexistent"
        assert out["hops"] == []


class TestVendorCoverage:
    def test_passes_required_terms_to_query(self, fake_graph):
        fake_graph["data"] = [
            {"vendor_id": "openai", "vendor_name": "OpenAI",
             "phi_calls": 42, "baa_id": "baa-1",
             "missing_terms": ["zero_retention"]},
        ]
        rows = vendor_coverage_report()
        assert len(rows) == 1
        assert rows[0]["missing_terms"] == ["zero_retention"]


class TestStats:
    def test_returns_first_row(self, fake_graph):
        fake_graph["data"] = [{
            "prompts": 100, "responses": 100, "phi_elements": 250,
            "vendors": 4, "baas": 2, "sinks": 6, "sources": 3,
        }]
        s = stats()
        assert s["prompts"] == 100
        assert s["vendors"] == 4

    def test_empty_returns_empty_dict(self, fake_graph):
        fake_graph["data"] = []
        assert stats() == {}


# ===========================================================================
# Cross-module sanity
# ===========================================================================
def test_canonical_terms_non_empty_and_unique():
    ids = [tid for tid, *_ in CANONICAL_BAA_TERMS]
    assert len(ids) == len(set(ids)), "duplicate term ids"
    assert len(ids) >= 10, "BAA term catalog suspiciously small"


@pytest.mark.parametrize("required_term", REQUIRED_TERMS_FOR_PHI)
def test_every_required_term_has_a_citation(required_term):
    by_id = {tid: cite for tid, _, cite in CANONICAL_BAA_TERMS}
    citation = by_id[required_term]
    assert citation, f"{required_term} has empty citation"
