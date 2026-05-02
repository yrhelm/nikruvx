"""Tests for engine.osi_classifier."""
from __future__ import annotations
import pytest

from engine.osi_classifier import classify, LAYER_NAMES, CWE_TO_LAYERS


@pytest.mark.parametrize(
    "description,cwes,expected_layer",
    [
        ("SQL injection in login form leading to remote code execution", ["CWE-89"], 7),
        ("Insecure deserialization of XML data via XXE",                ["CWE-502"], 6),
        ("ARP spoofing on the local subnet",                            [],          2),
        ("TLS certificate validation bypass",                           [],          6),
        ("Prompt injection in LangChain RAG pipeline",                  [],          7),
        ("Power side-channel attack on cryptographic chip",             ["CWE-1300"],1),
        ("TCP SYN flood causing denial of service",                     [],          4),
        ("Session fixation in PHPSESSID cookie",                        [],          5),
        ("ICMP redirect / IP fragmentation",                            [],          3),
    ],
)
def test_classify_hits_expected_layer(description, cwes, expected_layer):
    hits = classify(description, cwes)
    layers = [h["layer"] for h in hits]
    assert expected_layer in layers, (
        f"expected layer {expected_layer} for description={description!r}, got {layers}"
    )


def test_classify_returns_sorted_by_confidence_desc():
    hits = classify("XSS via cross-site scripting and SQL injection", ["CWE-79", "CWE-89"])
    confidences = [h["confidence"] for h in hits]
    assert confidences == sorted(confidences, reverse=True)


def test_classify_falls_back_to_application_when_no_signal():
    hits = classify("This is a generic vulnerability with nothing specific.")
    assert len(hits) == 1
    assert hits[0]["layer"] == 7


def test_classify_respects_threshold_and_max_layers():
    hits = classify("SQLi and XSS and prompt injection and deserialization",
                    ["CWE-89", "CWE-79", "CWE-502"], threshold=0.3, max_layers=2)
    assert len(hits) <= 2
    for h in hits:
        assert h["confidence"] >= 0.3


def test_layer_names_complete_and_in_range():
    assert set(LAYER_NAMES.keys()) == {1, 2, 3, 4, 5, 6, 7}


def test_cwe_table_layers_are_valid_osi_layers():
    for cwe, layers in CWE_TO_LAYERS.items():
        assert layers, f"{cwe} has empty layers"
        for L in layers:
            assert 1 <= L <= 7, f"{cwe} maps to invalid layer {L}"


def test_classify_normalizes_bare_cwe_id():
    hits_a = classify("SQL injection", ["CWE-89"])
    hits_b = classify("SQL injection", ["89"])
    assert {h["layer"] for h in hits_a} == {h["layer"] for h in hits_b}
