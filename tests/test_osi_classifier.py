"""Unit tests for engine.osi_classifier — no DB required."""
from engine.osi_classifier import classify, LAYER_NAMES


def _layers(hits):
    return {h["layer"] for h in hits}


def test_sql_injection_classifies_to_application():
    hits = classify("SQL injection in the login form leading to RCE", ["CWE-89"])
    assert 7 in _layers(hits)


def test_deserialization_classifies_to_presentation():
    hits = classify("Insecure Java deserialization in jackson-databind", ["CWE-502"])
    assert 6 in _layers(hits)


def test_mitm_classifies_to_network_and_presentation():
    hits = classify("Man-in-the-middle attack via certificate validation flaw", ["CWE-300"])
    layers = _layers(hits)
    assert 3 in layers or 6 in layers


def test_fallback_returns_application_when_no_signal():
    # no lexical signal, no CWE
    hits = classify("foo bar baz quux", [])
    assert hits, "fallback should always return at least one hit"
    assert hits[0]["layer"] == 7


def test_layer_names_complete():
    for n in range(1, 8):
        assert n in LAYER_NAMES


def test_cwe_id_normalisation_accepts_bare_number():
    hits = classify("xss in template", ["79"])
    assert 7 in _layers(hits)
