"""Verify CVSS v3 base-score parser in ingest.osv (§5.4 fix)."""
import pytest

# Avoid importing modules with hard third-party deps when unavailable
ingest_osv = pytest.importorskip("ingest.osv")
_base_score = ingest_osv._base_score
_cvss_from_record = ingest_osv._cvss_from_record


def test_log4shell_vector_scores_critical():
    # CVE-2021-44228 published vector
    s = _base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    assert s == 10.0


def test_low_severity_vector():
    # AC:H, PR:H, UI:R reduces severity
    s = _base_score("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
    assert s is not None
    assert 0 < s < 5.0


def test_invalid_returns_none():
    assert _base_score(None) is None
    assert _base_score("") is None
    assert _base_score("not-a-vector") is None
    assert _base_score("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P") is None
    # missing required metric
    assert _base_score("CVSS:3.1/AV:N/AC:L") is None


def test_cvss_from_record_prefers_numeric_score():
    rec = {"severity": [{"type": "CVSS_V31", "score": "9.8"}]}
    assert _cvss_from_record(rec) == (9.8, None)


def test_cvss_from_record_parses_vector():
    rec = {"severity": [{"type": "CVSS_V31",
                         "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    score, vec = _cvss_from_record(rec)
    assert score == 9.8
    assert vec.startswith("CVSS:3.1")


def test_no_severity_returns_none():
    assert _cvss_from_record({}) == (None, None)
