"""Tests for engine.risk_scoring."""
from __future__ import annotations
import pytest

from engine.risk_scoring import (
    RiskInput, score, score_dict, CWE_INHERENT_SEVERITY, _band, _age_factor,
)


def test_critical_log4shell_scores_critical_band():
    r = score(RiskInput(
        cvss_score=9.8, cwe_ids=["CWE-502"], osi_layers=[6, 7],
        poc_count=2, package_count=12, published="2024-12-01T00:00:00Z",
    ))
    assert r.score >= 75
    assert r.band in ("CRITICAL", "CRITICAL+")


def test_low_severity_xss_lands_in_low_band():
    r = score(RiskInput(
        cvss_score=3.1, cwe_ids=["CWE-79"], osi_layers=[7],
        poc_count=0, package_count=1, published="2018-01-01T00:00:00Z",
    ))
    assert r.band in ("LOW", "INFO")


def test_no_cvss_still_produces_score_when_other_factors_present():
    r = score(RiskInput(
        cvss_score=None, cwe_ids=["CWE-300", "CWE-295"], osi_layers=[3, 6],
        poc_count=1, package_count=3, published="2023-06-01T00:00:00Z",
    ))
    assert r.score > 0
    assert "CWE" in " ".join(r.explanation)


def test_cvss_index_dominates_when_no_other_factors():
    low = score(RiskInput(cvss_score=2.0))
    high = score(RiskInput(cvss_score=9.5))
    assert high.score > low.score


def test_poc_factor_grows_monotonically_with_poc_count():
    counts = [0, 1, 2, 5, 10]
    scores = [score(RiskInput(cvss_score=5.0, poc_count=n)).score for n in counts]
    for a, b in zip(scores, scores[1:]):
        assert b >= a


def test_age_factor_decays_with_time():
    fresh = _age_factor("2025-01-01T00:00:00Z")
    old = _age_factor("2010-01-01T00:00:00Z")
    assert fresh > old
    assert old >= 0.7    # floor


def test_band_thresholds():
    assert _band(95) == "CRITICAL+"
    assert _band(80) == "CRITICAL"
    assert _band(65) == "HIGH"
    assert _band(45) == "MEDIUM"
    assert _band(25) == "LOW"
    assert _band(5) == "INFO"


def test_score_dict_works_with_plain_dicts():
    out = score_dict({
        "cvss_score": 7.5, "cwe_ids": ["CWE-89"], "osi_layers": [7],
        "poc_count": 0, "package_count": 0,
    })
    assert "score" in out and "band" in out and "components" in out


def test_cwe_severity_table_values_reasonable():
    for cwe, sev in CWE_INHERENT_SEVERITY.items():
        assert 0 < sev <= 10, f"{cwe} severity {sev} out of range"


def test_unknown_cwe_does_not_crash():
    r = score(RiskInput(cvss_score=5.0, cwe_ids=["CWE-9999999"]))
    assert r.score >= 0
