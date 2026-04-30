"""Unit tests for engine.risk_scoring."""
from engine.risk_scoring import (
    RiskInput, score, score_dict, _band, _age_factor,
    DEFAULT_CWE_SEVERITY, CWE_INHERENT_SEVERITY,
)


def test_band_thresholds():
    assert _band(95) == "CRITICAL+"
    assert _band(80) == "CRITICAL"
    assert _band(65) == "HIGH"
    assert _band(45) == "MEDIUM"
    assert _band(25) == "LOW"
    assert _band(5) == "INFO"


def test_critical_log4shell_like_input_scores_high():
    r = score(RiskInput(
        cvss_score=10.0, cwe_ids=["CWE-502"], osi_layers=[6, 7],
        poc_count=5, package_count=20, published="2024-12-01T00:00:00Z",
    ))
    assert r.score >= 80
    assert r.band in ("CRITICAL", "CRITICAL+")


def test_empty_input_yields_low_or_info_band():
    r = score(RiskInput())
    assert r.score < 40


def test_missing_cvss_does_not_raise():
    r = score(RiskInput(cwe_ids=["CWE-89"]))
    assert r.components["cvss"] == 0.0


def test_age_factor_clamped_to_floor():
    assert _age_factor("1990-01-01T00:00:00Z") == 0.7


def test_age_factor_recent_close_to_one():
    from datetime import datetime, timezone
    recent = datetime.now(timezone.utc).isoformat()
    assert _age_factor(recent) >= 0.99


def test_score_dict_round_trips():
    out = score_dict({"cvss_score": 9.8, "cwe_ids": ["CWE-89"], "osi_layers": [7],
                      "poc_count": 1, "package_count": 3})
    for k in ("score", "band", "components", "explanation"):
        assert k in out


def test_unknown_cwe_uses_default_severity():
    r = score(RiskInput(cvss_score=5.0, cwe_ids=["CWE-99999"]))
    assert r.components["cwe_severity"] == DEFAULT_CWE_SEVERITY


def test_known_cwe_severity_is_used():
    assert CWE_INHERENT_SEVERITY["CWE-78"] >= 9.0
