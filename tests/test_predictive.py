"""Tests for the predictive exposure-window engine."""
from __future__ import annotations
import math
import pytest

from engine import predictive
from engine.predictive import (
    COVERAGE_DAMPING, FORECAST_WEIGHT, MIN_VELOCITY,
    _parse_first_seen, _months_between,
    forecast_all, forecast_for_technique, summary,
    velocity_per_technique,
)
from engine.attack_catalog import ATTACK_TECHNIQUES


# ===========================================================================
# Date parsing
# ===========================================================================
class TestParseFirstSeen:
    def test_year_month_day(self):
        d = _parse_first_seen("2024-03-29")
        assert d is not None and d.year == 2024 and d.month == 3

    def test_year_month(self):
        d = _parse_first_seen("2024-03")
        assert d is not None and d.year == 2024 and d.month == 3

    def test_iso8601_zulu(self):
        d = _parse_first_seen("2024-03-29T00:00:00Z")
        assert d is not None and d.year == 2024

    def test_forecast_returns_none(self):
        assert _parse_first_seen("forecast: 2025") is None
        assert _parse_first_seen("forecast: 2025-Q3") is None

    def test_ongoing_returns_none(self):
        assert _parse_first_seen("ongoing") is None

    def test_empty_returns_none(self):
        assert _parse_first_seen("") is None
        assert _parse_first_seen(None) is None


# ===========================================================================
# Velocity
# ===========================================================================
class TestVelocity:
    def test_every_technique_has_velocity_entry(self):
        v = velocity_per_technique()
        assert len(v) == len(ATTACK_TECHNIQUES)

    def test_no_pattern_techniques_get_min_velocity(self):
        v = velocity_per_technique()
        for tid, info in v.items():
            if info["historical"] == 0 and info["forecast"] == 0:
                assert info["velocity_per_month"] == MIN_VELOCITY

    def test_t1190_has_real_velocity(self):
        # T1190 is used in many catalog patterns (Log4Shell, Spring4Shell,
        # MOVEit, regreSSHion, ProxyShell, etc.)
        v = velocity_per_technique()
        assert v["T1190"]["historical"] >= 4
        assert v["T1190"]["velocity_per_month"] > MIN_VELOCITY

    def test_forecast_weighted_correctly(self):
        # AML.T0048 is touched by many AI-anticipated forecast patterns
        v = velocity_per_technique()
        info = v.get("AML.T0048")
        if info and info["forecast"] > 0:
            # weighted_count must reflect the FORECAST_WEIGHT down-weighting
            expected_min = info["historical"]
            expected_max = info["historical"] + info["forecast"]
            assert expected_min <= info["weighted_count"] <= expected_max


# ===========================================================================
# Forecast list
# ===========================================================================
class TestForecastAll:
    def test_returns_one_entry_per_technique(self, fake_graph):
        out = forecast_all()
        assert len(out) == len(ATTACK_TECHNIQUES)

    def test_all_entries_have_required_fields(self, fake_graph):
        required = {"technique_id", "technique_name", "tactic", "layer",
                    "velocity_per_month", "exposed_apps", "coverage_ratio",
                    "expected_days_until_landing", "risk_index"}
        for f in forecast_all():
            missing = required - set(f.keys())
            assert not missing, f"{f.get('technique_id')} missing {missing}"

    def test_no_exposure_means_infinite_window(self, fake_graph):
        # fake_graph has no Application nodes, so every technique has 0 exposure
        for f in forecast_all():
            if f["exposed_apps"] == 0:
                assert (f["expected_days_until_landing"] == float("inf")
                        or math.isinf(f["expected_days_until_landing"]))

    def test_results_sorted_by_risk_index_desc(self, fake_graph):
        out = forecast_all()
        for i in range(len(out) - 1):
            assert out[i]["risk_index"] >= out[i + 1]["risk_index"]

    def test_recommended_defenses_capped_at_5(self, fake_graph):
        for f in forecast_all():
            assert len(f["recommended_defenses"]) <= 5


# ===========================================================================
# Forecast lookup
# ===========================================================================
class TestForecastForTechnique:
    def test_known_returns_record(self, fake_graph):
        f = forecast_for_technique("T1190")
        assert f is not None
        assert f["technique_id"] == "T1190"

    def test_unknown_returns_none(self, fake_graph):
        assert forecast_for_technique("T9999.NEVER") is None


# ===========================================================================
# Summary
# ===========================================================================
class TestSummary:
    def test_summary_keys_present(self, fake_graph):
        s = summary()
        for k in ("total_techniques", "techniques_with_exposure",
                  "techniques_landing_within_30_days",
                  "techniques_landing_within_90_days",
                  "techniques_with_no_installed_coverage",
                  "top_5_by_risk", "constants"):
            assert k in s

    def test_top_5_is_actually_5_or_less(self, fake_graph):
        s = summary()
        assert len(s["top_5_by_risk"]) <= 5

    def test_constants_exposed(self, fake_graph):
        s = summary()
        assert s["constants"]["coverage_damping"] == COVERAGE_DAMPING
        assert s["constants"]["forecast_weight"] == FORECAST_WEIGHT


# ===========================================================================
# Sanity invariants
# ===========================================================================
def test_coverage_damping_in_valid_range():
    assert 0.0 <= COVERAGE_DAMPING <= 1.0


def test_forecast_weight_less_than_historical():
    """Forecasts must count for less than confirmed observations."""
    assert 0.0 < FORECAST_WEIGHT < 1.0


def test_months_between_returns_at_least_one():
    from datetime import datetime, timezone
    d = datetime.now(timezone.utc)
    assert _months_between(d, d) >= 1.0   # never zero, even for same date


@pytest.mark.parametrize("layer", [1, 2, 3, 4, 5, 6, 7])
def test_every_layer_has_at_least_one_forecast(fake_graph, layer):
    out = forecast_all()
    assert any(f["layer"] == layer for f in out), \
        f"OSI layer {layer} has no forecast entry"
