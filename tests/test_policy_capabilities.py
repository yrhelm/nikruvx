"""Tests for engine.policy_capabilities."""
from __future__ import annotations

from engine.policy_capabilities import (
    ALL_CAPS, CONTROL_CLASSES, by_name, for_capability, all_caps_with_classes,
)


def test_every_control_class_targets_a_known_capability():
    for cc in CONTROL_CLASSES:
        for cap in cc.capabilities:
            assert cap in ALL_CAPS, f"{cc.name} targets unknown capability {cap}"


def test_every_capability_has_at_least_one_mitigation_or_is_known_gap():
    """If a capability has zero mitigations, that's tracked as a known gap."""
    coverage = all_caps_with_classes()
    known_gaps = {"WRITE_FS"}    # currently no control class explicitly covers WRITE_FS
    for cap in ALL_CAPS:
        if cap in known_gaps:
            continue
        assert coverage.get(cap), f"capability {cap} has no mitigation classes"


def test_control_class_layers_in_range():
    for cc in CONTROL_CLASSES:
        assert 1 <= cc.layer <= 7, f"{cc.name} has invalid layer {cc.layer}"


def test_by_name_lookup_roundtrips():
    for cc in CONTROL_CLASSES:
        assert by_name(cc.name) is cc


def test_for_capability_returns_only_relevant_classes():
    for cap in ALL_CAPS:
        for cc in for_capability(cap):
            assert cap in cc.capabilities


def test_critical_capabilities_have_multiple_mitigations():
    """RCE / AUTH_BYPASS / DATA_EXFIL must be covered by 2+ classes each."""
    coverage = all_caps_with_classes()
    for must_have in ("RCE", "AUTH_BYPASS", "DATA_EXFIL"):
        assert len(coverage[must_have]) >= 2, (
            f"capability {must_have} only has {coverage.get(must_have)}"
        )
