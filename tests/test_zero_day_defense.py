"""Tests for the Zero-Day Defense module — catalogs + recommender + persistence."""
from __future__ import annotations
import pytest

from engine import attack_catalog, defense_catalog, zero_day_catalog, zero_day_defense
from engine.attack_catalog import ATTACK_TECHNIQUES, AttackTechnique
from engine.defense_catalog import DEFENSE_TECHNIQUES, DefenseTechnique
from engine.zero_day_catalog import ZERO_DAY_PATTERNS, ZeroDayPattern, ai_discovered
from engine.zero_day_defense import (
    coverage_gaps, coverage_matrix, installed_coverage, list_defenses,
    list_patterns, list_techniques, recommend_defenses, recommend_for_pattern,
    seed_all, seed_attack_techniques, seed_defense_techniques,
    seed_zero_day_patterns, stats,
)


# ===========================================================================
# Catalog integrity
# ===========================================================================
class TestAttackCatalog:
    def test_at_least_50_techniques(self):
        assert len(ATTACK_TECHNIQUES) >= 50, \
            "v1 attack catalog should ship at least 50 techniques"

    def test_unique_ids(self):
        ids = [t.id for t in ATTACK_TECHNIQUES]
        assert len(ids) == len(set(ids)), "duplicate technique ids"

    def test_layers_in_range(self):
        for t in ATTACK_TECHNIQUES:
            assert 1 <= t.layer <= 7, f"{t.id} has invalid layer {t.layer}"

    def test_every_layer_has_at_least_one_technique(self):
        layers = {t.layer for t in ATTACK_TECHNIQUES}
        for ln in range(1, 8):
            assert ln in layers, f"OSI layer {ln} has no ATT&CK technique mapped"

    def test_technique_has_capabilities(self):
        for t in ATTACK_TECHNIQUES:
            assert t.capabilities, f"{t.id} has no capability tags"

    def test_atlas_techniques_present(self):
        ids = {t.id for t in ATTACK_TECHNIQUES}
        # AI/ML coverage — at least the headline ones
        for must_have in ("AML.T0051", "AML.T0052", "AML.T0048"):
            assert must_have in ids, f"missing critical ATLAS technique {must_have}"


class TestDefenseCatalog:
    def test_at_least_40_defenses(self):
        assert len(DEFENSE_TECHNIQUES) >= 40, \
            "v1 defense catalog should ship at least 40 defenses"

    def test_unique_ids(self):
        ids = [d.id for d in DEFENSE_TECHNIQUES]
        assert len(ids) == len(set(ids)), "duplicate defense ids"

    def test_tactics_in_known_set(self):
        valid = {"Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore"}
        for d in DEFENSE_TECHNIQUES:
            assert d.tactic in valid, f"{d.id} has unknown tactic {d.tactic}"

    def test_every_defense_counters_at_least_one_technique(self):
        for d in DEFENSE_TECHNIQUES:
            assert d.counters, f"{d.id} doesn't counter any technique"

    def test_llm_defenses_have_dedicated_prefix(self):
        llm = [d for d in DEFENSE_TECHNIQUES if d.id.startswith("D3-LLM-")]
        assert len(llm) >= 5, "v1 should ship at least 5 LLM-specific defenses"

    def test_critical_techniques_have_defenses(self):
        # Every TTP that touches our ALL_CAPS = {RCE, AUTH_BYPASS, DATA_EXFIL,
        # PHI_DISCLOSURE} should have at least one defense
        from engine.defense_catalog import for_attack
        for t in ATTACK_TECHNIQUES:
            if any(c in t.capabilities for c in ("RCE", "AUTH_BYPASS",
                                                 "DATA_EXFIL")):
                defenses = for_attack(t.id)
                assert defenses, f"{t.id} ({t.name}) has no defense mapped"


class TestZeroDayCatalog:
    def test_at_least_25_patterns(self):
        assert len(ZERO_DAY_PATTERNS) >= 25, \
            "v1 zero-day catalog should ship at least 25 patterns"

    def test_unique_ids(self):
        ids = [z.id for z in ZERO_DAY_PATTERNS]
        assert len(ids) == len(set(ids)), "duplicate pattern ids"

    def test_severities_valid(self):
        valid = {"critical", "high", "medium", "low"}
        for z in ZERO_DAY_PATTERNS:
            assert z.severity in valid

    def test_every_pattern_uses_known_techniques(self):
        known = {t.id for t in ATTACK_TECHNIQUES}
        for z in ZERO_DAY_PATTERNS:
            for tid in z.techniques:
                assert tid in known, \
                    f"{z.id} uses unknown technique {tid}"

    def test_at_least_one_ai_discovered(self):
        assert len(ai_discovered()) >= 2, \
            "v1 should include at least 2 AI-discovered zero-days"

    def test_supply_chain_canonicals_present(self):
        ids = {z.id for z in ZERO_DAY_PATTERNS}
        for must_have in ("ZD-2024-XZ-UTILS", "ZD-2021-LOG4SHELL",
                          "ZD-2024-BIG-SLEEP-SQLITE"):
            assert must_have in ids, f"missing canonical pattern {must_have}"


# ===========================================================================
# Recommender
# ===========================================================================
class TestRecommender:
    def test_recommend_for_known_technique(self):
        out = recommend_defenses("T1190")
        assert "technique" in out
        assert out["defense_count"] >= 2
        # Harden tactic should rank first
        first_tactic = out["defenses"][0]["tactic"]
        assert first_tactic == "Harden", \
            f"expected Harden first, got {first_tactic}"

    def test_recommend_for_unknown_technique(self):
        out = recommend_defenses("T9999.NEVER")
        assert "error" in out

    def test_recommend_for_pattern(self):
        out = recommend_for_pattern("ZD-2021-LOG4SHELL")
        assert out["pattern"]["id"] == "ZD-2021-LOG4SHELL"
        assert out["defense_count"] >= 2
        assert len(out["techniques"]) >= 1

    def test_recommend_for_unknown_pattern(self):
        out = recommend_for_pattern("ZD-NONEXISTENT")
        assert "error" in out

    def test_atlas_pattern_recommends_llm_defenses(self):
        out = recommend_for_pattern("ZD-AML-INDIRECT-INJECTION")
        defense_ids = {d["id"] for d in out["defenses"]}
        # At least one LLM-specific defense should appear
        assert any(d.startswith("D3-LLM-") for d in defense_ids), \
            "expected at least one D3-LLM-* defense for indirect injection"

    def test_xz_supply_chain_recommends_sbom_and_signing(self):
        out = recommend_for_pattern("ZD-2024-XZ-UTILS")
        defense_ids = {d["id"] for d in out["defenses"]}
        assert "D3-SBOM" in defense_ids, "xz pattern should include SBOM defense"
        assert "D3-CCSV" in defense_ids, "xz pattern should include code-signing defense"


# ===========================================================================
# Coverage analysis
# ===========================================================================
class TestCoverage:
    def test_coverage_matrix_includes_all_layers(self):
        m = coverage_matrix()
        assert len(m["by_layer"]) == 7
        assert m["total_techniques"] == len(ATTACK_TECHNIQUES)
        assert m["total_defenses"] == len(DEFENSE_TECHNIQUES)
        assert m["total_zero_day_patterns"] == len(ZERO_DAY_PATTERNS)

    def test_coverage_matrix_per_layer_consistency(self):
        m = coverage_matrix()
        for entry in m["by_layer"]:
            assert (entry["techniques_with_defense"] +
                    entry["techniques_uncovered"]) == entry["technique_count"]

    def test_gaps_are_techniques_with_no_defense(self):
        from engine.defense_catalog import for_attack
        for gap in coverage_gaps():
            assert not for_attack(gap["technique_id"]), \
                f"gap reported for {gap['technique_id']} but defense exists"


class TestInstalledCoverage:
    def test_installed_coverage_with_no_policies(self, fake_graph):
        # No policies in graph → every technique either has catalog defense
        # but no installation, or no catalog defense. None should be 'covered'.
        fake_graph["data"] = [
            {"technique_id": "T1190", "name": "Exploit Public-Facing Application",
             "tactic": "Initial Access", "layer": 7,
             "total_defenses": 3, "installed_controls": 0,
             "status": "has_defense_in_catalog_not_installed"},
            {"technique_id": "T1200", "name": "Hardware Additions",
             "tactic": "Initial Access", "layer": 1,
             "total_defenses": 0, "installed_controls": 0,
             "status": "no_catalog_defense"},
        ]
        out = installed_coverage()
        statuses = {t["status"] for t in out["techniques"]}
        assert "covered" not in statuses
        assert "has_defense_in_catalog_not_installed" in statuses


# ===========================================================================
# List queries (filter logic)
# ===========================================================================
class TestListing:
    def test_list_patterns_filter_layer(self):
        out = list_patterns(layer=7)
        assert all(p["layer"] == 7 for p in out)

    def test_list_patterns_filter_ai_only(self):
        # ai_only is broadened to include both AI-discovered (real findings)
        # and AI-anticipated (forecast wave) — anything AI-related.
        out = list_patterns(ai_only=True)
        assert all(p["ai_discovered"] or p["ai_anticipated"] for p in out)
        assert len(out) >= 10, "should include forecast wave + real finds"

    def test_list_patterns_filter_severity(self):
        out = list_patterns(severity="critical")
        assert all(p["severity"] == "critical" for p in out)

    def test_list_techniques_filter_tactic(self):
        out = list_techniques(tactic="Initial Access")
        assert all(t["tactic"] == "Initial Access" for t in out)
        assert len(out) >= 1

    def test_list_techniques_filter_layer(self):
        out = list_techniques(layer=7)
        assert all(t["layer"] == 7 for t in out)

    def test_list_defenses_filter_tactic(self):
        out = list_defenses(tactic="Harden")
        assert all(d["tactic"] == "Harden" for d in out)
        assert len(out) >= 5


# ===========================================================================
# Seeding (with fake_graph)
# ===========================================================================
class TestSeeding:
    def test_seed_attack_techniques_writes_all(self, fake_graph):
        n = seed_attack_techniques()
        assert n == len(ATTACK_TECHNIQUES)
        assert len(fake_graph["writes"]) == 1
        cypher, params = fake_graph["writes"][0]
        assert "MERGE (t:AttackTechnique" in cypher
        assert len(params["rows"]) == len(ATTACK_TECHNIQUES)

    def test_seed_defenses_creates_countered_by_edges(self, fake_graph):
        n = seed_defense_techniques()
        assert n == len(DEFENSE_TECHNIQUES)
        cypher = fake_graph["writes"][0][0]
        assert "MERGE (d:DefenseTechnique" in cypher
        assert "COUNTERED_BY" in cypher

    def test_seed_zero_day_patterns_writes_techniques_edges(self, fake_graph):
        n = seed_zero_day_patterns()
        assert n == len(ZERO_DAY_PATTERNS)
        # Two writes: main MERGE + CVE bridge
        assert len(fake_graph["writes"]) >= 1
        first_cypher = fake_graph["writes"][0][0]
        assert "MERGE (z:ZeroDayPattern" in first_cypher
        assert "USES_TECHNIQUE" in first_cypher

    def test_seed_all_returns_counts(self, fake_graph):
        out = seed_all()
        assert out["attack_techniques"] == len(ATTACK_TECHNIQUES)
        assert out["defense_techniques"] == len(DEFENSE_TECHNIQUES)
        assert out["zero_day_patterns"] == len(ZERO_DAY_PATTERNS)


# ===========================================================================
# Stats
# ===========================================================================
def test_stats_returns_consistent_counts():
    s = stats()
    assert s["techniques"] == len(ATTACK_TECHNIQUES)
    assert s["defenses"] == len(DEFENSE_TECHNIQUES)
    assert s["patterns"] == len(ZERO_DAY_PATTERNS)
    assert s["ai_discovered_patterns"] >= 2
    assert s["techniques_uncovered_in_catalog"] == len(coverage_gaps())


@pytest.mark.parametrize("cap", ["RCE", "AUTH_BYPASS", "DATA_EXFIL"])
def test_critical_capabilities_have_defenses(cap):
    """Each high-impact capability has at least one TTP and a defense
    chain that mitigates it."""
    from engine.attack_catalog import for_capability
    from engine.defense_catalog import for_attack
    ttps = for_capability(cap)
    assert ttps, f"no TTP carries capability {cap}"
    covered = sum(1 for t in ttps if for_attack(t.id))
    assert covered >= 1, f"no defense covers any TTP carrying {cap}"


# ===========================================================================
# AI Threat Landscape — anticipatory-defense view
# ===========================================================================
class TestAiThreatLandscape:
    def test_at_least_10_anticipated_patterns(self):
        from engine.zero_day_catalog import ai_anticipated
        assert len(ai_anticipated()) >= 10, \
            "v1 should ship at least 10 AI-anticipated forecast patterns"

    def test_at_least_10_predicted_patterns(self):
        from engine.zero_day_catalog import predicted
        assert len(predicted()) >= 10, \
            "predicted/forecast catalog should be substantial"

    def test_immediate_window_non_empty(self):
        from engine.zero_day_catalog import by_mitigation_window
        assert len(by_mitigation_window("immediate")) >= 5, \
            "should ship at least 5 'immediate action' forecast items"

    def test_landscape_returns_structured_view(self):
        from engine.zero_day_defense import ai_threat_landscape
        out = ai_threat_landscape()
        assert "totals" in out
        assert "by_mitigation_window" in out
        assert "discovered" in out
        assert "anticipated_wave" in out
        assert out["totals"]["ai_anticipated"] >= 10
        assert out["totals"]["predicted_forecast"] >= 10

    def test_predicted_patterns_use_known_techniques(self):
        from engine.attack_catalog import ATTACK_TECHNIQUES
        from engine.zero_day_catalog import predicted
        known = {t.id for t in ATTACK_TECHNIQUES}
        for p in predicted():
            for tid in p.techniques:
                assert tid in known, \
                    f"predicted pattern {p.id} references unknown {tid}"

    def test_immediate_window_patterns_have_defenses(self):
        """Forecast patterns flagged 'immediate' must have defense chains —
        otherwise the user has nothing to do with the warning."""
        from engine.defense_catalog import for_attack
        from engine.zero_day_catalog import by_mitigation_window
        for p in by_mitigation_window("immediate"):
            covered = any(for_attack(tid) for tid in p.techniques)
            assert covered, (f"immediate-window pattern {p.id} has no defense "
                             f"chain — that defeats the point of the warning")
