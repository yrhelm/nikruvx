"""Tests for external_findings CSV importer + prioritizer re-scoring."""
from __future__ import annotations
import pytest

from ingest.external_findings import (
    Finding, detect_format, parse_csv, _parse_wiz, _parse_snyk,
    _parse_tenable, _parse_qualys, _parse_generic,
)
from engine.external_finding_prioritizer import (
    ScoredFinding, _band, _matches_forecast, _SEVERITY_TO_BASE,
    re_score, re_score_batch, persist_batch, list_batches, list_findings,
    to_export_csv,
)


# ===========================================================================
# Format detection
# ===========================================================================
class TestFormatDetection:
    def test_detect_wiz(self):
        headers = ["CVE", "Severity", "Resource", "Subscription", "Wiz Score"]
        assert detect_format(headers) == "wiz"

    def test_detect_snyk(self):
        headers = ["ISSUE_ID", "PACKAGE", "PROJECT_NAME", "INTRODUCED THROUGH"]
        assert detect_format(headers) == "snyk"

    def test_detect_tenable(self):
        headers = ["Plugin Name", "Plugin ID", "Host", "Severity", "CVE"]
        assert detect_format(headers) == "tenable"

    def test_detect_qualys(self):
        headers = ["QID", "Vuln Status", "Asset_Name", "CVSS Base"]
        assert detect_format(headers) == "qualys"

    def test_unknown_falls_to_generic(self):
        headers = ["foo", "bar", "baz"]
        assert detect_format(headers) == "generic"


# ===========================================================================
# Parsers
# ===========================================================================
class TestParsers:
    def test_wiz_basic_row(self):
        row = {
            "CVE": "CVE-2024-3094", "Severity": "Critical",
            "Package Name": "xz-utils", "Version": "5.6.0",
            "Resource ID": "vm-prod-1", "CVSS Score": "9.8",
            "Has Fix": "true",
        }
        f = _parse_wiz(row)
        assert f.source == "wiz"
        assert f.cve_id == "CVE-2024-3094"
        assert f.package == "xz-utils"
        assert f.original_severity == "critical"
        assert f.original_cvss == 9.8
        assert f.has_fix is True
        assert f.asset_id == "vm-prod-1"

    def test_snyk_basic_row(self):
        row = {
            "ISSUE_ID": "SNYK-PYTHON-DJANGO-12345",
            "CVE": "CVE-2024-9999",
            "PACKAGE": "django",
            "VERSION": "4.2.0",
            "ECOSYSTEM": "pypi",
            "SEVERITY": "high",
            "CVSS_SCORE": "7.5",
            "PROJECT_NAME": "myapp",
            "FIXABLE": "true",
        }
        f = _parse_snyk(row)
        assert f.source == "snyk"
        assert f.external_id == "SNYK-PYTHON-DJANGO-12345"
        assert f.cve_id == "CVE-2024-9999"
        assert f.package == "django"
        assert f.ecosystem == "pypi"
        assert f.original_severity == "high"
        assert f.has_fix is True

    def test_tenable_basic_row(self):
        row = {
            "Plugin ID": "12345",
            "Plugin Name": "Apache Log4j RCE",
            "CVE": "CVE-2021-44228, CVE-2021-45046",
            "Severity": "Critical",
            "CVSS3 Base Score": "10.0",
            "Host": "10.0.0.1",
            "Exploit Available": "true",
        }
        f = _parse_tenable(row)
        assert f.source == "tenable"
        # Should pick first CVE only
        assert f.cve_id == "CVE-2021-44228"
        assert f.original_severity == "critical"
        assert f.exploitable is True
        assert f.asset_id == "10.0.0.1"

    def test_qualys_basic_row(self):
        row = {
            "QID": "98765",
            "CVE ID": "CVE-2024-1234",
            "Severity": "5",
            "CVSS3.1 Base": "9.0",
            "Asset Name": "qualys-host-1",
            "Title": "Critical Memory Corruption",
        }
        f = _parse_qualys(row)
        assert f.source == "qualys"
        assert f.external_id == "98765"
        assert f.cve_id == "CVE-2024-1234"
        assert f.asset_id == "qualys-host-1"

    def test_generic_fallback(self):
        row = {"CVE": "CVE-2024-1", "Severity": "high", "Package": "foo"}
        f = _parse_generic(row)
        assert f.source == "generic"
        assert f.cve_id == "CVE-2024-1"

    def test_full_csv_parse_wiz(self):
        csv_text = (
            "CVE,Severity,Package Name,Version,Resource ID,CVSS Score,Has Fix\n"
            "CVE-2024-3094,Critical,xz-utils,5.6.0,vm-1,9.8,true\n"
            "CVE-2021-44228,Critical,log4j-core,2.14.0,k8s-1,10.0,true\n"
        )
        source, findings = parse_csv(csv_text)
        assert source == "wiz"
        assert len(findings) == 2
        assert findings[0].cve_id == "CVE-2024-3094"
        assert findings[1].package == "log4j-core"


# ===========================================================================
# Re-scoring (with fake_graph)
# ===========================================================================
class TestRescoring:
    def _f(self, **kw):
        defaults = {"source": "wiz", "external_id": "x"}
        defaults.update(kw)
        return Finding(**defaults)

    def test_band_thresholds(self):
        assert _band(85) == "critical"
        assert _band(65) == "high"
        assert _band(45) == "medium"
        assert _band(20) == "low"

    def test_severity_to_base_fallback(self):
        # When no CVSS, fall back to severity-based base score
        assert _SEVERITY_TO_BASE["critical"] > _SEVERITY_TO_BASE["high"]
        assert _SEVERITY_TO_BASE["high"] > _SEVERITY_TO_BASE["medium"]

    def test_no_environment_match_lowers_score(self, fake_graph):
        # No CVE in graph, no apps, no PoC, no KEV
        fake_graph["data"] = []
        f = self._f(cve_id="CVE-9999-9999", package="some-pkg",
                    original_severity="critical", original_cvss=9.0)
        s = re_score(f)
        # 90 base - 10 (not in inventory) = 80, still critical band
        # but lower than the original 9.0/10*100 = 90
        assert any("not in current inventory" in a["reason"] for a in s.adjustments)

    def test_kev_bumps_score(self, fake_graph):
        # Simulate CVE in KEV
        fake_graph["data"] = [{"id": "CVE-2021-44228", "cvss": 10.0,
                                "severity": "critical", "in_kev": True}]
        f = self._f(cve_id="CVE-2021-44228", original_severity="high",
                    original_cvss=7.0)
        s = re_score(f)
        assert s.in_kev is True
        assert any("KEV" in a["reason"] for a in s.adjustments)
        # Note: since fake_graph returns the same data for every query,
        # other adjustments might also fire, but KEV bump should be present

    def test_inventory_match_bumps_score(self, fake_graph):
        # CVE not in graph but package is in inventory
        fake_graph["data"] = [
            {"key": "myapp", "name": "MyApp", "category": "first_party_web",
             "trust_score": 70},
        ]
        f = self._f(cve_id=None, package="vulnpkg",
                    original_severity="medium", original_cvss=5.0)
        s = re_score(f)
        assert s.affected_apps and len(s.affected_apps) >= 1
        assert any("inventory" in a["reason"] for a in s.adjustments)

    def test_has_fix_bumps_score(self, fake_graph):
        fake_graph["data"] = []
        f = self._f(cve_id=None, original_cvss=5.0, has_fix=True)
        s = re_score(f)
        assert any("fix available" in a["reason"] for a in s.adjustments)

    def test_exploitable_bumps_score(self, fake_graph):
        fake_graph["data"] = []
        f = self._f(cve_id=None, original_cvss=5.0, exploitable=True)
        s = re_score(f)
        assert any("exploitable" in a["reason"] for a in s.adjustments)

    def test_score_capped_at_100(self, fake_graph):
        fake_graph["data"] = [{"id": "CVE-X", "cvss": 10, "severity": "critical",
                                "in_kev": True}]
        f = self._f(cve_id="CVE-X", original_cvss=10.0,
                    has_fix=True, exploitable=True)
        s = re_score(f)
        assert 0 <= s.nikruvx_score <= 100

    def test_adjustments_have_required_fields(self, fake_graph):
        fake_graph["data"] = []
        f = self._f(cve_id=None, original_cvss=5.0, has_fix=True, exploitable=True)
        s = re_score(f)
        for a in s.adjustments:
            assert "delta" in a and "reason" in a


# ===========================================================================
# Forecast keyword matching
# ===========================================================================
class TestForecastMatching:
    def test_memory_corruption_matches_forecast(self):
        f = Finding(source="wiz", external_id="x",
                    title="Heap buffer overflow in libxml2",
                    description="Use-after-free in XML parsing")
        assert _matches_forecast(f) is True

    def test_log4shell_class_matches_forecast(self):
        f = Finding(source="wiz", external_id="x",
                    title="JNDI lookup leads to RCE",
                    description="Deserialization vulnerability")
        assert _matches_forecast(f) is True

    def test_benign_does_not_match(self):
        f = Finding(source="wiz", external_id="x",
                    title="Outdated TLS cipher suite",
                    description="TLS 1.0 supported")
        assert _matches_forecast(f) is False


# ===========================================================================
# Re-score batch + export
# ===========================================================================
class TestBatchAndExport:
    def test_re_score_batch_returns_one_per_finding(self, fake_graph):
        fake_graph["data"] = []
        findings = [
            Finding(source="wiz", external_id="1", cve_id="CVE-1",
                    original_cvss=9.0),
            Finding(source="wiz", external_id="2", cve_id="CVE-2",
                    original_cvss=5.0),
        ]
        scored = re_score_batch(findings)
        assert len(scored) == 2
        # Higher CVSS should produce higher score
        assert scored[0].nikruvx_score > scored[1].nikruvx_score

    def test_export_csv_has_all_columns(self, fake_graph):
        fake_graph["data"] = []
        scored = [re_score(Finding(source="wiz", external_id="1",
                                    cve_id="CVE-1", original_cvss=8.0,
                                    title="Bad bug"))]
        out = to_export_csv(scored)
        assert "nikruvx_score" in out
        assert "priority_band" in out
        assert "recommended_action" in out
        assert "CVE-1" in out


# ===========================================================================
# Persistence
# ===========================================================================
class TestPersistence:
    def test_persist_batch_writes_findings(self, fake_graph):
        fake_graph["data"] = []
        scored = [
            re_score(Finding(source="wiz", external_id=f"x{i}",
                              cve_id=f"CVE-{i}", original_cvss=8.0))
            for i in range(3)
        ]
        bid = persist_batch(scored, source="wiz", batch_label="test-upload")
        assert bid.startswith("fb:")
        # First write is the FindingBatch + findings query
        cypher = fake_graph["writes"][0][0]
        assert "MERGE (b:FindingBatch" in cypher
        assert "MERGE (f:ExternalFinding" in cypher

    def test_list_batches(self, fake_graph):
        fake_graph["data"] = [{
            "batch_id": "fb:abc", "source": "wiz", "label": "test",
            "uploaded_at": "2026-05-04T12:00:00Z", "count": 42,
        }]
        rows = list_batches()
        assert len(rows) == 1
        assert rows[0]["count"] == 42

    def test_list_findings_filtered(self, fake_graph):
        fake_graph["data"] = [{
            "id": "ef:1", "cve_id": "CVE-1", "package": "x",
            "title": "bad", "original_severity": "critical",
            "original_cvss": 9.0, "nikruvx_score": 95.0,
            "priority_band": "critical", "in_kev": True, "has_poc": True,
            "coverage_ratio": 0.0, "recommended_action": "patch now",
            "adjustments_json": "[]", "batch_id": "fb:1", "source": "wiz",
            "version": "1.0",
        }]
        rows = list_findings(priority_band="critical")
        assert len(rows) == 1
        assert rows[0]["priority_band"] == "critical"
