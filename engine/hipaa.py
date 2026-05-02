"""
HIPAA / Privacy Rule / GDPR Article 9 / FDA SaMD mapping engine
================================================================
Maps Cyber Nexus internal concepts (capabilities, control classes, OWASP LLM
top 10, CWEs) to citable regulatory/compliance sections so reports can name
the actual rule that's in jeopardy.

References used (citations appear verbatim in generated reports):
  - HIPAA Security Rule:  45 CFR Part 164, Subpart C (164.302-164.318)
  - HIPAA Privacy Rule:   45 CFR Part 164, Subpart E (164.500-164.534)
  - HIPAA Breach Rule:    45 CFR 164.400-414
  - GDPR special category data: Article 9
  - FDA SaMD:             FDA "Pre-Specifications" + "Algorithm Change Protocol"
                          + Good Machine Learning Practices (GMLP) 2021
  - HHS OCR Guidance:     2024 NPRM strengthening Security Rule
"""

from __future__ import annotations

from dataclasses import dataclass

from .graph import run_read
from .healthcare import list_phi_packages_in_graph
from .posture import coverage as _posture_coverage
from .posture import gaps_for_cve as _gaps_for_cve


# ---------------------------------------------------------------------------
# Citation registry
# ---------------------------------------------------------------------------
@dataclass
class Citation:
    framework: str  # "HIPAA-Security" / "HIPAA-Privacy" / "GDPR" / "FDA-SaMD"
    section: str  # "164.312(a)(1)"
    title: str
    url: str = ""


HIPAA_SR = "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C"
HIPAA_PR = "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-E"
GDPR_A9 = "https://gdpr-info.eu/art-9-gdpr/"
FDA_GMLP = "https://www.fda.gov/medical-devices/software-medical-device-samd/good-machine-learning-practice-medical-device-development-guiding-principles"


# Capability -> [Citation]. For any gap involving this capability we cite these.
CAP_TO_CITATIONS: dict[str, list[Citation]] = {
    "PHI_DISCLOSURE": [
        Citation("HIPAA-Security", "164.312(a)(1)", "Access Control - Standard", HIPAA_SR),
        Citation("HIPAA-Security", "164.312(e)(1)", "Transmission Security - Standard", HIPAA_SR),
        Citation(
            "HIPAA-Privacy", "164.502(a)", "Uses and Disclosures of PHI - General Rule", HIPAA_PR
        ),
        Citation("HIPAA-Breach", "164.400-414", "Breach Notification Rule", HIPAA_SR),
        Citation(
            "GDPR", "Article 9(1)", "Processing of special categories of personal data", GDPR_A9
        ),
    ],
    "DATA_EXFIL": [
        Citation("HIPAA-Security", "164.312(e)(1)", "Transmission Security", HIPAA_SR),
        Citation(
            "HIPAA-Security", "164.308(a)(1)(ii)(D)", "Information System Activity Review", HIPAA_SR
        ),
    ],
    "READ_FS": [
        Citation("HIPAA-Security", "164.312(a)(2)(iv)", "Encryption and Decryption", HIPAA_SR),
        Citation("HIPAA-Security", "164.310(d)(2)(i)", "Disposal", HIPAA_SR),
    ],
    "READ_MEM": [
        Citation("HIPAA-Security", "164.312(a)(2)(iv)", "Encryption and Decryption", HIPAA_SR),
    ],
    "AUTH_BYPASS": [
        Citation("HIPAA-Security", "164.312(d)", "Person or Entity Authentication", HIPAA_SR),
        Citation("HIPAA-Security", "164.308(a)(5)(ii)(D)", "Password Management", HIPAA_SR),
    ],
    "PRIV_ESC": [
        Citation(
            "HIPAA-Security", "164.308(a)(3)(ii)(B)", "Workforce Clearance Procedure", HIPAA_SR
        ),
        Citation("HIPAA-Security", "164.308(a)(4)", "Information Access Management", HIPAA_SR),
    ],
    "MITM_NET": [
        Citation("HIPAA-Security", "164.312(e)(2)(i)", "Integrity Controls", HIPAA_SR),
        Citation("HIPAA-Security", "164.312(e)(2)(ii)", "Encryption in Transit", HIPAA_SR),
    ],
    "DECRYPT_TLS": [
        Citation("HIPAA-Security", "164.312(e)(2)(ii)", "Encryption in Transit", HIPAA_SR),
    ],
    "INTERNAL_HTTP": [
        Citation("HIPAA-Security", "164.312(c)(1)", "Integrity - Standard", HIPAA_SR),
    ],
    "RCE": [
        Citation(
            "HIPAA-Security", "164.308(a)(5)(ii)(B)", "Protection from Malicious Software", HIPAA_SR
        ),
        Citation("HIPAA-Security", "164.308(a)(1)(ii)(B)", "Risk Management", HIPAA_SR),
    ],
    "LOCAL_CODE": [
        Citation(
            "HIPAA-Security", "164.308(a)(5)(ii)(B)", "Protection from Malicious Software", HIPAA_SR
        ),
        Citation("HIPAA-Security", "164.310(c)", "Workstation Security", HIPAA_SR),
    ],
    "MODEL_ACCESS": [
        Citation("FDA-SaMD", "GMLP Principle 7", "Total Product Lifecycle - monitoring", FDA_GMLP),
    ],
}


# OWASP LLM Top 10 -> Citations.
OWASP_LLM_TO_CITATIONS: dict[str, list[Citation]] = {
    "LLM01:2025": [  # Prompt Injection
        Citation(
            "HIPAA-Privacy",
            "164.502(a)",
            "Use/disclosure - PHI may leak via prompt injection",
            HIPAA_PR,
        ),
        Citation(
            "HIPAA-Security",
            "164.308(a)(1)(ii)(B)",
            "Risk Management for LLM-driven systems",
            HIPAA_SR,
        ),
        Citation(
            "FDA-SaMD",
            "GMLP Principle 5",
            "Cybersecurity considerations integrated into design",
            FDA_GMLP,
        ),
    ],
    "LLM02:2025": [  # Sensitive info disclosure
        Citation("HIPAA-Privacy", "164.502(a)", "Use and Disclosure of PHI", HIPAA_PR),
        Citation(
            "HIPAA-Privacy",
            "164.514(b)",
            "De-identification of PHI for LLM training data",
            HIPAA_PR,
        ),
        Citation("HIPAA-Breach", "164.402", "Definition of Breach", HIPAA_SR),
    ],
    "LLM03:2025": [  # Supply chain
        Citation("HIPAA-Security", "164.308(b)(1)", "Business Associate Agreements", HIPAA_SR),
        Citation(
            "FDA-SaMD",
            "GMLP Principle 1",
            "Multi-disciplinary expertise across product lifecycle",
            FDA_GMLP,
        ),
    ],
    "LLM04:2025": [  # Data poisoning
        Citation(
            "FDA-SaMD",
            "GMLP Principle 3",
            "Clinical study participants representative of population",
            FDA_GMLP,
        ),
        Citation(
            "HIPAA-Security",
            "164.308(a)(1)(ii)(B)",
            "Risk Management - dataset integrity",
            HIPAA_SR,
        ),
    ],
    "LLM05:2025": [  # Improper output handling
        Citation("HIPAA-Security", "164.312(c)(1)", "Integrity Controls", HIPAA_SR),
    ],
    "LLM06:2025": [  # Excessive agency
        Citation("HIPAA-Security", "164.308(a)(4)", "Information Access Management", HIPAA_SR),
        Citation("HIPAA-Privacy", "164.514(d)", "Minimum necessary requirements", HIPAA_PR),
        Citation(
            "FDA-SaMD", "GMLP Principle 6", "Performance focused on the human-AI team", FDA_GMLP
        ),
    ],
    "LLM07:2025": [  # System prompt leakage
        Citation("HIPAA-Privacy", "164.502(a)", "Disclosure", HIPAA_PR),
    ],
    "LLM08:2025": [  # Vector / embedding weaknesses
        Citation(
            "HIPAA-Privacy", "164.514(b)", "De-identification - vector inversion risk", HIPAA_PR
        ),
    ],
    "LLM09:2025": [  # Misinformation / hallucination
        Citation(
            "FDA-SaMD", "GMLP Principle 9", "Users provided clear, essential information", FDA_GMLP
        ),
        Citation(
            "FDA-SaMD", "GMLP Principle 10", "Deployed models monitored for performance", FDA_GMLP
        ),
    ],
    "LLM10:2025": [  # Unbounded consumption
        Citation("HIPAA-Security", "164.308(a)(1)(ii)(B)", "Risk Management - DoS/abuse", HIPAA_SR),
    ],
}


# ---------------------------------------------------------------------------
# Coverage / gap rollups
# ---------------------------------------------------------------------------
def hipaa_coverage() -> dict:
    """Compute regulatory coverage rollup for the UI dashboard."""
    posture = _posture_coverage()
    cap_rows = posture["matrix"]
    out: list[dict] = []
    for r in cap_rows:
        cap = r["capability"]
        cites = [_cite_to_dict(c) for c in CAP_TO_CITATIONS.get(cap, [])]
        if not cites:
            continue
        out.append(
            {
                "capability": cap,
                "coverage_pct": r["coverage_pct"],
                "controls_total": r["controls_total"],
                "citations": cites,
                "missing_classes": r["missing_classes"],
            }
        )

    phi_packages = list_phi_packages_in_graph()
    phi_cves = run_read("""
        MATCH (c:CVE)-[:AFFECTS]->(p:Package:HandlesPHI)
        OPTIONAL MATCH (c)-[:MAPS_TO]->(l:OSILayer)
        RETURN c.id AS id, c.severity AS severity, c.cvss_score AS cvss,
               collect(DISTINCT l.number) AS layers
        ORDER BY coalesce(c.cvss_score,0) DESC LIMIT 50
    """)
    return {
        "phi_package_count": len(phi_packages),
        "phi_packages": phi_packages[:30],
        "phi_cve_count": len(phi_cves),
        "phi_cves": phi_cves,
        "regulatory_capabilities": out,
    }


def hipaa_gaps_for_cve(cve_id: str) -> dict:
    """Wrap posture.gaps_for_cve and add citations for each gap capability."""
    base = _gaps_for_cve(cve_id)
    for g in base.get("gaps", []):
        g["citations"] = [_cite_to_dict(c) for c in CAP_TO_CITATIONS.get(g["capability"], [])]
    return base


def owasp_llm_citations(threat_id: str) -> list[dict]:
    return [_cite_to_dict(c) for c in OWASP_LLM_TO_CITATIONS.get(threat_id, [])]


def _cite_to_dict(c: Citation) -> dict:
    return {"framework": c.framework, "section": c.section, "title": c.title, "url": c.url}
