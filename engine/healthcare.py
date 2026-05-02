"""
Healthcare package signatures + PHI tagging
============================================
Curated list of libraries that handle PHI (Protected Health Information) or
clinical data formats (HL7v2, FHIR, DICOM, NCPDP, X12, ICD/SNOMED/RxNorm,
biosignals, EHR integrations). Any Package node matching one of these gets
the auxiliary `:HandlesPHI` label so the chain generator and the HIPAA
compliance lens can reason about PHI exposure.

Curation criteria: package is *purposed* for handling PHI/clinical data, not
generic JSON/XML libs. We're conservative on purpose to keep false positives
down.
"""

from __future__ import annotations

from rich.console import Console

from .graph import run_read, session

console = Console()

# (ecosystem, package name pattern). Exact name match by default; "*" suffix
# means startswith.
PHI_PACKAGES: list[tuple[str, str, str]] = [
    # ----- HL7v2 / HL7 messaging -----
    ("PyPI", "hl7", "HL7v2 parser"),
    ("PyPI", "hl7apy", "HL7v2 toolkit"),
    ("npm", "hl7-standard", "HL7v2 parser"),
    ("npm", "node-hl7-client", "HL7 MLLP client"),
    ("npm", "simple-hl7", "HL7v2 messages"),
    ("Maven", "ca.uhn.hapi:hapi-base", "HAPI HL7 base"),
    ("Maven", "ca.uhn.hapi:hapi-structures-v25", "HAPI HL7 v2.5"),
    ("Maven", "ca.uhn.hapi:hapi-structures-v251", "HAPI HL7 v2.5.1"),
    # ----- FHIR -----
    ("PyPI", "fhir.resources", "FHIR resources"),
    ("PyPI", "fhirclient", "FHIR client"),
    ("PyPI", "fhirpy", "FHIR client async"),
    ("npm", "fhir", "FHIR parser"),
    ("npm", "fhir-kit-client", "FHIR REST client"),
    ("npm", "@types/fhir", "FHIR TypeScript defs"),
    ("Maven", "ca.uhn.hapi.fhir:hapi-fhir-base", "HAPI FHIR base"),
    ("Maven", "ca.uhn.hapi.fhir:hapi-fhir-structures-r4", "HAPI FHIR R4"),
    ("Maven", "ca.uhn.hapi.fhir:hapi-fhir-server", "HAPI FHIR server"),
    ("Go", "github.com/google/fhir", "Google FHIR Go"),
    # ----- DICOM (medical imaging) -----
    ("PyPI", "pydicom", "DICOM parser"),
    ("PyPI", "dicomweb-client", "DICOMweb client"),
    ("PyPI", "deid", "DICOM de-identification"),
    ("PyPI", "highdicom", "DICOM SR/segmentations"),
    ("npm", "dicom-parser", "DICOM parser"),
    ("npm", "dcmjs", "DICOM JS"),
    # ----- NCPDP / pharmacy -----
    ("PyPI", "ncpdp", "NCPDP D.0"),
    ("Maven", "com.cerner:ccl", "Cerner CCL"),
    # ----- X12 (claims / 270/271/837) -----
    ("PyPI", "pyx12", "X12 EDI parser"),
    ("npm", "edi-x12", "X12 parser"),
    # ----- ICD / SNOMED / RxNorm / LOINC -----
    ("PyPI", "icd10-cm", "ICD-10-CM lookup"),
    ("PyPI", "snomed-graph", "SNOMED CT graph"),
    ("PyPI", "loinc-tool", "LOINC tool"),
    ("PyPI", "rxnorm-py", "RxNorm wrapper"),
    # ----- Clinical NLP -----
    ("PyPI", "medspacy", "Clinical NLP spaCy"),
    ("PyPI", "cnlp_transformers", "Clinical NLP transformers"),
    ("PyPI", "scispacy", "Clinical/scientific spaCy"),
    ("PyPI", "negex", "Clinical negation detection"),
    # ----- EHR / vendor SDKs -----
    ("PyPI", "epicchart-client", "Epic EHR client"),
    ("npm", "@cerner/smart-on-fhir", "Cerner SMART-on-FHIR"),
    ("npm", "fhirclient", "SMART-on-FHIR JS"),
    ("PyPI", "smart-on-fhir", "SMART-on-FHIR Python"),
    # ----- Biosignals / wearables / IoMT -----
    ("PyPI", "wfdb", "WFDB ECG/PPG signal toolkit"),
    ("PyPI", "mne", "MEG/EEG analysis"),
    ("PyPI", "biopython", "BioPython - genomics + clinical"),
    ("PyPI", "antropy", "EEG entropy analysis"),
    # ----- Healthcare AI / clinical LLM SDKs -----
    ("PyPI", "clinical-trials-gov-sdk", "ClinicalTrials.gov"),
    ("PyPI", "rad-fact", "Radiology factuality eval"),
    ("PyPI", "med-mcp", "Medical MCP servers"),
    # ----- Patient ID / consent / audit -----
    ("PyPI", "fhir-consent", "FHIR Consent helpers"),
    ("PyPI", "audit-log", "audit log helpers (clinical)"),
    # ----- HL7v3 / CDA -----
    ("PyPI", "cda", "HL7 CDA"),
]


def _create_package_nodes() -> int:
    """Make sure every healthcare package exists as a Package node, even if
    OSV.dev had nothing to say about it. This is what guarantees the user
    sees something after clicking 'Tag PHI packages'."""
    items = [{"eco": e, "name": n, "purl": f"pkg:{e.lower()}/{n}"} for e, n, _ in PHI_PACKAGES]
    cypher = """
    UNWIND $items AS item
        MERGE (p:Package {purl: item.purl})
        SET p.ecosystem = item.eco, p.name = item.name
        RETURN count(p) AS n
    """
    with session() as s:
        res = list(s.run(cypher, items=items))
    return res[0]["n"] if res else 0


def tag_phi_packages() -> int:
    """Apply the :HandlesPHI label to every healthcare-package node in graph.
    Idempotent. Does NOT ingest OSV - call seed_phi_packages() for that."""
    _create_package_nodes()  # make sure they exist
    purls = [f"pkg:{e.lower()}/{n}" for e, n, _ in PHI_PACKAGES]
    cypher = """
    UNWIND $purls AS purl
    MATCH (p:Package {purl: purl})
    SET p:HandlesPHI
    RETURN count(p) AS n
    """
    with session() as s:
        res = list(s.run(cypher, purls=purls))
    n = res[0]["n"] if res else 0
    console.print(f"[green]Tagged {n} package(s) with :HandlesPHI")
    return n


def seed_phi_packages(via_osv: bool = True, limit: int | None = None) -> dict:
    """Bring every healthcare package into the graph, then tag them.

    Args:
      via_osv: if True (default), call OSV.dev for each package so any
               associated CVEs are pulled in too. Slower (~1-2 min for 50
               packages, mostly because of OSV's per-call latency) but
               produces a much richer HIPAA dashboard.
               if False, just create the Package nodes - instant but no CVEs.
      limit:   cap on how many packages to ingest (useful for testing).

    Returns:
      {"created_packages": N, "tagged": M, "via_osv": bool, "errors": [...]}
    """
    pkgs = PHI_PACKAGES[:limit] if limit else PHI_PACKAGES
    errors: list[str] = []

    if via_osv:
        try:
            from ingest.osv import ingest_package as _osv_pkg
        except Exception as e:
            errors.append(f"OSV ingester not importable: {e}")
            via_osv = False

    if via_osv:
        for eco, name, _desc in pkgs:
            try:
                _osv_pkg(eco, name)
            except Exception as e:
                errors.append(f"{eco}:{name} -> {e}")

    # Always create Package nodes so the tag has something to match.
    created = _create_package_nodes()
    tagged = tag_phi_packages()
    return {
        "created_packages": created,
        "tagged": tagged,
        "via_osv": via_osv,
        "errors": errors[:10],
    }


def list_phi_packages_in_graph() -> list[dict]:
    return run_read("""
        MATCH (p:Package:HandlesPHI)
        OPTIONAL MATCH (c:CVE)-[:AFFECTS]->(p)
        RETURN p.purl AS purl, p.ecosystem AS ecosystem, p.name AS name,
               count(c) AS cve_count
        ORDER BY cve_count DESC, p.name
    """)


def is_phi_package(purl: str) -> bool:
    """Quick check used by the chain generator to convert DATA_EXFIL -> PHI_DISCLOSURE."""
    rows = run_read("MATCH (p:Package {purl: $purl}) RETURN p:HandlesPHI AS phi", purl=purl)
    return bool(rows and rows[0].get("phi"))


def cve_handles_phi(cve_id: str) -> bool:
    rows = run_read(
        """
        MATCH (c:CVE {id: $id})-[:AFFECTS]->(p:Package)
        WHERE p:HandlesPHI
        RETURN count(p) AS n
    """,
        id=cve_id.upper(),
    )
    return bool(rows and rows[0]["n"] > 0)


if __name__ == "__main__":
    n = tag_phi_packages()
    print(f"Tagged {n} packages")
    for p in list_phi_packages_in_graph()[:20]:
        print(f"  {p['ecosystem']:10s} {p['name']:40s} {p['cve_count']} CVE(s)")
