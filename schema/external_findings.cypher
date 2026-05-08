// =====================================================================
// EXTERNAL FINDINGS  (NikruvX v1.9)
// =====================================================================
// Vulnerability findings imported from external scanners (Wiz, Snyk,
// Tenable, Qualys, etc.) re-prioritized against the user's actual
// environment using NikruvX's TTP coverage, asset inventory, KEV
// telemetry, PoC availability, and forecast catalog.
//
// One :ExternalFinding per uploaded row; bridges to existing :CVE,
// :Application, :Package nodes for environmental context.
// =====================================================================

CREATE CONSTRAINT external_finding_id IF NOT EXISTS
  FOR (f:ExternalFinding) REQUIRE f.id IS UNIQUE;

CREATE CONSTRAINT finding_batch_id IF NOT EXISTS
  FOR (b:FindingBatch) REQUIRE b.id IS UNIQUE;

CREATE INDEX external_finding_source IF NOT EXISTS
  FOR (f:ExternalFinding) ON (f.source);

CREATE INDEX external_finding_priority_band IF NOT EXISTS
  FOR (f:ExternalFinding) ON (f.priority_band);

CREATE INDEX external_finding_cve IF NOT EXISTS
  FOR (f:ExternalFinding) ON (f.cve_id);

CREATE INDEX external_finding_score IF NOT EXISTS
  FOR (f:ExternalFinding) ON (f.nikruvx_score);

CREATE INDEX external_finding_uploaded IF NOT EXISTS
  FOR (f:ExternalFinding) ON (f.uploaded_at);
