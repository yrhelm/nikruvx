// =====================================================================
// MCP GATE EXTENSION  (NikruvX v1.5)
// =====================================================================
// Pre-deployment review for MCP servers / AI agents. Each review
// produces an :McpApproval node with a verdict and a fan-out of
// :McpFinding nodes (one per issue surfaced by the review pipeline).
//
// Loaded automatically by engine.graph.apply_schema().
// =====================================================================

CREATE CONSTRAINT mcp_approval_id IF NOT EXISTS
  FOR (a:McpApproval) REQUIRE a.id IS UNIQUE;

CREATE CONSTRAINT mcp_finding_id IF NOT EXISTS
  FOR (f:McpFinding) REQUIRE f.id IS UNIQUE;

CREATE INDEX mcp_approval_status IF NOT EXISTS
  FOR (a:McpApproval) ON (a.status);

CREATE INDEX mcp_approval_target IF NOT EXISTS
  FOR (a:McpApproval) ON (a.target_name);

CREATE INDEX mcp_finding_severity IF NOT EXISTS
  FOR (f:McpFinding) ON (f.severity);

CREATE INDEX mcp_finding_check IF NOT EXISTS
  FOR (f:McpFinding) ON (f.check_id);
