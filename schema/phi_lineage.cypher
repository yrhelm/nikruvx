// =====================================================================
// PHI LINEAGE EXTENSION (NikruvX v1.4)
// =====================================================================
// Tracks PHI flow across the AI stack: source -> prompt -> model ->
// vendor -> region -> sink, with BAA coverage and evidence-grade edges.
//
// Loaded automatically by engine.graph.apply_schema(); all *.cypher
// files in this directory are applied in alphabetical order so this
// runs after graph_schema.cypher.
//
// Raw PHI text is NEVER persisted. Only counts per identifier_type.
// =====================================================================

// ----- Lineage nodes -----
CREATE CONSTRAINT phi_source_id IF NOT EXISTS
  FOR (s:PHISource) REQUIRE s.id IS UNIQUE;

CREATE CONSTRAINT phi_element_id IF NOT EXISTS
  FOR (e:PHIElement) REQUIRE e.id IS UNIQUE;

CREATE CONSTRAINT subject_pseudo IF NOT EXISTS
  FOR (s:Subject) REQUIRE s.pseudo_id IS UNIQUE;

CREATE CONSTRAINT actor_id IF NOT EXISTS
  FOR (a:Actor) REQUIRE a.id IS UNIQUE;

CREATE CONSTRAINT lineage_session_id IF NOT EXISTS
  FOR (s:LineageSession) REQUIRE s.id IS UNIQUE;

CREATE CONSTRAINT prompt_id IF NOT EXISTS
  FOR (p:Prompt) REQUIRE p.id IS UNIQUE;

CREATE CONSTRAINT response_id IF NOT EXISTS
  FOR (r:Response) REQUIRE r.id IS UNIQUE;

CREATE CONSTRAINT ai_model_id IF NOT EXISTS
  FOR (m:AIModel) REQUIRE m.id IS UNIQUE;

CREATE CONSTRAINT ai_vendor_id IF NOT EXISTS
  FOR (v:AIVendor) REQUIRE v.id IS UNIQUE;

CREATE CONSTRAINT region_code IF NOT EXISTS
  FOR (r:Region) REQUIRE r.code IS UNIQUE;

CREATE CONSTRAINT sink_id IF NOT EXISTS
  FOR (s:Sink) REQUIRE s.id IS UNIQUE;

CREATE CONSTRAINT retention_id IF NOT EXISTS
  FOR (r:RetentionPolicy) REQUIRE r.id IS UNIQUE;

CREATE CONSTRAINT baa_id IF NOT EXISTS
  FOR (b:BAA) REQUIRE b.id IS UNIQUE;

CREATE CONSTRAINT baa_term_id IF NOT EXISTS
  FOR (t:BAATerm) REQUIRE t.id IS UNIQUE;

CREATE CONSTRAINT evidence_id IF NOT EXISTS
  FOR (e:Evidence) REQUIRE e.id IS UNIQUE;

// ----- Secondary indexes for hot queries -----
CREATE INDEX prompt_ts IF NOT EXISTS FOR (p:Prompt) ON (p.ts);
CREATE INDEX response_ts IF NOT EXISTS FOR (r:Response) ON (r.ts);
CREATE INDEX phi_element_type IF NOT EXISTS FOR (e:PHIElement) ON (e.identifier_type);
CREATE INDEX sink_kind IF NOT EXISTS FOR (s:Sink) ON (s.kind);
CREATE INDEX evidence_kind IF NOT EXISTS FOR (e:Evidence) ON (e.kind);
CREATE INDEX baa_expires IF NOT EXISTS FOR (b:BAA) ON (b.expires);
CREATE INDEX ai_vendor_name IF NOT EXISTS FOR (v:AIVendor) ON (v.name);
CREATE INDEX ai_model_name IF NOT EXISTS FOR (m:AIModel) ON (m.name);
