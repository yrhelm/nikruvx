// =====================================================================
// ZERO-DAY DEFENSE EXTENSION  (NikruvX v1.6)
// =====================================================================
// TTP-based defense layer that complements the CVE-based spine.
//
// Even before a CVE is assigned, a behavior maps to an ATT&CK technique
// which maps to an OSI layer which maps to D3FEND defensive controls.
// That gives security teams a way to answer "what zero-days would land
// on my stack?" without waiting for the patch cycle.
//
// Loaded automatically by engine.graph.apply_schema().
// =====================================================================

CREATE CONSTRAINT attack_technique_id IF NOT EXISTS
  FOR (t:AttackTechnique) REQUIRE t.id IS UNIQUE;

CREATE CONSTRAINT defense_technique_id IF NOT EXISTS
  FOR (d:DefenseTechnique) REQUIRE d.id IS UNIQUE;

CREATE CONSTRAINT zero_day_pattern_id IF NOT EXISTS
  FOR (z:ZeroDayPattern) REQUIRE z.id IS UNIQUE;

CREATE CONSTRAINT behavioral_indicator_id IF NOT EXISTS
  FOR (b:BehavioralIndicator) REQUIRE b.id IS UNIQUE;

// ----- Secondary indexes -----
CREATE INDEX attack_technique_tactic IF NOT EXISTS
  FOR (t:AttackTechnique) ON (t.tactic);

CREATE INDEX attack_technique_layer IF NOT EXISTS
  FOR (t:AttackTechnique) ON (t.layer);

CREATE INDEX zero_day_severity IF NOT EXISTS
  FOR (z:ZeroDayPattern) ON (z.severity);

CREATE INDEX zero_day_ai_discovered IF NOT EXISTS
  FOR (z:ZeroDayPattern) ON (z.ai_discovered);

CREATE INDEX zero_day_ai_anticipated IF NOT EXISTS
  FOR (z:ZeroDayPattern) ON (z.ai_anticipated);

CREATE INDEX zero_day_predicted IF NOT EXISTS
  FOR (z:ZeroDayPattern) ON (z.predicted);

CREATE INDEX zero_day_mitigation_window IF NOT EXISTS
  FOR (z:ZeroDayPattern) ON (z.mitigation_window);

CREATE INDEX zero_day_layer IF NOT EXISTS
  FOR (z:ZeroDayPattern) ON (z.layer);

CREATE INDEX defense_tactic IF NOT EXISTS
  FOR (d:DefenseTechnique) ON (d.tactic);

// ----- Full-text indexes for search -----
CREATE FULLTEXT INDEX attack_technique_search IF NOT EXISTS
  FOR (t:AttackTechnique) ON EACH [t.id, t.name, t.description];

CREATE FULLTEXT INDEX zero_day_pattern_search IF NOT EXISTS
  FOR (z:ZeroDayPattern) ON EACH [z.id, z.name, z.description];
