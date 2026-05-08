// =====================================================================
// PETRI MULTI-TURN AUDITS  (NikruvX v1.8)
// =====================================================================
// Multi-turn auditor-vs-target alignment audits, integrating the
// Meridian Labs / Anthropic Petri framework.
//
// Each PetriAudit is one execution of (auditor, target, scenario).
// PetriTurn nodes form an ordered conversation transcript.
// =====================================================================

CREATE CONSTRAINT petri_audit_id IF NOT EXISTS
  FOR (a:PetriAudit) REQUIRE a.id IS UNIQUE;

CREATE CONSTRAINT petri_turn_id IF NOT EXISTS
  FOR (t:PetriTurn) REQUIRE t.id IS UNIQUE;

CREATE CONSTRAINT petri_scenario_id IF NOT EXISTS
  FOR (s:PetriScenario) REQUIRE s.id IS UNIQUE;

CREATE INDEX petri_audit_target IF NOT EXISTS
  FOR (a:PetriAudit) ON (a.target_spec);

CREATE INDEX petri_audit_scenario IF NOT EXISTS
  FOR (a:PetriAudit) ON (a.scenario_id);

CREATE INDEX petri_audit_passed IF NOT EXISTS
  FOR (a:PetriAudit) ON (a.passed);

CREATE INDEX petri_audit_ts IF NOT EXISTS
  FOR (a:PetriAudit) ON (a.ts);

CREATE INDEX petri_scenario_category IF NOT EXISTS
  FOR (s:PetriScenario) ON (s.category);
