// =====================================================================
// MODEL GATE EXTENSION  (NikruvX v1.6)
// =====================================================================
// Security regression suite for LLMs. Each evaluation run produces a
// :ModelEval node with a fan-out of :ModelProbeResult nodes (one per
// probe). Regression diff results are stored as :ModelRegression so
// the UI can show deltas over time.
//
// Loaded automatically by engine.graph.apply_schema().
// =====================================================================

CREATE CONSTRAINT model_eval_id IF NOT EXISTS
  FOR (e:ModelEval) REQUIRE e.id IS UNIQUE;

CREATE CONSTRAINT model_probe_result_id IF NOT EXISTS
  FOR (r:ModelProbeResult) REQUIRE r.id IS UNIQUE;

CREATE CONSTRAINT model_regression_id IF NOT EXISTS
  FOR (r:ModelRegression) REQUIRE r.id IS UNIQUE;

CREATE INDEX model_eval_model_id IF NOT EXISTS
  FOR (e:ModelEval) ON (e.model_id);

CREATE INDEX model_eval_ts IF NOT EXISTS
  FOR (e:ModelEval) ON (e.ts);

CREATE INDEX model_probe_category IF NOT EXISTS
  FOR (r:ModelProbeResult) ON (r.category);

CREATE INDEX model_probe_passed IF NOT EXISTS
  FOR (r:ModelProbeResult) ON (r.passed);
