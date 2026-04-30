// =====================================================================
// CYBERSECURITY NEXUS - GRAPH SCHEMA (Neo4j Cypher)
// =====================================================================
// Run this once after Neo4j starts. Creates constraints + indexes.
// =====================================================================

// ----- Uniqueness constraints (also create indexes) -----
CREATE CONSTRAINT cve_id IF NOT EXISTS
  FOR (c:CVE) REQUIRE c.id IS UNIQUE;

CREATE CONSTRAINT cwe_id IF NOT EXISTS
  FOR (c:CWE) REQUIRE c.id IS UNIQUE;

CREATE CONSTRAINT osi_layer IF NOT EXISTS
  FOR (l:OSILayer) REQUIRE l.number IS UNIQUE;

CREATE CONSTRAINT package_purl IF NOT EXISTS
  FOR (p:Package) REQUIRE p.purl IS UNIQUE;

CREATE CONSTRAINT package_version_key IF NOT EXISTS
  FOR (v:PackageVersion) REQUIRE v.key IS UNIQUE;

CREATE CONSTRAINT poc_url IF NOT EXISTS
  FOR (p:PoC) REQUIRE p.url IS UNIQUE;

CREATE CONSTRAINT ai_threat_id IF NOT EXISTS
  FOR (a:AIThreat) REQUIRE a.id IS UNIQUE;

CREATE CONSTRAINT vendor_name IF NOT EXISTS
  FOR (v:Vendor) REQUIRE v.name IS UNIQUE;

CREATE CONSTRAINT product_key IF NOT EXISTS
  FOR (p:Product) REQUIRE p.key IS UNIQUE;

// ----- Helpful secondary indexes -----
CREATE INDEX cve_severity IF NOT EXISTS FOR (c:CVE) ON (c.severity);
CREATE INDEX cve_cvss IF NOT EXISTS FOR (c:CVE) ON (c.cvss_score);
CREATE INDEX cve_published IF NOT EXISTS FOR (c:CVE) ON (c.published);
CREATE INDEX package_eco IF NOT EXISTS FOR (p:Package) ON (p.ecosystem);
CREATE INDEX package_name IF NOT EXISTS FOR (p:Package) ON (p.name);
CREATE INDEX cwe_name IF NOT EXISTS FOR (c:CWE) ON (c.name);

// ----- Full-text indexes for the universal search bar -----
CREATE FULLTEXT INDEX cve_search IF NOT EXISTS
  FOR (c:CVE) ON EACH [c.id, c.description];

CREATE FULLTEXT INDEX cwe_search IF NOT EXISTS
  FOR (c:CWE) ON EACH [c.id, c.name, c.description];

CREATE FULLTEXT INDEX package_search IF NOT EXISTS
  FOR (p:Package) ON EACH [p.name, p.purl];

CREATE FULLTEXT INDEX ai_threat_search IF NOT EXISTS
  FOR (a:AIThreat) ON EACH [a.id, a.name, a.description];

// ----- Seed the 7 OSI layers (idempotent) -----
MERGE (l1:OSILayer {number: 1}) SET l1.name = "Physical",     l1.description = "Cables, signaling, hardware, RF, power-side channels";
MERGE (l2:OSILayer {number: 2}) SET l2.name = "Data Link",    l2.description = "MAC, ARP, VLAN, switches, 802.1x, Wi-Fi link layer";
MERGE (l3:OSILayer {number: 3}) SET l3.name = "Network",      l3.description = "IP, ICMP, routing, firewalls, NAT, IPsec";
MERGE (l4:OSILayer {number: 4}) SET l4.name = "Transport",    l4.description = "TCP/UDP, port-based attacks, segment integrity";
MERGE (l5:OSILayer {number: 5}) SET l5.name = "Session",      l5.description = "Auth/session mgmt, RPC, NetBIOS, session hijack";
MERGE (l6:OSILayer {number: 6}) SET l6.name = "Presentation", l6.description = "Encoding, TLS, serialization, encryption flaws, prompt formatting (LLM)";
MERGE (l7:OSILayer {number: 7}) SET l7.name = "Application",  l7.description = "App logic, web, API, AI/ML, business-logic flaws";

// =====================================================================
// POSTURE / POLICY EXTENSION
// =====================================================================
// Adds Policy and Control nodes so uploaded cloud / endpoint / WAF /
// firewall policies can be validated against CVE attack chains.
// =====================================================================
CREATE CONSTRAINT policy_id IF NOT EXISTS
  FOR (p:Policy) REQUIRE p.id IS UNIQUE;
CREATE CONSTRAINT control_id IF NOT EXISTS
  FOR (c:Control) REQUIRE c.id IS UNIQUE;

CREATE INDEX policy_source IF NOT EXISTS FOR (p:Policy) ON (p.source);
CREATE INDEX policy_type IF NOT EXISTS FOR (p:Policy) ON (p.type);
CREATE INDEX control_layer IF NOT EXISTS FOR (c:Control) ON (c.layer);
CREATE INDEX control_action IF NOT EXISTS FOR (c:Control) ON (c.action);

CREATE FULLTEXT INDEX policy_search IF NOT EXISTS
  FOR (p:Policy) ON EACH [p.id, p.name, p.source];
CREATE FULLTEXT INDEX control_search IF NOT EXISTS
  FOR (c:Control) ON EACH [c.id, c.title, c.action];

// ----- Schema documentation (as a single info node) -----
MERGE (i:_NexusInfo {key: "schema"})
SET i.version  = "1.1.0",
    i.created  = datetime(),
    i.nodes    = ["CVE","CWE","OSILayer","Package","PackageVersion","PoC","AIThreat","Vendor","Product","Policy","Control"],
    i.relations= ["CLASSIFIED_AS","MAPS_TO","AFFECTS","VERSION_OF","HAS_POC","CHILD_OF","RELATED_TO","AFFECTS_PRODUCT","MADE_BY","CONTAINS","MITIGATES","APPLIES_AT","GOVERNS"];
