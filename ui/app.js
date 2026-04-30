/* ============================================================
   Cybersecurity Nexus - frontend logic
   ============================================================ */
const API = "/api";
const $ = (sel) => document.querySelector(sel);

const LAYER_NAMES = {
  1: "Physical", 2: "Data Link", 3: "Network", 4: "Transport",
  5: "Session", 6: "Presentation", 7: "Application",
};

let cy = null;
let _lastGraphCve = null;
let _graphResizeTimer = null;

window.addEventListener("DOMContentLoaded", async () => {
  await loadStats();
  await loadAIThreats();
  $("#searchBtn").addEventListener("click", doSearch);
  $("#q").addEventListener("keydown", (e) => { if (e.key === "Enter") doSearch(); });
  initGraph();
  initModes();
  pingHealth();
});

/* ---------- mode switching ---------- */
function initModes() {
  document.querySelectorAll(".mode-btn").forEach(btn => {
    btn.addEventListener("click", () => switchMode(btn.dataset.mode));
  });
  // SBOM
  initSbom();
  $("#rtBtn").addEventListener("click", runRedTeam);
  $("#kevRefresh").addEventListener("click", refreshKev);
}
function switchMode(mode) {
  document.querySelectorAll(".mode-btn").forEach(b => b.classList.toggle("active", b.dataset.mode === mode));
  ["sbomMode","redteamMode","kevMode","postureMode","hipaaMode","clinicalMode"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.hidden = id !== `${mode}Mode`;
  });
  if (mode === "kev")      refreshKev();
  if (mode === "posture")  initPosture();
  if (mode === "hipaa")    initHipaa();
  if (mode === "clinical") initClinical();
}

/* ---------- bootstrap ---------- */
async function pingHealth() {
  try {
    const r = await fetch(`${API}/health`).then(r => r.json());
    $("#health").textContent = `neo4j: ${r.neo4j}`;
  } catch { $("#health").textContent = "neo4j: offline"; }
}

async function loadStats() {
  try {
    const s = await fetch(`${API}/stats`).then(r => r.json());
    $("#cveCount").textContent = s.counts.cves;
    $("#cweCount").textContent = s.counts.cwes;
    $("#pkgCount").textContent = s.counts.packages;
    $("#pocCount").textContent = s.counts.pocs;
    $("#aiCount").textContent = s.counts.ai_threats;
    const tower = $("#osiTower");
    tower.innerHTML = "";
    s.layers.slice().reverse().forEach(l => {
      const li = document.createElement("li");
      li.dataset.layer = l.layer;
      li.innerHTML = `<span class="num">L${l.layer}</span><span class="name">${l.name}</span><span class="count">${l.cves}</span>`;
      li.onclick = () => loadOSI(l.layer);
      tower.appendChild(li);
    });
  } catch (e) { console.error(e); }
}

async function loadAIThreats() {
  try {
    const list = await fetch(`${API}/ai-vulns`).then(r => r.json());
    const ul = $("#aiList");
    ul.innerHTML = "";
    if (!list.length) {
      ul.innerHTML = `<li class="muted">No AI threats loaded yet — run <code>python -m ingest.ai_threats</code></li>`;
      return;
    }
    list.forEach(t => {
      const li = document.createElement("li");
      li.className = "ai-link";
      li.tabIndex = 0;
      li.dataset.threatId = t.threat.id;
      li.innerHTML = `<span class="badge">${t.threat.framework}</span><a href="#" class="ai-anchor">${t.threat.id} — ${t.threat.name}</a>`;
      const open = (e) => {
        if (e) { e.preventDefault(); e.stopPropagation(); }
        // If a mode overlay is on, switch back to Explore so the detail is visible.
        const exploreBtn = document.querySelector('.mode-btn[data-mode="explore"]');
        if (exploreBtn && !exploreBtn.classList.contains("active")) exploreBtn.click();
        loadAIThreat(t.threat.id);
      };
      li.addEventListener("click", open);
      li.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") open(e); });
      ul.appendChild(li);
    });
  } catch (e) {
    console.error("loadAIThreats failed:", e);
    $("#aiList").innerHTML = `<li class="muted">Failed to load AI threats: ${e.message}</li>`;
  }
}

/* ---------- search ---------- */
async function doSearch() {
  const q = $("#q").value.trim();
  if (!q) return;
  // If it looks like an exact CVE/CWE id, jump straight in.
  if (/^CVE-\d{4}-\d+$/i.test(q)) return loadCVE(q.toUpperCase());
  if (/^CWE-\d+$/i.test(q))      return loadCWE(q.toUpperCase());
  const r = await fetch(`${API}/search?q=${encodeURIComponent(q)}`).then(r => r.json());
  renderResults(r);
}

function renderResults(r) {
  const div = $("#results");
  div.innerHTML = "";
  const groups = [
    ["CVEs", r.cves, x => `<div class="row" onclick="loadCVE('${x.id}')"><b>${x.id}</b> · ${x.severity || "?"} · CVSS ${x.cvss ?? "?"}<br><span class="muted">${(x.description||"").slice(0,140)}…</span></div>`],
    ["CWEs", r.cwes, x => `<div class="row" onclick="loadCWE('${x.id}')"><b>${x.id}</b> — ${x.name}</div>`],
    ["Packages", r.packages, x => `<div class="row" onclick="loadPackage('${x.ecosystem}','${x.name}')"><b>${x.name}</b> <span class="muted">${x.ecosystem}</span></div>`],
    ["AI Threats", r.ai_threats, x => `<div class="row" onclick="loadAIThreat('${x.id}')"><b>${x.id}</b> — ${x.name} <span class="muted">${x.framework}</span></div>`],
  ];
  let any = false;
  groups.forEach(([title, items, render]) => {
    if (!items?.length) return;
    any = true;
    div.insertAdjacentHTML("beforeend", `<div class="group-title">${title} (${items.length})</div>`);
    items.forEach(x => div.insertAdjacentHTML("beforeend", render(x)));
  });
  if (!any) div.innerHTML = `<div class="muted">No results.</div>`;
}

/* ---------- CVE detail ---------- */
async function loadCVE(id) {
  const d = await fetch(`${API}/cve/${id}`).then(r => r.ok ? r.json() : Promise.reject(r.status));
  const c = d.cve;
  const cwes = d.cwes.map(w => `<span class="chip" onclick="loadCWE('${w.id}')">${w.id}${w.name ? ' — '+w.name : ''}</span>`).join("");
  const layers = d.layers.map(l => `<span class="chip layer" onclick="loadOSI(${l.number})">L${l.number} ${l.name}</span>`).join("");
  const pkgs = d.packages.map(p => `
      <div class="pkg-row">
        <span class="eco">${p.ecosystem}</span>
        <span><a href="#" onclick="loadPackage('${p.ecosystem}','${p.name}');return false;">${p.name}</a>
        ${p.affected?.length ? `<span class="muted"> · affected: ${p.affected.join(', ')}</span>` : ''}
        ${p.fixed?.length ? `<span class="muted"> · fixed: ${p.fixed.join(', ')}</span>` : ''}
        </span>
      </div>`).join("") || `<span class="muted">No package mappings yet — run the OSV/GHSA ingester.</span>`;
  const pocs = d.pocs.length ? d.pocs.map(p => `
      <div class="poc-block">
        <a href="${p.url}" target="_blank">${p.url}</a> <span class="muted">[${p.source}${p.language?'/'+p.language:''}]</span>
        ${p.snippet ? `<pre>${escapeHtml(p.snippet)}</pre>` : ''}
      </div>`).join("") : `<span class="muted">No public PoC found yet — run <code>python -m ingest.poc ${c.id}</code>.</span>`;
  const ai = d.ai_threats.length ? d.ai_threats.map(a => `<span class="chip" onclick="loadAIThreat('${a.id}')">${a.framework}: ${a.id} — ${a.name}</span>`).join("") : "";

  const r = d.risk;
  const reasons = (r.explanation || []).map(e => `· ${e}`).join("<br>");
  const html = `
    <div class="cve-card">
      <h2>${c.id}</h2>
      <span class="severity-pill ${c.severity}">${c.severity || 'UNKNOWN'}</span>
      ${c.cvss_score ? `<span class="muted"> · CVSS ${c.cvss_score}</span>` : ''}
      ${c.published ? `<span class="muted"> · published ${c.published.slice(0,10)}</span>` : ''}
      <div class="desc">${escapeHtml(c.description || '')}</div>

      <div class="section-h">OSI Layers</div><div class="chips">${layers || '<span class="muted">—</span>'}</div>
      <div class="section-h">CWEs</div><div class="chips">${cwes || '<span class="muted">—</span>'}</div>
      ${ai ? `<div class="section-h">Linked AI Threats</div><div class="chips">${ai}</div>` : ''}

      <div class="risk-card">
        <div><span class="risk-score">${r.score}</span><span class="muted"> / 100</span></div>
        <div class="risk-band">NEXUS RISK · ${r.band}</div>
        <div class="components">
          <div>CVSS <b>${r.components.cvss}</b></div>
          <div>CWE sev <b>${r.components.cwe_severity}</b></div>
          <div>OSI breadth <b>${r.components.osi_breadth}</b></div>
          <div>PoC factor <b>${r.components.poc_factor}</b></div>
          <div>Blast radius <b>${r.components.blast_radius}</b></div>
          <div>Age factor <b>${r.components.age_factor}</b></div>
        </div>
        <div class="reasons">${reasons}</div>
      </div>

      <div class="section-h">Affected Packages (${d.packages.length})</div>${pkgs}
      <div class="section-h">Public PoCs (${d.pocs.length})</div>${pocs}

      ${(c.references && c.references.length) ? `<div class="section-h">References</div><div class="chips">${c.references.slice(0,8).map(u=>`<a class="chip" href="${u}" target="_blank">${new URL(u).hostname}</a>`).join('')}</div>` : ''}

      <div class="action-bar">
        <button onclick="loadStory('${c.id}')">📖 LLM Story</button>
        <button onclick="loadChain('${c.id}')">⚡ Attack Chain</button>
        <button onclick="loadTwins('${c.id}')">🧬 Patch Twins</button>
        <button onclick="loadDefense('${c.id}')">🛡 Defense Recipes</button>
        <button onclick="loadSimilar('${c.id}')">🔍 Similar (DNA)</button>
      </div>
      <div id="extra"></div>
    </div>`;
  $("#detail").innerHTML = html;
  drawGraph(c.id);
}

/* ---------- LLM story ---------- */
async function loadStory(cve) {
  const ex = $("#extra");
  ex.innerHTML = `<div class="section-h">LLM Threat Story</div><div class="story-block" id="storyBox">Generating (local Ollama)…</div>`;
  const box = $("#storyBox");
  box.textContent = "";
  try {
    const resp = await fetch(`/api/story/stream/${cve}`);
    if (!resp.body) {
      const j = await fetch(`/api/story/${cve}`).then(r => r.json());
      box.textContent = j.narrative || `(no output)`;
      return;
    }
    const reader = resp.body.getReader();
    const dec = new TextDecoder();
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      box.textContent += dec.decode(value, { stream: true });
    }
  } catch (e) {
    box.textContent = `Local LLM unreachable. Install Ollama (https://ollama.com/download) and run:\n  ollama pull llama3.1:8b\n\nThe rest of Cyber Nexus works without it.`;
  }
}

/* ---------- Attack chain ---------- */
async function loadChain(cve) {
  const ex = $("#extra");
  ex.innerHTML = `<div class="section-h">Cross-Layer Attack Chains</div><div id="chainBox" class="muted">Building chains…</div>`;
  try {
    const r = await fetch(`/api/attack-chain/${cve}`).then(r => r.ok ? r.json() : Promise.reject(r.status));
    const html = (r.chains || []).map((c,i) => `
      <div class="chain-card">
        <div><b>Chain #${i+1}</b> — score <span class="twin-score">${c.score}</span> · layers ${c.layers_traversed.join(', ')} · depth ${c.length}</div>
        ${c.steps.map(s => `
          <div class="step">
            <span class="arrow">${s.layer_from ? `L${s.layer_from}→L${s.layer_to}` : `L${s.layer_to}`}</span>
            <a href="#" onclick="loadCVE('${s.cve}');return false;">${s.cve}</a>
            <span class="muted"> · ${s.severity || '?'} · risk ${s.risk}</span><br>
            <span class="muted">${s.transition || ''}</span>
          </div>`).join("")}
      </div>`).join("") || `<div class="muted">No chains derivable from this seed (likely needs more graph context — re-run OSV/GHSA ingest).</div>`;
    $("#chainBox").outerHTML = html;
  } catch (e) {
    $("#chainBox").innerHTML = `<div class="muted">No chains found.</div>`;
  }
}

/* ---------- Patch twins ---------- */
async function loadTwins(cve) {
  const ex = $("#extra");
  ex.innerHTML = `<div class="section-h">Patch Twins (sibling CVEs likely sharing root cause)</div><div id="twinsBox" class="muted">Searching…</div>`;
  const r = await fetch(`/api/patch-twins/${cve}`).then(r => r.json());
  const tw = r.twins || [];
  if (!tw.length) {
    $("#twinsBox").innerHTML = `<div class="muted">No twins above similarity threshold. Run <code>python -m engine.dna embed</code> to enable semantic matching.</div>`;
    return;
  }
  const rows = tw.map(t => `
    <div class="twin-row" onclick="loadCVE('${t.id}')">
      <span><b>${t.id}</b></span>
      <span>${t.severity || '?'}</span>
      <span class="twin-score">${t.twin_score}</span>
      <span class="muted">${(t.description || '').slice(0,160)}…</span>
    </div>`).join("");
  $("#twinsBox").outerHTML = rows;
}

/* ---------- Defense recipes ---------- */
async function loadDefense(cve) {
  const ex = $("#extra");
  ex.innerHTML = `<div class="section-h">Defense Recipes per OSI Layer</div><div id="defBox" class="muted">Generating recipes…</div>`;
  const r = await fetch(`/api/defense/${cve}`).then(r => r.json());
  if (!r.controls) {
    $("#defBox").innerHTML = `<div class="muted">No recipes available.</div>`;
    return;
  }
  const html = r.controls.map(c => `
    <div class="defense-block">
      <span class="layer-tag">L${c.layer}</span>
      <span class="type-tag">${c.type}</span>
      <b style="margin-left:8px">${c.title}</b>
      ${c.cwe ? `<span class="muted"> · ${c.cwe}</span>` : ''}
      <pre>${escapeHtml(c.code || '')}</pre>
    </div>`).join("");
  $("#defBox").outerHTML = html;
}

/* ---------- Similar (DNA) ---------- */
async function loadSimilar(cve) {
  const ex = $("#extra");
  ex.innerHTML = `<div class="section-h">Semantically similar CVEs</div><div id="simBox" class="muted">Finding neighbors…</div>`;
  const r = await fetch(`/api/similar/${cve}?k=12`).then(r => r.json());
  const ns = r.neighbors || [];
  if (!ns.length) {
    $("#simBox").innerHTML = `<div class="muted">No neighbors yet. Run <code>python -m engine.dna embed</code> to enable semantic search.</div>`;
    return;
  }
  const html = ns.map(n => `
    <div class="twin-row" onclick="loadCVE('${n.id}')">
      <span><b>${n.id}</b></span>
      <span>${n.severity || '?'}</span>
      <span class="twin-score">${(n.score||0).toFixed(3)}</span>
      <span class="muted">cwe ${(n.cwes||[]).join(',') || '—'} · L${(n.layers||[]).join(',') || '—'}</span>
    </div>`).join("");
  $("#simBox").outerHTML = html;
}

/* ---------- SBOM mode ---------- */
function initSbom() {
  const dz = $("#dropzone");
  const fi = $("#sbomFile");
  ["dragenter","dragover"].forEach(e => dz.addEventListener(e, ev => { ev.preventDefault(); dz.classList.add("dragover"); }));
  ["dragleave","drop"].forEach(e => dz.addEventListener(e, ev => { ev.preventDefault(); dz.classList.remove("dragover"); }));
  dz.addEventListener("drop", ev => { fi.files = ev.dataTransfer.files; });
  $("#sbomBtn").addEventListener("click", uploadSbom);
}
async function uploadSbom() {
  const f = $("#sbomFile").files[0];
  if (!f) { alert("Pick a file first."); return; }
  const fd = new FormData(); fd.append("file", f);
  $("#sbomResult").innerHTML = `<div class="muted">Scanning ${f.name} (${(f.size/1024).toFixed(1)} KB)…</div>`;
  const r = await fetch("/api/sbom", { method: "POST", body: fd }).then(r => r.json());
  if (r.error) { $("#sbomResult").innerHTML = `<div class="muted">${r.error}</div>`; return; }
  const layerColors = { L1:"#888", L2:"#6699ff", L3:"#00e5ff", L4:"#2ee59d", L5:"#ffcc44", L6:"#b265ff", L7:"#ff4d6d" };
  const totalLayer = Object.values(r.layer_breakdown || {}).reduce((a,b)=>a+b,0) || 1;
  const layerBar = Object.entries(r.layer_breakdown || {}).map(([k,v]) =>
    `<div class="seg" style="width:${(v/totalLayer*100).toFixed(1)}%; background:${layerColors[k]||'#444'}">${k} (${v})</div>`).join("");
  const sevHtml = Object.entries(r.severity_breakdown || {}).map(([k,v]) => `<span class="chip">${k}: ${v}</span>`).join("") || '<span class="muted">no severity data</span>';
  const chains = (r.attack_chains || []).map((c,i) => `
    <div class="chain-card">
      <div><b>Chain #${i+1}</b> — score <span class="twin-score">${c.score}</span> · layers ${c.layers_traversed.join(', ')} · depth ${c.length}</div>
      ${c.steps.map(s => `<div class="step"><span class="arrow">${s.layer_from?`L${s.layer_from}→L${s.layer_to}`:`L${s.layer_to}`}</span> <a href="#" onclick="document.querySelector('[data-mode=explore]').click(); loadCVE('${s.cve}'); return false;">${s.cve}</a> · ${s.severity || '?'} · ${s.transition || ''}</div>`).join("")}
    </div>`).join("") || '<div class="muted">No attack chains derivable for this stack.</div>';
  const pkgRows = (r.packages || []).filter(p=>p.cves?.length).map(p =>
    `<div class="pkg-row"><span class="eco">${p.ecosystem}</span><span><b>${p.name}</b> <span class="muted">· ${p.cves.length} CVE(s)</span></span></div>`).join("") || '<div class="muted">No vulnerable packages found.</div>';
  $("#sbomResult").innerHTML = `
    <div class="sbom-summary">
      <div class="stat"><div class="num">${r.component_count}</div><div class="lbl">parsed</div></div>
      <div class="stat"><div class="num">${r.matched_packages}</div><div class="lbl">matched</div></div>
      <div class="stat"><div class="num">${r.cve_count}</div><div class="lbl">CVEs</div></div>
      <div class="stat"><div class="num">${r.aggregate_score}</div><div class="lbl">${r.aggregate_band}</div></div>
      <div class="stat"><div class="num">${(r.attack_chains||[]).length}</div><div class="lbl">attack paths</div></div>
    </div>
    <div class="section-h">OSI Distribution</div>
    <div class="sbom-layer-bar">${layerBar || '<span class="muted" style="margin:auto">no layer hits</span>'}</div>
    <div class="section-h">Severity Breakdown</div><div class="chips">${sevHtml}</div>
    <div class="section-h">Top Cross-Layer Attack Chains</div>${chains}
    <div class="section-h">Vulnerable Packages</div>${pkgRows}
  `;
}

/* ---------- Red-Team mode ---------- */
async function runRedTeam() {
  const stack = $("#rtStack").value.trim();
  if (!stack) { alert("Describe your stack."); return; }
  const purls = $("#rtPurls").value.split(",").map(s => s.trim()).filter(Boolean);
  const entry = $("#rtEntry").value;
  $("#rtResult").innerHTML = `<div class="muted">Running graph fan-out + LLM (this may take 20-60s if Ollama is invoked)…</div>`;
  const r = await fetch("/api/red-team", {
    method: "POST", headers: {"Content-Type":"application/json"},
    body: JSON.stringify({ stack_summary: stack, purls, entry })
  }).then(r => r.json());
  const chainsHtml = (r.chains || []).map((c,i) => `
    <div class="chain-card">
      <div><b>Chain #${i+1}</b> — score <span class="twin-score">${c.score}</span> · layers ${c.layers_traversed.join(', ')}</div>
      ${c.steps.map(s => `<div class="step"><span class="arrow">${s.layer_from?`L${s.layer_from}→L${s.layer_to}`:`L${s.layer_to}`}</span> ${s.cve} · ${s.transition || ''}</div>`).join("")}
    </div>`).join("");
  $("#rtResult").innerHTML = `
    <div class="section-h">Aggregate Nexus score: <span class="twin-score">${r.aggregate_score.toFixed(1)}</span> / 100 (${r.band})</div>
    ${chainsHtml}
    <div class="section-h">Red-Team Plan</div>
    <pre>${escapeHtml(r.plan || '(no plan)')}</pre>
  `;
}

/* ---------- Posture mode ---------- */
let _postureInited = false;
function initPosture() {
  if (_postureInited) { refreshPolicyList(); return; }
  _postureInited = true;
  document.querySelectorAll(".sub-btn").forEach(btn => {
    btn.addEventListener("click", () => switchSub(btn.dataset.sub));
  });
  $("#policyUploadBtn").addEventListener("click", uploadPolicies);
  $("#policyClearBtn").addEventListener("click", async () => {
    if (!confirm("Delete ALL uploaded policies?")) return;
    await fetch("/api/policies/clear", { method: "DELETE" });
    refreshPolicyList();
    $("#policyResult").innerHTML = `<div class="muted">Cleared.</div>`;
  });
  $("#pastePolicyBtn").addEventListener("click", pastePolicy);
  $("#gapRunBtn").addEventListener("click", runGap);
  refreshPolicyList();
}
function switchSub(sub) {
  document.querySelectorAll(".sub-btn").forEach(b => b.classList.toggle("active", b.dataset.sub === sub));
  ["subUpload","subMatrix","subGaps"].forEach(id => $("#"+id).hidden = id !== "sub" + sub.charAt(0).toUpperCase() + sub.slice(1));
  if (sub === "matrix") loadMatrix();
}
async function uploadPolicies() {
  const files = $("#policyFiles").files;
  if (!files.length) { alert("Pick one or more files."); return; }
  const fd = new FormData();
  for (const f of files) fd.append("files", f);
  $("#policyResult").innerHTML = `<div class="muted">Importing ${files.length} file(s)…</div>`;
  const r = await fetch("/api/policies/upload", { method: "POST", body: fd }).then(r => r.json());
  const lines = (r.files || []).map(f =>
    f.error
      ? `<div class="row" style="color:var(--accent-2)">${f.filename}: ${f.error}</div>`
      : `<div class="row"><b>${f.filename}</b> · ${f.platforms.join(', ')} · ${f.policies} policy / ${f.controls} control(s)</div>`
  ).join("");
  $("#policyResult").innerHTML = `<div class="section-h">Imported ${r.imported} policy file(s)</div>${lines}`;
  refreshPolicyList();
}
async function pastePolicy() {
  const content = $("#policyPaste").value.trim();
  if (!content) return;
  const hint = $("#pasteHint").value.trim() || null;
  const r = await fetch("/api/policies/paste", {
    method: "POST", headers: {"Content-Type":"application/json"},
    body: JSON.stringify({ content, hint })
  }).then(r => r.json());
  $("#policyResult").innerHTML = `<div class="row">Imported ${r.imported} policy / ${r.controls} control(s) (${(r.platforms||[]).join(', ')||'unknown format'})</div>`;
  refreshPolicyList();
}
async function refreshPolicyList() {
  const r = await fetch("/api/policies").then(r => r.json());
  const grouped = {};
  (r.policies || []).forEach(p => { (grouped[p.source] = grouped[p.source] || []).push(p); });
  const html = Object.entries(grouped).map(([src, ps]) =>
    `<div class="section-h">${src} (${ps.length})</div>` +
    ps.map(p => `<div class="row"><b>${p.name}</b> <span class="muted">· ${p.type} · ${p.controls} control(s)</span></div>`).join("")
  ).join("") || `<div class="muted">No policies loaded yet.</div>`;
  $("#policyList").innerHTML = html;
}

async function loadMatrix() {
  $("#matrixBox").innerHTML = `<div class="muted">Loading…</div>`;
  const r = await fetch("/api/posture/coverage").then(r => r.json());
  const platforms = Object.entries(r.policies_loaded || {});
  const platformLine = platforms.length
    ? `<div class="muted" style="margin-bottom:14px">Loaded: ${platforms.map(([s,n])=>`${s} ×${n}`).join(' · ')}</div>`
    : `<div class="muted" style="margin-bottom:14px">No policies loaded - go to Upload Policies first. The matrix below will all be red.</div>`;

  const headerCells = [1,2,3,4,5,6,7].map(l => `<th>L${l}</th>`).join("");
  const rows = (r.matrix || []).map(m => {
    const cells = [1,2,3,4,5,6,7].map(l => {
      const n = m.by_layer["L"+l] || 0;
      const cls = n === 0 ? "empty" : n >= 3 ? "has has-high" : "has";
      const tip = `${n} control(s) at L${l} mitigating ${m.capability}`;
      return `<td class="cell ${cls}" title="${tip}">${n || '—'}</td>`;
    }).join("");
    const pctClass = m.coverage_pct >= 80 ? "full" : m.coverage_pct >= 30 ? "partial" : "empty";
    return `<tr>
      <td class="cap-name" title="Recommended classes: ${m.recommended_classes.join(', ')}\nMissing: ${m.missing_classes.join(', ')}">${m.capability}</td>
      ${cells}
      <td class="coverage-pct ${pctClass}">${m.coverage_pct}%</td>
    </tr>`;
  }).join("");
  $("#matrixBox").innerHTML = `
    ${platformLine}
    <table class="matrix-table">
      <thead><tr><th style="text-align:left">Capability</th>${headerCells}<th>Class coverage</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}

async function runGap() {
  let cve = $("#gapCve").value.trim().toUpperCase();
  if (!cve) { alert("Enter a CVE-ID."); return; }
  if (!cve.startsWith("CVE-")) cve = "CVE-" + cve;
  $("#gapsBox").innerHTML = `<div class="muted">Building chain + scanning policies…</div>`;
  const [gapResp, replayResp] = await Promise.all([
    fetch(`/api/posture/gaps/${cve}`).then(r => r.json()),
    fetch(`/api/posture/replay/${cve}`).then(r => r.json()),
  ]);
  const gaps = (gapResp.gaps || []).map(g => `
    <div class="gap-card ${g.severity}">
      <span class="severity-pill ${g.severity}">${g.severity} GAP</span>
      <span class="cap">${g.capability}</span>
      <span class="muted"> · step at L${g.step_layer} of ${g.cve}</span>
      <div class="muted" style="margin-top:6px">Recommended classes: ${(g.recommended_classes||[]).join(', ') || '—'}</div>
      ${(g.remediations||[]).map(r => `<div class="rec"><b>${r.title}</b> <span class="muted">[${(r.platforms||[]).join(', ')}]</span><br>${r.snippet ? escapeHtml(r.snippet) : ''}</div>`).join("")}
    </div>`).join("") || `<div class="muted">No gaps for this CVE - everything is covered.</div>`;
  const blocks = (gapResp.blocks || []).map(b => `
    <div class="block-card">
      <span class="cap">✓ ${b.capability}</span>
      <span class="muted"> · L${b.step_layer} · ${b.cve}</span>
      <div class="muted" style="margin-top:6px">${b.summary}</div>
    </div>`).join("");
  const v = (replayResp.summary || {}).overall || "?";
  const tlSteps = (replayResp.steps || []).map(s => `
    <div class="tl-step ${s.verdict}">
      <span class="verdict ${s.verdict}">${s.verdict}</span>
      <b style="margin-left:8px">step ${s.n}</b>
      <span class="muted"> · ${s.layer_from?`L${s.layer_from}→`:''}L${s.layer_to} · ${s.cve}</span>
      <div class="muted" style="margin-top:4px">${s.transition || ''}</div>
      ${(s.blocks||[]).map(b => `<div style="margin-top:4px;color:var(--green);font-size:11px">✓ ${b.capability} blocked by <b>${b.control.title || b.control.id}</b> <span class="muted">(${b.control.source||'?'})</span></div>`).join("")}
      ${(s.gaps||[]).map(g => `<div style="margin-top:4px;color:var(--accent-2);font-size:11px">✗ ${g.capability} unblocked - try: ${g.recommended.join(', ')}</div>`).join("")}
    </div>`).join("");
  $("#gapsBox").innerHTML = `
    <div class="section-h">Verdict: <span class="verdict ${v}">${v}</span> for ${cve}</div>
    <div class="section-h">Per-step replay</div>
    <div class="timeline">${tlSteps}</div>
    <div class="section-h">Gaps (${(gapResp.gaps||[]).length})</div>${gaps}
    ${blocks ? `<div class="section-h">Blocks (${(gapResp.blocks||[]).length})</div>${blocks}` : ''}
  `;
}

/* ---------- HIPAA / Compliance mode ---------- */
let _hipaaInited = false;
function initHipaa() {
  refreshHipaaSummary();
  if (_hipaaInited) return; _hipaaInited = true;
  $("#phiSeedBtn").addEventListener("click", async () => {
    if (!confirm("This will pull ~50 healthcare packages from OSV.dev. Takes 1-2 minutes the first time. Continue?")) return;
    $("#phiSeedStatus").textContent = "Seeding healthcare packages from OSV.dev (this may take 1-2 minutes)…";
    $("#phiSeedBtn").disabled = true;
    try {
      const r = await fetch("/api/hipaa/seed-phi?via_osv=true", { method: "POST" }).then(r => r.json());
      $("#phiSeedStatus").textContent =
        `Done. Created ${r.created_packages} package node(s); tagged ${r.tagged} as :HandlesPHI` +
        (r.errors && r.errors.length ? ` (${r.errors.length} OSV error(s) - see API console)` : "");
      refreshHipaaSummary();
    } catch (e) {
      $("#phiSeedStatus").textContent = "Seed failed: " + e.message;
    } finally {
      $("#phiSeedBtn").disabled = false;
    }
  });
  $("#phiTagBtn").addEventListener("click", async () => {
    const r = await fetch("/api/hipaa/tag-phi", { method: "POST" }).then(r => r.json());
    $("#phiSeedStatus").textContent = `Tagged ${r.tagged} PHI-handling package(s) (no OSV pull).`;
    refreshHipaaSummary();
  });
  $("#hipaaSraBtn").addEventListener("click", () => generateSra("markdown"));
  $("#hipaaSraDocxBtn").addEventListener("click", () => generateSra("docx"));
}
async function refreshHipaaSummary() {
  $("#hipaaSummary").innerHTML = `<div class="muted">Loading…</div>`;
  const r = await fetch("/api/hipaa/coverage").then(r => r.json());
  const pkgs = (r.phi_packages || []).slice(0,12).map(p =>
    `<div class="row"><b>${p.name}</b> <span class="muted">${p.ecosystem} · ${p.cve_count} CVE(s)</span></div>`).join("");
  const cves = (r.phi_cves || []).slice(0,15).map(c =>
    `<div class="row" onclick="document.querySelector('[data-mode=explore]').click(); loadCVE('${c.id}')">
      <b>${c.id}</b> · ${c.severity || '?'} · CVSS ${c.cvss || '?'} · L${(c.layers||[]).join(',')}</div>`).join("");
  const cap = (r.regulatory_capabilities || []).map(rc => `
    <div class="gap-card ${rc.coverage_pct >= 80 ? 'LOW' : rc.coverage_pct >= 30 ? 'MEDIUM' : 'HIGH'}">
      <span class="cap">${rc.capability}</span>
      <span class="muted"> · ${rc.coverage_pct}% covered · ${rc.controls_total} control(s)</span>
      <div class="muted" style="margin-top:6px">Citations: ${rc.citations.map(c=>`${c.framework} §${c.section}`).join('; ')}</div>
    </div>`).join("");
  $("#hipaaSummary").innerHTML = `
    <div class="sbom-summary">
      <div class="stat"><div class="num">${r.phi_package_count}</div><div class="lbl">PHI packages</div></div>
      <div class="stat"><div class="num">${r.phi_cve_count}</div><div class="lbl">PHI-affecting CVEs</div></div>
      <div class="stat"><div class="num">${(r.regulatory_capabilities || []).length}</div><div class="lbl">regulated capabilities</div></div>
    </div>
    <div class="section-h">PHI-Handling Components</div>${pkgs || '<div class="muted">None tagged yet — click "Tag PHI packages" above after running the SBOM/OSV ingest.</div>'}
    <div class="section-h">Top PHI-Affecting CVEs</div>${cves || '<div class="muted">None.</div>'}
    <div class="section-h">Regulated Capabilities Coverage</div>${cap}
  `;
}
async function generateSra(format) {
  const stack = $("#hipaaStack").value.trim();
  const org = $("#hipaaOrg").value.trim() || "Your Organization";
  if (format === "docx") {
    const resp = await fetch("/api/hipaa/sra", {
      method: "POST", headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ format: "docx", organization: org, stack_summary: stack })
    });
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = "HIPAA_SRA.docx"; a.click();
    URL.revokeObjectURL(url);
    return;
  }
  $("#hipaaSraOut").style.display = "block";
  $("#hipaaSraOut").innerHTML = `<div class="muted">Generating…</div>`;
  const r = await fetch("/api/hipaa/sra", {
    method: "POST", headers: {"Content-Type":"application/json"},
    body: JSON.stringify({ format: "markdown", organization: org, stack_summary: stack })
  }).then(r => r.json());
  $("#hipaaSraOut").innerHTML = `<pre>${escapeHtml(r.report)}</pre>`;
}

/* ---------- Clinical AI mode ---------- */
let _clinInited = false;
function initClinical() {
  if (_clinInited) return; _clinInited = true;
  document.querySelectorAll("[data-sub-clin]").forEach(btn => {
    btn.addEventListener("click", () => switchClinSub(btn.dataset.subClin));
  });
  $("#clinRunBtn").addEventListener("click", runClinical);
  $("#clinFindingsBtn").addEventListener("click", refreshClinFindings);
  $("#cardGenBtn").addEventListener("click", () => generateCard("markdown"));
  $("#cardDocxBtn").addEventListener("click", () => generateCard("docx"));
  loadClinCategories();
}
function switchClinSub(s) {
  document.querySelectorAll("[data-sub-clin]").forEach(b => b.classList.toggle("active", b.dataset.subClin === s));
  ["clinRun","clinFindings","clinCard"].forEach(id => $("#"+id).hidden = id !== `clin${s.charAt(0).toUpperCase()+s.slice(1)}`);
  if (s === "findings") refreshClinFindings();
}
async function loadClinCategories() {
  const r = await fetch("/api/clinical-ai/categories").then(r => r.json());
  const html = (r.categories || []).map(c => `
    <label style="margin-right:14px;display:inline-block">
      <input type="checkbox" class="clin-cat" value="${c.category}" checked />
      <b>${c.category}</b> <span class="muted">(${c.case_count} cases)</span>
    </label>`).join("");
  $("#clinCategories").innerHTML = `<div class="muted">${r.total_cases} test cases across categories:</div>${html}`;
}
async function runClinical() {
  const model = $("#clinModel").value.trim() || "llama3.1:8b";
  const cats = Array.from(document.querySelectorAll(".clin-cat:checked")).map(c => c.value);
  const apiBase = $("#clinApiBase").value.trim() || null;
  const apiKey = $("#clinApiKey").value.trim() || null;
  $("#clinRunStatus").innerHTML = `<div class="muted">Running ${cats.length} categor(ies) against ${model}… this may take 1-5 minutes.</div>`;
  try {
    const r = await fetch("/api/clinical-ai/run", {
      method: "POST", headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ model, categories: cats, api_base: apiBase, api_key: apiKey })
    }).then(r => r.json());
    const fail = r.findings.filter(f => !f.passed);
    const failHtml = fail.map(f => `
      <div class="gap-card ${f.severity}">
        <span class="severity-pill ${f.severity}">${f.severity}</span>
        <span class="cap">${f.test_id}</span>
        <span class="muted"> · ${f.category}</span>
        <div class="muted" style="margin-top:6px">${f.reason}</div>
        ${f.citation ? `<div class="muted">Citation: ${f.citation}</div>` : ''}
        <details style="margin-top:6px"><summary class="muted">Model response</summary><pre>${escapeHtml(f.response||'')}</pre></details>
      </div>`).join("");
    $("#clinRunStatus").innerHTML = `
      <div class="sbom-summary">
        <div class="stat"><div class="num">${r.findings.length}</div><div class="lbl">Tests</div></div>
        <div class="stat"><div class="num">${r.findings.length - fail.length}</div><div class="lbl">Pass</div></div>
        <div class="stat"><div class="num">${fail.length}</div><div class="lbl">Fail</div></div>
      </div>
      <div class="section-h">Failures</div>
      ${failHtml || '<div class="muted">All tests passed.</div>'}
    `;
  } catch (e) {
    $("#clinRunStatus").innerHTML = `<div class="muted" style="color:var(--accent-2)">Run failed: ${e.message}. Make sure Ollama is running with the chosen model pulled, or set api_base for an OpenAI-compatible endpoint.</div>`;
  }
}
async function refreshClinFindings() {
  const m = $("#clinFindingsModel").value.trim() || null;
  const url = "/api/clinical-ai/findings" + (m ? `?model=${encodeURIComponent(m)}` : "");
  const r = await fetch(url).then(r => r.json());
  const summ = r.summary || {};
  const sumHtml = Object.entries(summ.by_category || {}).map(([k,v]) =>
    `<div class="row"><b>${k}</b> <span class="muted">${v.passed} pass / ${v.failed} fail</span></div>`).join("");
  const items = (r.findings || []).map(f => `
    <div class="gap-card ${f.passed ? 'LOW' : f.severity}">
      <span class="severity-pill ${f.passed ? 'LOW' : f.severity}">${f.passed ? '✓ PASS' : f.severity}</span>
      <span class="cap">${f.test_id}</span> <span class="muted">${f.category} · ${f.model} · ${f.timestamp}</span>
      <div class="muted" style="margin-top:6px">${f.reason || ''}</div>
    </div>`).join("");
  $("#clinFindingsBox").innerHTML = `
    <div class="section-h">By category</div>${sumHtml || '<div class="muted">No findings yet.</div>'}
    <div class="section-h">All findings</div>${items}
  `;
}
async function generateCard(format) {
  const body = {
    model_name: $("#cardModel").value.trim() || "(unspecified)",
    intended_use: $("#cardIntended").value.trim(),
    training_data: $("#cardTraining").value.trim(),
    evaluation_data: $("#cardEval").value.trim(),
    limitations: $("#cardLimits").value.trim(),
    monitoring_plan: $("#cardMonitoring").value.trim(),
    format,
  };
  if (format === "docx") {
    const resp = await fetch("/api/clinical-ai/model-card", {
      method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify(body)});
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = "model_card.docx"; a.click();
    URL.revokeObjectURL(url);
    return;
  }
  $("#cardOut").style.display = "block";
  $("#cardOut").innerHTML = `<div class="muted">Generating…</div>`;
  const r = await fetch("/api/clinical-ai/model-card", {
    method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify(body)
  }).then(r => r.json());
  $("#cardOut").innerHTML = `<pre>${escapeHtml(r.report)}</pre>`;
}

/* ---------- KEV mode ---------- */
async function refreshKev(force) {
  $("#kevResult").innerHTML = `<div class="muted">Loading CISA KEV…</div>`;
  if (force === undefined) force = false;
  if (event && event.type === "click" && event.target.id === "kevRefresh") {
    await fetch("/api/telemetry/refresh", { method: "POST" });
  }
  const r = await fetch("/api/telemetry/kev").then(r => r.json());
  if (!r.cves || !r.cves.length) {
    $("#kevResult").innerHTML = `<div class="muted">No KEV data yet. Click 'Refresh from CISA' above.</div>`;
    return;
  }
  const rows = r.cves.map(c => `
    <div class="kev-row" onclick="document.querySelector('[data-mode=explore]').click(); loadCVE('${c.id}')">
      <span><b>${c.id}</b></span>
      <span>${c.severity || '?'}</span>
      <span>added ${(c.added||'').slice(0,10)} · L${(c.layers||[]).join(',') || '—'}</span>
      <span>${c.cvss || '?'}</span>
      <span class="${c.ransomware === 'Known' ? 'ransomware' : ''}">${c.ransomware || ''}</span>
    </div>`).join("");
  $("#kevResult").innerHTML = `<div class="muted">${r.count} actively-exploited vulnerabilities (CISA KEV)</div>${rows}`;
}

/* ---------- CWE detail ---------- */
async function loadCWE(id) {
  if (!id.toUpperCase().startsWith("CWE-")) id = "CWE-" + id;
  const d = await fetch(`${API}/cwe/${id}`).then(r => r.ok ? r.json() : Promise.reject(r.status));
  const w = d.cwe;
  const layers = d.layers.map(l => `<span class="chip layer" onclick="loadOSI(${l.number})">L${l.number} ${l.name}</span>`).join("");
  const parents = d.parents.filter(p => p.id).map(p => `<span class="chip" onclick="loadCWE('${p.id}')">${p.id} — ${p.name||''}</span>`).join("") || '<span class="muted">—</span>';
  const children = d.children.filter(c => c.id).map(c => `<span class="chip" onclick="loadCWE('${c.id}')">${c.id} — ${c.name||''}</span>`).join("") || '<span class="muted">—</span>';
  const cves = d.cves.slice(0,30).map(c => `<span class="chip" onclick="loadCVE('${c.id}')">${c.id} (${c.severity||'?'})</span>`).join("");
  $("#detail").innerHTML = `
    <div class="cve-card">
      <h2>${w.id} — ${w.name||''}</h2>
      <span class="severity-pill MEDIUM">${w.abstraction||''}</span>
      <span class="muted"> · ${w.status||''}</span>
      <div class="desc">${escapeHtml(w.description||'')}</div>
      <div class="section-h">OSI Layers</div><div class="chips">${layers}</div>
      <div class="section-h">Parent CWEs</div><div class="chips">${parents}</div>
      <div class="section-h">Child CWEs</div><div class="chips">${children}</div>
      <div class="section-h">CVEs (${d.cve_count})</div><div class="chips">${cves || '<span class="muted">none yet</span>'}</div>
    </div>`;
}

/* ---------- Package detail ---------- */
async function loadPackage(eco, name) {
  const d = await fetch(`${API}/package/${eco}/${encodeURIComponent(name)}`).then(r => r.ok ? r.json() : Promise.reject(r.status));
  const p = d.pkg;
  const cves = d.cves.map(c => `
    <div class="row" onclick="loadCVE('${c.id}')"><b>${c.id}</b> · ${c.severity||'?'} · CVSS ${c.cvss_score??'?'}
      ${c.affected?.length ? `<br><span class="muted">affected ${c.affected.join(', ')}</span>` : ''}
      ${c.fixed?.length ? `<span class="muted"> · fixed ${c.fixed.join(', ')}</span>` : ''}
    </div>`).join("") || '<span class="muted">No CVEs linked.</span>';
  $("#detail").innerHTML = `
    <div class="cve-card">
      <h2>${p.name}</h2>
      <span class="severity-pill HIGH">${p.ecosystem}</span>
      <div class="muted">${p.purl}</div>
      <div class="section-h">CVEs affecting this package (${d.cves.length})</div>${cves}
    </div>`;
}

/* ---------- OSI layer ---------- */
async function loadOSI(layerNum) {
  const d = await fetch(`${API}/osi/${layerNum}`).then(r => r.json());
  const t = d.totals || {};
  const cveLine = (c) => `<div class="row" onclick="loadCVE('${c.id}')"><b>${c.id}</b> · ${c.severity||'?'} · CVSS ${c.cvss_score ?? '?'}</div>`;
  const cves = (d.cves || []).map(cveLine).join("") || '<span class="muted">none yet</span>';
  const cwes = (d.cwes || []).map(c=>`<div class="row" onclick="loadCWE('${c.id}')"><b>${c.id}</b> — ${c.name||''}</div>`).join("") || '<span class="muted">none yet</span>';
  const ai = (d.ai_threats || []).map(a=>`<div class="row" onclick="loadAIThreat('${a.id}')"><b>${a.id}</b> — ${a.name} <span class="muted">${a.framework}</span></div>`).join("") || '<span class="muted">—</span>';
  const cveHdr = t.cve_total != null ? `CVEs at this layer <span class="muted">(showing top ${(d.cves||[]).length} of ${t.cve_total} by CVSS)</span>` : 'CVEs at this layer';
  const cweHdr = t.cwe_total != null ? `CWEs at this layer <span class="muted">(${t.cwe_total})</span>` : 'CWEs at this layer';
  const aiHdr  = t.ai_total  != null ? `AI Threats at this layer <span class="muted">(${t.ai_total})</span>` : 'AI Threats at this layer';
  $("#detail").innerHTML = `
    <div class="cve-card">
      <h2>OSI Layer ${d.layer.number} — ${d.layer.name}</h2>
      <div class="desc">${escapeHtml(d.layer.description||'')}</div>
      <div class="section-h">${cveHdr}</div>${cves}
      <div class="section-h">${cweHdr}</div>${cwes}
      <div class="section-h">${aiHdr}</div>${ai}
    </div>`;
}

/* ---------- AI threat ---------- */
async function loadAIThreat(id) {
  const list = await fetch(`${API}/ai-vulns`).then(r => r.json());
  const t = list.find(x => x.threat.id === id);
  if (!t) return;
  const layers = (t.layers||[]).filter(Boolean).map(n => `<span class="chip layer" onclick="loadOSI(${n})">L${n} ${LAYER_NAMES[n]}</span>`).join("");
  const cves = (t.cves||[]).filter(Boolean).map(c => `<span class="chip" onclick="loadCVE('${c}')">${c}</span>`).join("") || '<span class="muted">—</span>';
  $("#detail").innerHTML = `
    <div class="cve-card">
      <h2>${t.threat.id} — ${t.threat.name}</h2>
      <span class="severity-pill HIGH">${t.threat.framework}</span>
      <div class="desc">${escapeHtml(t.threat.description||'')}</div>
      <div class="section-h">OSI Layers</div><div class="chips">${layers}</div>
      <div class="section-h">Linked CVEs</div><div class="chips">${cves}</div>
    </div>`;
}

/* ---------- Cytoscape graph ---------- */
function initGraph() {
  cy = cytoscape({
    container: document.getElementById("cy"),
    style: [
      { selector: "node", style: {
          "label": "data(label)", "font-size": 9, "color": "#d6e1f5",
          "text-valign": "bottom", "text-halign": "center", "text-margin-y": 4,
          "background-color": "#1a2742", "border-width": 1, "border-color": "#2d4068", "width": 22, "height": 22,
        }},
      { selector: 'node[label = "CVE"]', style: { "background-color": "#ff4d6d", "shape": "diamond", "width": 28, "height": 28 } },
      { selector: 'node[label = "CWE"]', style: { "background-color": "#ffcc44", "shape": "round-rectangle" } },
      { selector: 'node[label = "OSILayer"]', style: { "background-color": "#00e5ff", "shape": "hexagon", "width": 32, "height": 32 } },
      { selector: 'node[label = "Package"]', style: { "background-color": "#2ee59d", "shape": "ellipse" } },
      { selector: 'node[label = "PoC"]', style: { "background-color": "#b265ff", "shape": "triangle" } },
      { selector: 'node[label = "AIThreat"]', style: { "background-color": "#ff8800", "shape": "star" } },
      { selector: "edge", style: { "width": 1, "line-color": "#2d4068", "target-arrow-color": "#2d4068",
                                   "target-arrow-shape": "triangle", "curve-style": "bezier",
                                   "label": "data(label)", "font-size": 7, "color": "#6c7a99",
                                   "text-rotation": "autorotate" }},
    ],
    // Concentric is one-shot, deterministic, no per-frame iteration.
    layout: { name: "concentric", animate: false, fit: false },
    wheelSensitivity: 0.2,
    pixelRatio: 1,                  // avoid DPR-driven repaints
    textureOnViewport: true,         // cheap repaints during pan/zoom
    motionBlur: false,
    hideEdgesOnViewport: false,
  });
  cy.on("tap", "node", (e) => {
    const d = e.target.data();
    if (d.label === "CVE")      loadCVE(d.id.split(":")[1]);
    else if (d.label === "CWE") loadCWE(d.id.split(":")[1]);
    else if (d.label === "OSILayer") loadOSI(parseInt(d.id.split(":")[1]));
    else if (d.label === "AIThreat") loadAIThreat(d.id.split(":")[1]);
    else if (d.label === "Package") loadPackage(d.ecosystem, d.name);
  });

  // Debounce browser resize -> single fit() call
  window.addEventListener("resize", () => {
    clearTimeout(_graphResizeTimer);
    _graphResizeTimer = setTimeout(() => {
      cy.resize();
      cy.fit(undefined, 30);
    }, 150);
  });
}

async function drawGraph(cveId) {
  // Don't repeat the SAME successful render, but always allow retry on failure.
  if (_lastGraphCve === cveId && cy.elements().length > 0) return;

  $("#graphHint").textContent = `loading nexus for ${cveId}…`;
  let g;
  try {
    const resp = await fetch(`${API}/graph/${cveId}`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    g = await resp.json();
  } catch (e) {
    $("#graphHint").textContent = `graph fetch failed: ${e.message}`;
    console.error("graph fetch failed:", e);
    cy.elements().remove();
    _lastGraphCve = null;
    return;
  }

  const nodes = Array.isArray(g.nodes) ? g.nodes : [];
  const edges = Array.isArray(g.edges) ? g.edges : [];

  if (nodes.length === 0) {
    $("#graphHint").textContent = `${cveId} has no relationships in the graph yet`;
    cy.elements().remove();
    _lastGraphCve = null;
    return;
  }

  // Batch mutations + run layout once. Prevents intermediate paints.
  cy.startBatch();
  cy.elements().remove();
  try {
    cy.add(nodes);
    cy.add(edges);
  } catch (e) {
    console.error("cytoscape add failed:", e, { nodes, edges });
    cy.endBatch();
    $("#graphHint").textContent = `cytoscape add failed: ${e.message}`;
    _lastGraphCve = null;
    return;
  }
  cy.endBatch();

  if (nodes.length === 1) {
    // A single node - no need for a layout, just center it.
    cy.center();
    cy.fit(undefined, 30);
  } else {
    cy.layout({
      name: "concentric",
      fit: true, padding: 25, animate: false,
      concentric: (n) => (n.data("label") === "CVE" ? 10 : 1),
      levelWidth: () => 1,
      minNodeSpacing: 30,
    }).run();
  }

  $("#graphHint").textContent = `nexus around ${cveId} · ${nodes.length} nodes, ${edges.length} edges`;
  _lastGraphCve = cveId;
}

/* ---------- helpers ---------- */
function escapeHtml(s) {
  return (s || "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
}
