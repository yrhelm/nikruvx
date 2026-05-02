<#
.SYNOPSIS
  NikruvX / Cyber Nexus - one-shot Windows installer.

.DESCRIPTION
  Single command from clone to running UI. Handles every prerequisite,
  retries flaky steps, skips work already done, and prints clear progress.

  Usage:
    .\install.ps1                  # full install + bootstrap
    .\install.ps1 -SkipBootstrap   # install only, no data ingest
    .\install.ps1 -SkipOllama      # don't pull Ollama models
    .\install.ps1 -NoApi           # don't auto-start the API at the end

.NOTES
  Safe to re-run. Each step is idempotent.
#>
param(
  [switch]$SkipBootstrap,
  [switch]$SkipOllama,
  [switch]$NoApi
)

$ErrorActionPreference = "Stop"
$VENV = ".venv"

# ---------- pretty printing ----------
function Step($n, $total, $msg) {
  Write-Host ""
  Write-Host "[$n/$total] $msg" -ForegroundColor Cyan
  Write-Host ("-" * 70) -ForegroundColor DarkGray
}
function Ok($msg) { Write-Host "  [+] $msg" -ForegroundColor Green }
function Warn($msg) { Write-Host "  [!] $msg" -ForegroundColor Yellow }
function Die($msg) {
  Write-Host ""
  Write-Host "  [-] $msg" -ForegroundColor Red
  Write-Host ""
  exit 1
}

# ---------- 0. preflight ----------
Step 1 8 "Checking prerequisites"

# Python
try {
  $pyver = (& python --version 2>&1).ToString()
  if ($pyver -notmatch "^Python 3\.(1[1-9]|[2-9][0-9])") {
    Warn "Python version is $pyver. Recommended: 3.11+. May still work."
  } else {
    Ok "Python: $pyver"
  }
} catch {
  Die "Python is not installed or not on PATH. Install Python 3.11+ from https://www.python.org/downloads/windows/"
}

# Docker
try {
  $null = & docker version --format '{{.Server.Version}}' 2>&1
  if ($LASTEXITCODE -ne 0) { throw }
  Ok "Docker: running"
} catch {
  Die "Docker is not running. Start Docker Desktop and re-run this script."
}

# Git (optional but nice)
try {
  $null = & git --version 2>&1
  Ok "Git: present"
} catch {
  Warn "Git is not installed - that's fine for running, but you'll need it for `git pull`."
}

# ---------- 1. .env file ----------
Step 2 8 "Configuring .env"

if (-not (Test-Path .env)) {
  if (Test-Path .env.example) {
    Copy-Item .env.example .env
    Ok "Created .env from .env.example (set NVD_API_KEY for ~10x faster ingest)"
  } else {
    Warn ".env.example not found - skipping (defaults will be used)"
  }
} else {
  Ok ".env already present"
}

# ---------- 2. Python venv + deps ----------
Step 3 8 "Setting up Python venv + dependencies"

if (-not (Test-Path $VENV)) {
  & python -m venv $VENV
  Ok "Created $VENV"
} else {
  Ok "$VENV already exists"
}

. (Join-Path $VENV "Scripts\Activate.ps1")
& python -m pip install --upgrade pip --quiet
& pip install -q -r requirements.txt
if (Test-Path requirements-dev.txt) { & pip install -q -r requirements-dev.txt }
Ok "Python dependencies installed"

# ---------- 3. Free up port 8000 + 7474 + 7687 if anyone holds them ----------
Step 4 8 "Releasing ports 7474, 7687, 8000 if held"
foreach ($port in 7474, 7687, 8000) {
  $conn = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
  if ($conn) {
    foreach ($c in $conn) {
      try {
        $proc = Get-Process -Id $c.OwningProcess -ErrorAction Stop
        Warn "Port $port held by $($proc.ProcessName) (PID $($c.OwningProcess)) - leaving alone (kill manually if blocking)"
      } catch {}
    }
  } else {
    Ok "Port $port free"
  }
}

# ---------- 4. Start Neo4j (skip api container so no restart-loop) ----------
Step 5 8 "Starting Neo4j via docker compose"

# Force-remove any old containers to avoid name conflicts
foreach ($name in "nexus-neo4j", "nikruvx-neo4j", "nikruvx-api") {
  & docker rm -f $name 2>$null | Out-Null
}

& docker compose up -d neo4j
if ($LASTEXITCODE -ne 0) { Die "docker compose up failed - run 'docker compose logs neo4j' to see why." }
Ok "Neo4j container created"

# Wait for Neo4j to actually accept Bolt connections (more reliable than docker healthcheck)
Write-Host "  Waiting for Neo4j to accept Bolt connections (up to 180s)..."
$ready = $false
for ($i = 0; $i -lt 60; $i++) {
  try {
    $r = Invoke-WebRequest "http://localhost:7474" -UseBasicParsing -TimeoutSec 2
    if ($r.StatusCode -eq 200) { $ready = $true; break }
  } catch {}
  Start-Sleep -Seconds 3
  if ($i % 5 -eq 0 -and $i -gt 0) { Write-Host "    still waiting... ($($i*3)s)" }
}
if (-not $ready) {
  Warn "Neo4j HTTP didn't respond within 180s. Check 'docker compose logs neo4j'. Continuing anyway."
} else {
  Ok "Neo4j is responding on http://localhost:7474"
}

# ---------- 5. Apply schema ----------
Step 6 8 "Applying graph schema"
try {
  & python -c "from engine.graph import apply_schema; apply_schema(); print('schema ok')"
  Ok "Schema applied (constraints + indexes + 7 OSI layers)"
} catch {
  Warn "Schema apply failed: $_  (will retry during bootstrap)"
}

# ---------- 6. Bootstrap ingest ----------
if ($SkipBootstrap) {
  Step 7 8 "Skipping bootstrap (-SkipBootstrap was passed)"
} else {
  Step 7 8 "Bootstrapping the graph (3-6 min, set NVD_API_KEY in .env to speed up 10x)"
  & python scripts\bootstrap.py
  if ($LASTEXITCODE -ne 0) {
    Warn "Bootstrap finished with errors - some sources may have rate-limited. The graph still has whatever loaded."
  } else {
    Ok "Bootstrap complete"
  }
}

# ---------- 7. Optional Ollama models ----------
Step 8 8 "Optional: Ollama models for LLM features"
if ($SkipOllama) {
  Ok "Skipped (-SkipOllama)"
} else {
  $hasOllama = $null
  try { $hasOllama = & ollama --version 2>$null } catch {}
  if (-not $hasOllama) {
    Warn "Ollama is not installed. Get it from https://ollama.com/download/windows for the LLM features."
    Warn "Skipping model pull. You can run '.\tasks.ps1 ollama' later."
  } else {
    try {
      & ollama pull llama3.1:8b
      & ollama pull nomic-embed-text
      Ok "Ollama models pulled (llama3.1:8b + nomic-embed-text)"
    } catch {
      Warn "Ollama model pull hit an error - run '.\tasks.ps1 ollama' later to retry."
    }
  }
}

# ---------- Summary ----------
Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  NikruvX install complete" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Neo4j Browser: http://localhost:7474  (neo4j / nexus_password)"
Write-Host "  Cyber Nexus UI: http://127.0.0.1:8000/"
Write-Host ""

if ($NoApi) {
  Write-Host "  To start the API, run:"
  Write-Host "    .\tasks.ps1 run" -ForegroundColor Yellow
  Write-Host ""
} else {
  Write-Host "  Starting the API now..." -ForegroundColor Yellow
  Write-Host ""
  Start-Sleep -Seconds 2
  & python -m api.server
}
