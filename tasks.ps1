<#
.SYNOPSIS
  NikruvX / Cyber Nexus -- Windows task runner (parity with Makefile).
.DESCRIPTION
  PowerShell equivalent of `make` targets. Same names so the README can
  link to either depending on platform.

  Usage:    .\tasks.ps1 <target>
  Targets:  install, bootstrap, run, test, lint, format, mypy,
            openapi, demo, ollama, docker-up, docker-down, clean, help
.EXAMPLE
  .\tasks.ps1 bootstrap
  .\tasks.ps1 run
  .\tasks.ps1 test
#>
param(
  [Parameter(Position = 0)]
  [string]$Target = "help"
)

$ErrorActionPreference = "Stop"
$VENV = ".venv"
$Python = "python"

function Use-Venv {
  if (-not (Test-Path $VENV)) {
    & $Python -m venv $VENV
  }
  $activate = Join-Path $VENV "Scripts\Activate.ps1"
  . $activate
}

function Help {
  @"
NikruvX / Cyber Nexus -- Windows task runner

Targets:
  help          Show this help
  install       Create venv + install runtime + dev dependencies
  docker-up     Start Neo4j via docker-compose
  docker-down   Stop docker stack (preserves data)
  bootstrap     First-time setup: install + Neo4j + ingest
  run           Run the API + UI on http://127.0.0.1:8000
  test          Run pytest suite
  lint          ruff check + ruff format --check + mypy
  format        Auto-format with ruff
  mypy          Type-check engine modules
  openapi       Regenerate docs/openapi.json
  demo          bootstrap + run + open browser
  ollama        Pull recommended Ollama models
  clean         Remove caches and venv (KEEPS data/)
"@
}

function Install {
  Use-Venv
  python -m pip install --upgrade pip
  pip install -r requirements.txt -r requirements-dev.txt
}

function Docker-Up   { docker compose up -d }
function Docker-Down { docker compose down }

function Wait-Neo4j {
  Write-Host "Waiting for Neo4j..."
  for ($i = 0; $i -lt 60; $i++) {
    try {
      $r = Invoke-WebRequest "http://localhost:7474" -UseBasicParsing -TimeoutSec 2
      if ($r.StatusCode -eq 200) { return }
    } catch { Start-Sleep -Seconds 2 }
  }
  throw "Neo4j did not become ready in 120 seconds."
}

function Bootstrap {
  Install
  Docker-Up
  Wait-Neo4j
  python scripts/bootstrap.py
}

function Run     { Use-Venv; python -m api.server }
function Test    { Use-Venv; pytest -q }
function Lint    { Use-Venv; ruff check .; ruff format --check .; mypy engine }
function Format-Code { Use-Venv; ruff format .; ruff check . --fix }
function Mypy    { Use-Venv; mypy engine }

function OpenAPI {
  Use-Venv
  New-Item -Force -ItemType Directory docs > $null
  python -c "from api.server import app; import json, pathlib; pathlib.Path('docs/openapi.json').write_text(json.dumps(app.openapi(), indent=2)); print('docs/openapi.json updated')"
}

function Demo {
  Bootstrap
  Write-Host "Starting API in a new window..."
  Start-Process powershell -ArgumentList "-NoExit", "-Command",
    "Set-Location '$PWD'; . .venv\Scripts\Activate.ps1; python -m api.server"
  Start-Sleep -Seconds 3
  Start-Process "http://127.0.0.1:8000/"
}

function Ollama {
  ollama pull llama3.1:8b
  ollama pull nomic-embed-text
}

function Clean {
  $paths = @(
    $VENV, ".pytest_cache", ".ruff_cache", ".mypy_cache",
    "__pycache__",
    "engine/__pycache__", "ingest/__pycache__", "api/__pycache__",
    "config/__pycache__", "tests/__pycache__", "scripts/__pycache__"
  )
  foreach ($p in $paths) {
    if (Test-Path $p) { Remove-Item -Recurse -Force $p }
  }
}

switch ($Target.ToLower()) {
  "help"        { Help }
  "install"     { Install }
  "docker-up"   { Docker-Up }
  "docker-down" { Docker-Down }
  "bootstrap"   { Bootstrap }
  "run"         { Run }
  "test"        { Test }
  "lint"        { Lint }
  "format"      { Format-Code }
  "mypy"        { Mypy }
  "openapi"     { OpenAPI }
  "demo"        { Demo }
  "ollama"      { Ollama }
  "clean"       { Clean }
  default       { Write-Host "Unknown target: $Target"; Help; exit 1 }
}
