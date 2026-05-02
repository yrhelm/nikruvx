#!/usr/bin/env bash
# =============================================================
#  NikruvX / Cyber Nexus -- one-shot Linux/macOS installer
# =============================================================
#  Usage:
#    ./install.sh                    # full install + bootstrap + run
#    SKIP_BOOTSTRAP=1 ./install.sh   # install only
#    SKIP_OLLAMA=1 ./install.sh      # don't pull Ollama models
#    NO_API=1 ./install.sh           # don't auto-start the API
#
#  Safe to re-run. Each step is idempotent.
# =============================================================
set -euo pipefail

VENV=".venv"
TOTAL=8

# ---------- pretty printing ----------
c_cyan="\033[36m"; c_green="\033[32m"; c_yellow="\033[33m"
c_red="\033[31m"; c_dim="\033[2m"; c_off="\033[0m"

step() { printf "\n${c_cyan}[%d/%d] %s${c_off}\n" "$1" "$TOTAL" "$2"; printf "${c_dim}%s${c_off}\n" "----------------------------------------------------------------------"; }
ok()   { printf "  ${c_green}[+]${c_off} %s\n" "$1"; }
warn() { printf "  ${c_yellow}[!]${c_off} %s\n" "$1"; }
die()  { printf "\n  ${c_red}[-]${c_off} %s\n\n" "$1"; exit 1; }

# ---------- 1. preflight ----------
step 1 "Checking prerequisites"

if ! command -v python3 >/dev/null 2>&1; then
  die "python3 is not installed. Install Python 3.11+ first."
fi
PYVER=$(python3 --version | awk '{print $2}')
ok "Python: $PYVER"

if ! command -v docker >/dev/null 2>&1; then
  die "Docker is not installed. Install Docker Desktop / docker-ce first."
fi
if ! docker version >/dev/null 2>&1; then
  die "Docker daemon is not running. Start Docker and re-run."
fi
ok "Docker: running"

# ---------- 2. .env ----------
step 2 "Configuring .env"
if [ ! -f .env ]; then
  if [ -f .env.example ]; then
    cp .env.example .env
    ok "Created .env from .env.example (set NVD_API_KEY for ~10x faster ingest)"
  fi
else
  ok ".env already present"
fi

# ---------- 3. venv + deps ----------
step 3 "Setting up Python venv + dependencies"
if [ ! -d "$VENV" ]; then
  python3 -m venv "$VENV"
  ok "Created $VENV"
else
  ok "$VENV already exists"
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"
python -m pip install --upgrade pip --quiet
pip install -q -r requirements.txt
[ -f requirements-dev.txt ] && pip install -q -r requirements-dev.txt
ok "Python dependencies installed"

# ---------- 4. port check ----------
step 4 "Checking ports 7474, 7687, 8000"
for port in 7474 7687 8000; do
  if (command -v lsof >/dev/null 2>&1 && lsof -nP -iTCP:$port -sTCP:LISTEN >/dev/null 2>&1) ||
     (command -v ss >/dev/null 2>&1 && ss -tln "( sport = :$port )" 2>/dev/null | grep -q ":$port"); then
    warn "Port $port is in use - leaving alone (manually free if it conflicts)"
  else
    ok "Port $port free"
  fi
done

# ---------- 5. start Neo4j ----------
step 5 "Starting Neo4j via docker compose"
docker rm -f nexus-neo4j nikruvx-neo4j nikruvx-api 2>/dev/null || true
docker compose up -d neo4j
ok "Neo4j container created"

printf "  Waiting for Neo4j to accept HTTP (up to 180s)...\n"
ready=0
for i in $(seq 1 60); do
  if curl -fsS -o /dev/null http://localhost:7474; then ready=1; break; fi
  sleep 3
  [ $((i % 5)) -eq 0 ] && [ "$i" -gt 0 ] && printf "    still waiting... (%ss)\n" $((i*3))
done
if [ "$ready" -ne 1 ]; then
  warn "Neo4j HTTP didn't respond. Check 'docker compose logs neo4j'. Continuing anyway."
else
  ok "Neo4j is responding on http://localhost:7474"
fi

# ---------- 6. schema ----------
step 6 "Applying graph schema"
if python -c "from engine.graph import apply_schema; apply_schema(); print('schema ok')"; then
  ok "Schema applied"
else
  warn "Schema apply failed - bootstrap will retry"
fi

# ---------- 7. bootstrap ----------
if [ "${SKIP_BOOTSTRAP:-}" = "1" ]; then
  step 7 "Skipping bootstrap (SKIP_BOOTSTRAP=1)"
else
  step 7 "Bootstrapping the graph (3-6 min)"
  if python scripts/bootstrap.py; then
    ok "Bootstrap complete"
  else
    warn "Bootstrap exited non-zero - some sources may have rate-limited"
  fi
fi

# ---------- 8. ollama ----------
step 8 "Optional: Ollama models"
if [ "${SKIP_OLLAMA:-}" = "1" ]; then
  ok "Skipped (SKIP_OLLAMA=1)"
elif ! command -v ollama >/dev/null 2>&1; then
  warn "Ollama not installed - get it from https://ollama.com/download for the LLM features"
else
  ollama pull llama3.1:8b      || warn "model pull failed (retry later with: make ollama)"
  ollama pull nomic-embed-text || true
  ok "Ollama models pulled"
fi

# ---------- summary ----------
echo ""
echo "================================================="
printf "${c_green}  NikruvX install complete${c_off}\n"
echo "================================================="
echo ""
echo "  Neo4j Browser:  http://localhost:7474  (neo4j / nexus_password)"
echo "  Cyber Nexus UI: http://127.0.0.1:8000/"
echo ""

if [ "${NO_API:-}" = "1" ]; then
  echo "  To start the API, run:"
  printf "    ${c_yellow}make run${c_off}   (or: python -m api.server)\n\n"
else
  echo "  Starting the API now..."
  echo ""
  sleep 2
  exec python -m api.server
fi
