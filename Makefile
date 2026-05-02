# =====================================================================
#  NikruvX / Cyber Nexus -- one-shot tasks
# =====================================================================
#  Usage:    make <target>
#  Targets:  bootstrap, run, test, lint, demo, openapi, ollama, clean
#
#  On Windows: use tasks.ps1 instead -- same target names.
# =====================================================================

PY ?= python
VENV ?= .venv
ACTIVATE = . $(VENV)/bin/activate

.PHONY: help venv install bootstrap run test lint format mypy openapi \
        demo ollama clean docker-up docker-down

help:        ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

venv:        ## Create the local virtualenv if missing
	@test -d $(VENV) || $(PY) -m venv $(VENV)

install: venv  ## Install runtime + dev dependencies
	@$(ACTIVATE) && pip install --upgrade pip && \
		pip install -r requirements.txt -r requirements-dev.txt

docker-up:   ## Start Neo4j (and optional services) via docker-compose
	docker compose up -d

docker-down: ## Stop docker stack (preserves data volume)
	docker compose down

bootstrap: install docker-up  ## First-time setup: deps + Neo4j + initial ingest
	@echo "Waiting for Neo4j to be ready..."
	@until curl -s -o /dev/null -w "%{http_code}" http://localhost:7474 | grep -q 200; do sleep 2; done
	@$(ACTIVATE) && python scripts/bootstrap.py

run:         ## Run the API + UI on http://127.0.0.1:8000
	@$(ACTIVATE) && python -m api.server

test:        ## Run pytest suite
	@$(ACTIVATE) && pytest -q

lint:        ## ruff lint + format check + mypy
	@$(ACTIVATE) && ruff check . && ruff format --check . && mypy engine

format:      ## Auto-format code with ruff
	@$(ACTIVATE) && ruff format . && ruff check . --fix

mypy:        ## Type-check engine modules
	@$(ACTIVATE) && mypy engine

openapi:     ## Regenerate docs/openapi.json from the FastAPI app
	@$(ACTIVATE) && mkdir -p docs && \
		python -c "from api.server import app; import json, pathlib; pathlib.Path('docs/openapi.json').write_text(json.dumps(app.openapi(), indent=2)); print('docs/openapi.json updated')"

demo:        ## End-to-end demo: bootstrap + start API + open browser
	@make bootstrap
	@echo "Starting API at http://127.0.0.1:8000 ... Ctrl+C to stop"
	@$(ACTIVATE) && python -m api.server &
	@sleep 3
	@command -v xdg-open >/dev/null && xdg-open http://127.0.0.1:8000/ || \
		(command -v open >/dev/null && open http://127.0.0.1:8000/) || \
		echo "Open http://127.0.0.1:8000/ in your browser"

ollama:      ## Pull the recommended Ollama models (separate install required)
	ollama pull llama3.1:8b
	ollama pull nomic-embed-text

clean:       ## Remove caches + venv (KEEPS your data/ directory)
	rm -rf $(VENV) .pytest_cache .ruff_cache .mypy_cache __pycache__ \
	       engine/__pycache__ ingest/__pycache__ api/__pycache__ \
	       config/__pycache__ tests/__pycache__ scripts/__pycache__

.DEFAULT_GOAL := help
