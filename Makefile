# PhishLens: one-command workflows. Requires uv (Python) and Node 20+.
.PHONY: setup dev serve test lint eval eval-llm demo docker

setup:            ## Install backend and frontend dependencies
	cd backend && uv sync
	cd frontend && npm ci

dev: setup        ## Run API (:8000) and UI (:3000) with reload; Ctrl+C stops both
	@echo "UI: http://localhost:3000   API: http://localhost:8000/docs"
	@trap 'kill 0' INT TERM; \
	  (cd backend && uv run uvicorn phishlens.api:app --reload --port 8000) & \
	  (cd frontend && PHISHLENS_API_URL=http://127.0.0.1:8000 npm run dev) & \
	  wait

serve: setup      ## Production mode: build the static UI and serve everything from :8000
	cd frontend && NEXT_OUTPUT=export npm run build
	@echo "http://localhost:8000"
	cd backend && PHISHLENS_STATIC_DIR=../frontend/out uv run uvicorn phishlens.api:app --port 8000

test:             ## Backend tests, frontend type check and lint
	cd backend && uv run pytest -q
	cd frontend && npx tsc --noEmit && npm run lint

lint:
	cd backend && uv run ruff check . && uv run ruff format --check .

eval:             ## Download public corpora and evaluate on the held-out split
	cd backend && uv run python eval/download.py
	cd backend && uv run python eval/run_eval.py --split test --report eval/RESULTS.md

eval-llm:         ## Evaluate with the AI content check (needs ANTHROPIC_API_KEY; costs money)
	cd backend && uv run python eval/run_eval.py --split test --with-llm --limit 100 --report eval/RESULTS_LLM.md

demo:             ## The three demo cases in the terminal
	cd backend && uv run python -m phishlens analyze ../frontend/public/samples/obvious-phish.eml
	@echo; echo "------------------------------------------------------------"; echo
	cd backend && uv run python -m phishlens analyze ../frontend/public/samples/ceo-fraud.eml
	@echo; echo "------------------------------------------------------------"; echo
	cd backend && uv run python -m phishlens analyze ../frontend/public/samples/legitimate-invoice.eml

docker:           ## Build and run the single container on :8000
	docker compose up --build
