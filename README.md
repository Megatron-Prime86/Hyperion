# Hyperion

AI-powered alert triage and enrichment for SOC analysts.

Alerts land in Postgres (or SQLite with no setup) via `POST /api/v1/alerts/ingest`; `POST /api/v1/simulator/replay` seeds benign noise, a suspicious login, and a multi-stage attack chain. Each ingest runs the pipeline: **enrichment** (IOCs, IP class, local threat intel, asset criticality, MITRE) -> **correlation** (incidents by shared `src_ip`/`user`/`host` within `CORRELATION_WINDOW_MINUTES`) -> **AI triage** (validated JSON, deterministic fallback). The dashboard comes in Phase 3.

LLM: `LLM_PROVIDER=mock` (default, no key) | `openai` | `anthropic` with the matching key; `LLM_MODEL` overrides the default model. Invalid or failed LLM output falls back to deterministic scoring (`provider=fallback`).

Async mode: set `CELERY_TASK_ALWAYS_EAGER=false` and run `celery -A app.pipeline.celery_app worker` from `backend/`. If Redis is unreachable, ingest processes inline.

## Run (no Docker)

SQLite is the default. Redis is optional; Celery falls back to eager mode when it is unset or `CELERY_TASK_ALWAYS_EAGER=true`.

```bash
cd backend
uv venv --python 3.12
uv pip install -e ".[dev]"
uv run uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Run (Docker)

```bash
docker compose up --build
```

API: `http://localhost:8000`. Postgres 18 and Redis 8 come up with the API. Copy `.env.example` if you want local overrides.

## Verify

```bash
curl -s http://127.0.0.1:8000/api/v1/health
curl -s -X POST http://127.0.0.1:8000/api/v1/alerts/ingest \
  -H 'content-type: application/json' \
  -d '{"title":"Blocked outbound DNS","severity":"low","src_ip":"10.1.1.8","user":"a.chen","host":"WKSTN-14"}'
curl -s -X POST http://127.0.0.1:8000/api/v1/alerts/ingest \
  -H 'content-type: application/json' \
  -d '{"alerts":[{"title":"One"},{"title":"Two","severity":"high"}]}'
curl -s -X POST http://127.0.0.1:8000/api/v1/simulator/replay
curl -s http://127.0.0.1:8000/api/v1/incidents
curl -s http://127.0.0.1:8000/api/v1/incidents/<incident-id>
cd backend && pytest -q
```

Ingest accepts one alert object, a JSON list, or `{"alerts":[...]}`.
