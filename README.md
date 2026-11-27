# Hyperion

AI-powered alert triage and enrichment for SOC analysts.

Alerts arrive via `POST /api/v1/alerts/ingest` (API key). Each new alert runs the pipeline: **dedup** (repeats fold into a counter) -> **enrichment** (IOCs, IP class, threat intel, asset criticality, MITRE) -> **correlation** (incidents by shared `src_ip`/`user`/`host` within `CORRELATION_WINDOW_MINUTES`) -> **AI triage** (validated JSON, deterministic fallback). Analysts work incidents in the Next.js dashboard.

## Run locally (no Docker)

```bash
cd backend
cp ../.env.example .env            # optional; blank secrets are generated at startup
uv venv --python 3.12 && uv pip install -e ".[dev]"
uv run uvicorn app.main:app --port 8000     # applies migrations on start; SQLite by default
```
On first start the API log prints (once) any generated `INGEST_API_KEY`, `JWT_SECRET` and the `admin` password. Set them in `.env` to keep them stable.

```bash
cd frontend && npm install && npm run dev   # http://localhost:3000, API at http://localhost:8000
```

## Run with Docker

```bash
cp .env.example .env               # optional: set INGEST_API_KEY, ADMIN_PASSWORD, ANALYST_PASSWORD, JWT_SECRET
docker compose up --build          # postgres, redis, api, celery worker, dashboard
docker compose logs api | grep -i generated      # if you left secrets blank
```

## Auth

| Who | How | Can |
|---|---|---|
| Alert sources | `X-API-Key: <INGEST_API_KEY>` | `POST /api/v1/alerts/ingest` |
| `analyst` | login -> Bearer token | view incidents/audit, Acknowledge / Escalate / False Positive / Resolve |
| `admin` | login -> Bearer token | everything above + `POST /api/v1/simulator/replay` |

`POST /api/v1/auth/login` with `{"username","password"}`. Failed logins are throttled (5 per minute per user and IP). The analyst account exists only when `ANALYST_PASSWORD` is set. The audit log records the signed-in username.

## Real alert sources

`POST /api/v1/alerts/ingest/{source}` (API key) normalises vendor formats: `wazuh` (one alert, a list, or `{"alerts":[...]}`) and `cloudtrail` (one record, a list, or `{"Records":[...]}`). Wazuh `rule.level` maps to severity and `rule.mitre` is used directly; hostile or malformed fields are ignored, not trusted. Add a source by writing one function in `app/adapters.py`.

Wazuh integration (not tested against a live manager): copy `integrations/wazuh/custom-hyperion` to `/var/ossec/integrations/` (owner `root:wazuh`, mode `750`) and add to `ossec.conf`:
```xml
<integration>
  <name>custom-hyperion</name>
  <hook_url>http://HYPERION_HOST:8000/api/v1/alerts/ingest/wazuh</hook_url>
  <api_key>YOUR_INGEST_API_KEY</api_key>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
```

Sample packs (recorded Wazuh SSH brute-force-to-root chain, CloudTrail account takeover) replay with times re-based to now: pick a pack next to **Run Simulation** (admin), or `POST /api/v1/simulator/replay?pack=wazuh|cloudtrail|builtin`.

## Live threat intel

Set any of `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, `OTX_API_KEY`, `URLHAUS_API_KEY`. External IPs, domains and hashes are looked up (max `INTEL_MAX_LOOKUPS` per alert), cached in the database for `INTEL_CACHE_HOURS`, and skipped while a source is cooling down after a rate limit (429 honours `Retry-After`) or an auth error. Network or provider failures never fail the pipeline; the built-in local feed keeps working offline. Source health is on the **System & Audit** page and `GET /api/v1/intel/status`. Verdict thresholds are heuristics (e.g. VirusTotal: 3+ malicious engines = malicious).

## AI quality

**Feedback loop.** Every alert gets a `rule_key` (source + title with IPs, hashes and numbers masked). Each incident you mark False Positive or Escalate counts once toward every pattern it contains. When a pattern has `FEEDBACK_MIN_DECISIONS` decisions at a `FEEDBACK_RATIO` ratio, future incidents made only of dismissed patterns lose `FEEDBACK_FP_PENALTY` points (the verdict drops at most one step), and escalated patterns gain `FEEDBACK_BOOST`. The penalty is withheld when there is malicious threat intel, critical severity, a critical asset or 3+ MITRE tactics, and every adjustment is written into the evidence. Incident detail shows **Similar past incidents**; the System page lists decisions per pattern (`GET /api/v1/feedback/rules`). One mistaken decision on a multi-alert incident votes for every pattern in it, which is why the thresholds exist.

**Evaluation harness.** `cd backend && uv run python -m app.evaluate` runs 30 labelled cases (benign, suspicious, malicious, injection text and deliberately hard ones) through the real pipeline on a throwaway database and prints accuracy, a confusion matrix, dangerous misses (attack called false positive), under-triaged attacks and false alarms. With `LLM_PROVIDER` set to a real provider it also reports LLM vs rule-based agreement, score drift, fallback rate and latency. Add `--json out.json` to save results and `--cases file.json` to use your own labelled set (cases must share a host, user or src_ip). The bundled set is small and written by hand, so treat its numbers as a regression gate for the wiring, not a benchmark; the value comes from adding your own labelled alerts.

**Prompt-injection defences** (tested in `tests/test_quality.py`): alert fields are clipped, stripped of delimiter-like text and fenced by a per-call random nonce; model output is schema-validated; a model that contradicts malicious threat intel is rejected; and any model score more than `LLM_MAX_DEVIATION` points from the rule-based baseline is clamped to that bound (with the baseline verdict) and flagged in the evidence.

## Database migrations (Alembic)

```bash
cd backend
uv run alembic upgrade head                 # fresh database (the API also does this on start)
uv run alembic stamp 0001 && uv run alembic upgrade head   # database created by Phases 1-3
uv run alembic revision --autogenerate -m "describe change"   # after editing app/models.py
```
Set `AUTO_MIGRATE=false` to run migrations yourself.

## Alert deduplication

Alerts with the same source, title, severity and entities (`src_ip`, `dst_ip`, `user`, `host`, `domain`, `file_hash`) within `DEDUP_WINDOW_MINUTES` fold into one row with `dup_count`. The ingest response reports `accepted`, `duplicates` and the distinct alerts. The simulator bypasses dedup.

## Try it

```bash
KEY=<INGEST_API_KEY>
for i in 1 2 3; do curl -s -X POST localhost:8000/api/v1/alerts/ingest \
  -H "X-API-Key: $KEY" -H 'content-type: application/json' \
  -d '{"title":"Port scan","severity":"medium","src_ip":"10.1.1.8","host":"WKSTN-14"}'; done
TOKEN=$(curl -s -X POST localhost:8000/api/v1/auth/login -H 'content-type: application/json' \
  -d '{"username":"admin","password":"<ADMIN_PASSWORD>"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s -X POST localhost:8000/api/v1/simulator/replay -H "Authorization: Bearer $TOKEN"
curl -s localhost:8000/api/v1/incidents -H "Authorization: Bearer $TOKEN"
```

## Tests and CI

```bash
cd backend && uv run pytest -q
```
GitHub Actions (`.github/workflows/ci.yml`) runs pytest and `pip-audit` for the backend, and `npm ci`, build and `npm audit` for the frontend.

## Configuration

See `.env.example`. LLM: `LLM_PROVIDER=mock` (default) | `openai` | `anthropic` with the matching key; `LLM_MODEL` overrides the default. Invalid or failed LLM output falls back to deterministic scoring (`provider=fallback`). Async pipeline: `CELERY_TASK_ALWAYS_EAGER=false` plus `celery -A app.pipeline.celery_app worker`; if Redis is unreachable, ingest processes inline.

The dashboard keeps its login token in `sessionStorage` (cleared when the tab closes). Put the API behind HTTPS before exposing it beyond localhost.
