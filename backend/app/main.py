from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db import get_session, init_db
from app.models import Alert, AuditLog, utcnow
from app.schemas import AlertIn, AlertOut, HealthOut, IngestResult, ReplayResult
from app.simulator import replay_alerts

MAX_BATCH = 500


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await init_db()
    yield


app = FastAPI(title="Hyperion", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _payloads(body: Any) -> list[Any]:
    if isinstance(body, list):
        return body
    if isinstance(body, dict) and isinstance(body.get("alerts"), list):
        return body["alerts"]
    if isinstance(body, dict):
        return [body]
    raise HTTPException(status_code=422, detail="Body must be an alert, a list, or {\"alerts\": [...]}")


def _parse(body: Any) -> list[AlertIn]:
    payloads = _payloads(body)
    if len(payloads) > MAX_BATCH:
        raise HTTPException(status_code=413, detail=f"Batch limit is {MAX_BATCH} alerts")
    alerts: list[AlertIn] = []
    errors: list[dict[str, Any]] = []
    for index, item in enumerate(payloads):
        try:
            alerts.append(AlertIn.model_validate(item))
        except ValidationError as exc:
            errors.append({"index": index, "errors": exc.errors()})
    if errors:
        raise HTTPException(status_code=422, detail=errors)
    return alerts


def _raw_of(alert: AlertIn) -> dict[str, Any]:
    extra = dict(alert.model_extra or {})
    extra.pop("alerts", None)
    merged = {**extra, **alert.raw}
    return merged


def _row(alert: AlertIn) -> Alert:
    return Alert(
        external_id=alert.external_id,
        source=alert.source,
        title=alert.title,
        description=alert.description,
        severity=alert.severity,
        status=alert.status or "new",
        event_time=alert.event_time or datetime.now(timezone.utc),
        src_ip=alert.src_ip,
        dst_ip=alert.dst_ip,
        user_name=alert.user,
        host=alert.host,
        domain=alert.domain,
        file_hash=alert.file_hash,
        raw=_raw_of(alert),
    )


def _out(row: Alert) -> AlertOut:
    return AlertOut(
        id=row.id,
        external_id=row.external_id,
        source=row.source,
        title=row.title,
        description=row.description,
        severity=row.severity,
        status=row.status,
        event_time=row.event_time,
        src_ip=row.src_ip,
        dst_ip=row.dst_ip,
        user=row.user_name,
        host=row.host,
        domain=row.domain,
        file_hash=row.file_hash,
        incident_id=row.incident_id,
        created_at=row.created_at,
    )


async def _store(session: AsyncSession, alerts: list[AlertIn], action: str, actor: str) -> list[Alert]:
    rows = [_row(alert) for alert in alerts]
    session.add_all(rows)
    await session.flush()
    session.add(
        AuditLog(
            actor=actor,
            action=action,
            target_type="alert",
            target_id=None,
            note=f"Stored {len(rows)} alert(s)",
            detail={"ids": [str(row.id) for row in rows]},
            created_at=utcnow(),
        )
    )
    await session.commit()
    for row in rows:
        await session.refresh(row)
    return rows


@app.get("/api/v1/health", response_model=HealthOut)
async def health() -> HealthOut:
    return HealthOut(
        status="ok",
        database=settings.database_backend,
        llm_mode=settings.llm_mode,
        redis_fallback=settings.celery_task_always_eager or not settings.redis_url,
    )


@app.post("/api/v1/alerts/ingest", response_model=IngestResult)
async def ingest(request: Request, session: AsyncSession = Depends(get_session)) -> IngestResult:
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON") from exc
    alerts = _parse(body)
    rows = await _store(session, alerts, action="alert.ingest", actor="ingest")
    return IngestResult(accepted=len(rows), alerts=[_out(row) for row in rows])


@app.post("/api/v1/simulator/replay", response_model=ReplayResult)
async def replay(session: AsyncSession = Depends(get_session)) -> ReplayResult:
    payloads = replay_alerts()
    alerts = _parse(payloads)
    rows = await _store(session, alerts, action="simulator.replay", actor="simulator")
    scenarios: dict[str, int] = {}
    for payload in payloads:
        name = str(payload.get("scenario") or "unspecified")
        scenarios[name] = scenarios.get(name, 0) + 1
    return ReplayResult(seeded=len(rows), scenarios=scenarios, alerts=[_out(row) for row in rows])
