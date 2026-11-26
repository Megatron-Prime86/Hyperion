import hashlib
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any

import uuid

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import (
    Principal, check_throttle, current_user, ensure_secrets, make_token, record_failure, require_admin, require_api_key,
    seed_users, verify_password,
)
from app.config import settings
from app.db import SessionLocal, get_session, init_db, migrate
from app.models import Alert, AuditLog, Enrichment, Incident, TriageReport, User, aware, utcnow
from app.pipeline import dispatch
from app.schemas import (
    ActionIn, AlertIn, AlertOut, AuditOut, EnrichmentOut, HealthOut, IncidentDetail, IncidentOut, IngestResult, LoginIn, ReplayResult, TokenOut, TriageReportOut,
)
from app.simulator import replay_alerts

MAX_BATCH = 500


@asynccontextmanager
async def lifespan(_app: FastAPI):
    ensure_secrets()
    await (migrate() if settings.auto_migrate else init_db())
    async with SessionLocal() as session:
        await seed_users(session)
    yield


app = FastAPI(title="Hyperion", version="0.4.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip()],
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
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


def _fingerprint(alert: AlertIn) -> str:
    parts = [alert.source, alert.title, alert.severity, alert.src_ip, alert.dst_ip, alert.user, alert.host, alert.domain, alert.file_hash]
    return hashlib.sha256("|".join((p or "").strip().lower() for p in parts).encode()).hexdigest()


def _row(alert: AlertIn) -> Alert:
    when = aware(alert.event_time).astimezone(timezone.utc) if alert.event_time else datetime.now(timezone.utc)
    return Alert(
        fingerprint=_fingerprint(alert),
        last_seen=when,
        external_id=alert.external_id,
        source=alert.source,
        title=alert.title,
        description=alert.description,
        severity=alert.severity,
        status=alert.status or "new",
        event_time=when,
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
        dup_count=row.dup_count,
        last_seen=row.last_seen or row.event_time,
        incident_id=row.incident_id,
        created_at=row.created_at,
    )


async def _store(session: AsyncSession, alerts: list[AlertIn], action: str, actor: str, dedup: bool = True) -> tuple[list[Alert], int]:
    """Persist alerts, folding repeats (same fingerprint within the dedup window) into dup_count."""
    window = timedelta(minutes=settings.dedup_window_minutes)
    rows: dict[uuid.UUID, Alert] = {}
    fresh: list[Alert] = []
    folded = 0
    for alert in alerts:
        row = _row(alert)
        existing = None
        if dedup:
            existing = await session.scalar(
                select(Alert)
                .where(Alert.fingerprint == row.fingerprint, Alert.last_seen >= row.event_time - window,
                       Alert.last_seen <= row.event_time + window)
                .order_by(Alert.last_seen.desc())
                .limit(1)
            )
        if existing:
            existing.dup_count += 1
            existing.last_seen = max(aware(existing.last_seen), row.event_time)
            rows[existing.id] = existing
            folded += 1
        else:
            session.add(row)
            await session.flush()
            rows[row.id] = row
            fresh.append(row)
    session.add(
        AuditLog(
            actor=actor, action=action, target_type="alert", target_id=None,
            note=f"Stored {len(fresh)} new alert(s), folded {folded} duplicate(s)",
            detail={"ids": [str(r.id) for r in fresh]}, created_at=utcnow(),
        )
    )
    await session.commit()
    if fresh:
        await dispatch(session, [r.id for r in fresh])
    for row in rows.values():
        await session.refresh(row)
    return list(rows.values()), folded


@app.get("/api/v1/health", response_model=HealthOut)
async def health() -> HealthOut:
    return HealthOut(
        status="ok",
        database=settings.database_backend,
        llm_mode=settings.llm_mode,
        redis_fallback=settings.celery_task_always_eager or not settings.redis_url,
    )


@app.post("/api/v1/alerts/ingest", response_model=IngestResult)
async def ingest(request: Request, _: None = Depends(require_api_key), session: AsyncSession = Depends(get_session)) -> IngestResult:
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON") from exc
    alerts = _parse(body)
    rows, folded = await _store(session, alerts, action="alert.ingest", actor="api-key")
    return IngestResult(accepted=len(alerts), duplicates=folded, alerts=[_out(row) for row in rows])


@app.post("/api/v1/simulator/replay", response_model=ReplayResult)
async def replay(admin: Principal = Depends(require_admin), session: AsyncSession = Depends(get_session)) -> ReplayResult:
    payloads = replay_alerts()
    alerts = _parse(payloads)
    rows, _ = await _store(session, alerts, action="simulator.replay", actor=admin.username, dedup=False)
    scenarios: dict[str, int] = {}
    for payload in payloads:
        name = str(payload.get("scenario") or "unspecified")
        scenarios[name] = scenarios.get(name, 0) + 1
    return ReplayResult(seeded=len(rows), scenarios=scenarios, alerts=[_out(row) for row in rows])


@app.get("/api/v1/incidents", response_model=list[IncidentOut])
async def list_incidents(
    _: Principal = Depends(current_user),
    status: str | None = None,
    tier: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
) -> list[Incident]:
    query = select(Incident).order_by(Incident.risk_score.desc().nulls_last(), Incident.last_seen.desc()).limit(limit)
    if status:
        query = query.where(Incident.status == status)
    if tier:
        query = query.where(Incident.risk_tier == tier)
    return list(await session.scalars(query))


@app.get("/api/v1/incidents/{incident_id}", response_model=IncidentDetail)
async def incident_detail(
    incident_id: uuid.UUID, _: Principal = Depends(current_user), session: AsyncSession = Depends(get_session)
) -> IncidentDetail:
    incident = await session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    alerts = list(await session.scalars(select(Alert).where(Alert.incident_id == incident_id).order_by(Alert.event_time)))
    enrichments = list(await session.scalars(select(Enrichment).where(Enrichment.alert_id.in_([a.id for a in alerts]))))
    report = await session.scalar(
        select(TriageReport).where(TriageReport.incident_id == incident_id).order_by(TriageReport.created_at.desc()).limit(1)
    )
    return IncidentDetail(
        **IncidentOut.model_validate(incident).model_dump(),
        alerts=[_out(a) for a in alerts],
        enrichments=[EnrichmentOut.model_validate(e) for e in enrichments],
        triage=TriageReportOut.model_validate(report) if report else None,
    )


ACTION_STATUS = {"acknowledge": "acknowledged", "escalate": "escalated", "false_positive": "false_positive", "resolve": "resolved"}


@app.post("/api/v1/incidents/{incident_id}/action", response_model=IncidentOut)
async def incident_action(
    incident_id: uuid.UUID, body: ActionIn, user: Principal = Depends(current_user), session: AsyncSession = Depends(get_session)
) -> Incident:
    incident = await session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    previous, incident.status = incident.status, ACTION_STATUS[body.action]
    incident.updated_at = utcnow()
    session.add(
        AuditLog(
            actor=user.username, action=f"incident.{body.action}", target_type="incident", target_id=str(incident_id),
            note=body.note, detail={"from": previous, "to": incident.status, "risk_score": incident.risk_score},
        )
    )
    await session.commit()
    return incident


@app.get("/api/v1/audit", response_model=list[AuditOut])
async def audit(
    limit: int = Query(50, ge=1, le=500), _: Principal = Depends(current_user), session: AsyncSession = Depends(get_session)
) -> list[AuditLog]:
    return list(await session.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)))


@app.post("/api/v1/auth/login", response_model=TokenOut)
async def login(body: LoginIn, request: Request, session: AsyncSession = Depends(get_session)) -> TokenOut:
    key = f"{request.client.host if request.client else '?'}:{body.username.lower()}"
    check_throttle(key)
    user = await session.scalar(select(User).where(User.username == body.username))
    if not verify_password(body.password, user.password_hash if user else None):
        record_failure(key)
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return TokenOut(access_token=make_token(user.username, user.role), username=user.username, role=user.role)
