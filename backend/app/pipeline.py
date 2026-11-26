"""Enrichment -> correlation -> triage pipeline, run inline or via Celery (auto-fallback to inline)."""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone

from celery import Celery
from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.config import settings
from app.enrichment import enrich
from app.models import Alert, AuditLog, Enrichment, Incident, TriageReport, aware, utcnow
from app.triage import SEV_RANK, build_context, triage

CLOSED = ("resolved", "false_positive")

celery_app = Celery("hyperion", broker=settings.redis_url, backend=None)
celery_app.conf.update(
    task_always_eager=settings.celery_task_always_eager,
    broker_connection_timeout=1,
    broker_transport_options={"socket_connect_timeout": 1, "max_retries": 1},
)


async def correlate(session: AsyncSession, alert: Alert) -> Incident:
    """Join an open incident sharing src_ip/user/host within the time window, else open a new one."""
    window = timedelta(minutes=settings.correlation_window_minutes)
    t = aware(alert.event_time)
    keys = [(alert.src_ip, Alert.src_ip), (alert.user_name, Alert.user_name), (alert.host, Alert.host)]
    shared = [col == val for val, col in keys if val]
    matches: list[Incident] = []
    if shared:
        rows = await session.scalars(
            select(Incident).where(
                Incident.status.notin_(CLOSED),
                Incident.id.in_(select(Alert.incident_id).where(Alert.incident_id.is_not(None), or_(*shared))),
            ).order_by(Incident.first_seen)
        )
        matches = [i for i in rows if aware(i.first_seen) - window <= t <= aware(i.last_seen) + window]
    if not matches:
        etype, evalue = next(((n, v) for n, (v, _) in zip(("src_ip", "user", "host"), keys) if v), (None, None))
        incident = Incident(title=alert.title[:500], severity=alert.severity, entity_type=etype,
                            entity_value=evalue, alert_count=0, first_seen=t, last_seen=t)
        session.add(incident)
        await session.flush()
        matches = [incident]
    primary, *others = matches
    for other in others:  # alert bridges two incidents: merge them into the earliest
        await session.execute(Alert.__table__.update().where(Alert.incident_id == other.id).values(incident_id=primary.id))
        await session.execute(delete(TriageReport).where(TriageReport.incident_id == other.id))
        await session.delete(other)
    alert.incident_id = primary.id
    await session.flush()
    return primary


async def refresh_incident(session: AsyncSession, incident: Incident) -> list[Alert]:
    alerts = list(await session.scalars(select(Alert).where(Alert.incident_id == incident.id)))
    top = max(alerts, key=lambda a: (SEV_RANK[a.severity], aware(a.event_time)))
    incident.alert_count = len(alerts)
    incident.severity = top.severity
    incident.first_seen = min(aware(a.event_time) for a in alerts)
    incident.last_seen = max(aware(a.event_time) for a in alerts)
    incident.title = top.title[:480] + (f" (+{len(alerts) - 1} related)" if len(alerts) > 1 else "")
    return alerts


async def process_alerts(session: AsyncSession, alert_ids: list[uuid.UUID]) -> list[uuid.UUID]:
    alerts = list(await session.scalars(select(Alert).where(Alert.id.in_(alert_ids))))
    alerts.sort(key=lambda a: aware(a.event_time))
    for alert in alerts:  # 1. enrich
        if not await session.scalar(select(Enrichment.id).where(Enrichment.alert_id == alert.id)):
            session.add(Enrichment(alert_id=alert.id, **await enrich(alert)))
    await session.flush()
    touched: dict[uuid.UUID, Incident] = {}
    for alert in alerts:  # 2. correlate
        incident = await correlate(session, alert)
        touched[incident.id] = incident
    live = {i.id for i in await session.scalars(select(Incident).where(Incident.id.in_(touched)))}
    done: list[uuid.UUID] = []
    for iid in live:  # 3. triage each touched incident once
        incident = touched[iid]
        members = await refresh_incident(session, incident)
        enrichments = {e.alert_id: e for e in await session.scalars(
            select(Enrichment).where(Enrichment.alert_id.in_([a.id for a in members])))}
        result, provider, model = await triage(build_context(incident, members, enrichments))
        session.add(TriageReport(incident_id=iid, provider=provider, model=model, **result.model_dump()))
        incident.risk_score, incident.risk_tier, incident.summary = result.risk_score, result.risk_tier, result.executive_summary
        incident.updated_at = utcnow()
        done.append(iid)
    session.add(AuditLog(actor="system", action="pipeline.run", target_type="incident", note=f"Processed {len(alerts)} alert(s)",
                         detail={"incident_ids": [str(i) for i in done], "alert_ids": [str(a.id) for a in alerts]}))
    await session.commit()
    return done


@celery_app.task(name="hyperion.process_alerts")
def process_alerts_task(alert_ids: list[str]) -> None:
    async def run() -> None:
        engine = create_async_engine(settings.database_url, poolclass=NullPool)
        try:
            async with async_sessionmaker(engine, expire_on_commit=False)() as session:
                await process_alerts(session, [uuid.UUID(i) for i in alert_ids])
        finally:
            await engine.dispose()

    asyncio.run(run())


async def dispatch(session: AsyncSession, alert_ids: list[uuid.UUID]) -> bool:
    """Queue via Celery when Redis is available, else run inline. Returns True if processed inline."""
    if not (settings.celery_task_always_eager or not settings.redis_url):
        try:
            process_alerts_task.apply_async(args=[[str(i) for i in alert_ids]], retry=False)
            return False
        except Exception:
            pass  # broker unreachable -> sync fallback
    await process_alerts(session, alert_ids)
    return True
