"""Live updates over server-sent events. Streams are driven by database changes, so events raised by a
Celery worker reach every connected dashboard without extra infrastructure."""
import asyncio
import json
from collections.abc import AsyncIterator
from datetime import datetime, timedelta

from fastapi import Request
from sqlalchemy import select

from app.db import SessionLocal
from app.models import Incident, aware, utcnow

POLL_SECONDS, PING_SECONDS = 2.0, 15.0


def sse(data: dict | None = None, event: str = "message") -> str:
    return f": ping\n\n" if data is None else f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


async def changes_since(since: datetime) -> list[dict]:
    async with SessionLocal() as session:
        rows = await session.scalars(select(Incident).where(Incident.updated_at > since).order_by(Incident.updated_at).limit(100))
        return [{"type": "incident_changed", "id": str(i.id), "title": i.title, "status": i.status, "risk_score": i.risk_score,
                 "risk_tier": i.risk_tier, "assignee": i.assignee, "new": aware(i.created_at) > since,
                 "updated_at": aware(i.updated_at).isoformat()} for i in rows]


async def stream(request: Request, since: datetime, once: bool = False) -> AsyncIterator[str]:
    yield sse({"type": "ready", "since": since.isoformat()}, "ready")
    last_ping = asyncio.get_event_loop().time()
    while True:
        batch = await changes_since(since)
        for event in batch:
            yield sse(event, "incident")
            since = max(since, datetime.fromisoformat(event["updated_at"]))
        if once or await request.is_disconnected():
            return
        now = asyncio.get_event_loop().time()
        if not batch and now - last_ping >= PING_SECONDS:
            last_ping = now
            yield sse()
        await asyncio.sleep(POLL_SECONDS)
