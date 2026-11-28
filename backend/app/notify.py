"""Critical-incident notifications: Slack incoming webhook and SMTP email. Failures are recorded, never raised."""
import asyncio
import smtplib
from email.message import EmailMessage
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import AuditLog, Incident, utcnow

TIER_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def make_client() -> httpx.AsyncClient:  # tests replace this to inject a mock transport
    return httpx.AsyncClient(timeout=10)


def configured() -> dict[str, bool]:
    return {"slack": bool(settings.slack_webhook_url), "email": bool(settings.smtp_host and settings.notify_email_to)}


def _slack_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def message(incident: Incident) -> tuple[str, str]:
    subject = " ".join(f"[Hyperion] {incident.risk_tier or 'new'} incident: {incident.title}".split())[:200]  # no CR/LF in headers
    body = (f"{incident.title}\nRisk {incident.risk_score}/100 ({incident.risk_tier}), {incident.alert_count} alert(s), "
            f"entity {incident.entity_type}={incident.entity_value}\n\n{incident.summary or ''}\n\n"
            f"{settings.dashboard_url.rstrip('/')}/incidents/{incident.id}")
    return subject, body


async def _slack(subject: str, body: str) -> None:
    async with make_client() as client:
        resp = await client.post(settings.slack_webhook_url, json={"text": _slack_escape(f"*{subject}*\n{body}")})
    resp.raise_for_status()


def _send_email(subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, settings.smtp_from, ", ".join(t.strip() for t in settings.notify_email_to.split(",") if t.strip())
    msg.set_content(body)
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
        if settings.smtp_starttls:
            smtp.starttls()
        if settings.smtp_user:
            smtp.login(settings.smtp_user, settings.smtp_password)
        smtp.send_message(msg)


async def notify_all(subject: str, body: str) -> dict[str, str]:
    results: dict[str, str] = {}
    for channel, enabled in configured().items():
        if not enabled:
            continue
        try:
            await (_slack(subject, body) if channel == "slack" else asyncio.to_thread(_send_email, subject, body))
            results[channel] = "sent"
        except Exception as exc:
            results[channel] = f"failed: {type(exc).__name__}"
    return results


async def maybe_notify(session: AsyncSession, incident: Incident) -> dict[str, Any] | None:
    """Notify once per incident when it first reaches NOTIFY_MIN_TIER."""
    if incident.notified_at or not incident.risk_tier or not any(configured().values()):
        return None
    if TIER_RANK.get(incident.risk_tier, 0) < TIER_RANK.get(settings.notify_min_tier, 3):
        return None
    results = await notify_all(*message(incident))
    if "sent" in results.values():
        incident.notified_at = utcnow()
    session.add(AuditLog(actor="system", action="notify.incident", target_type="incident", target_id=str(incident.id),
                         note=f"{incident.risk_tier} incident", detail=results))
    return results
