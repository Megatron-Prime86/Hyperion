"""Analyst feedback loop: rule keys, per-rule decision stats, similar past incidents."""
import hashlib
import re
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import Alert, Incident, aware

DECIDED = ("false_positive", "escalated", "resolved")
_IP, _HEX, _NUM = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), re.compile(r"\b[0-9a-f]{32,64}\b"), re.compile(r"\d+")


def rule_key(source: str | None, title: str | None) -> str:
    """Stable id for an alert pattern: same source + title with IPs, hashes and numbers masked."""
    text = _NUM.sub("#", _HEX.sub("<hash>", _IP.sub("<ip>", (title or "").lower())))
    return hashlib.blake2b(f"{(source or '').lower()}|{' '.join(text.split())}".encode(), digest_size=8).hexdigest()


def _verdict(s: dict[str, Any]) -> str | None:
    fp, esc = s["false_positive"], s["escalated"]
    if fp >= settings.feedback_min_decisions and fp / (fp + esc) >= settings.feedback_ratio:
        return "likely_false_positive"
    if esc >= settings.feedback_min_decisions and esc / (fp + esc) >= settings.feedback_ratio:
        return "likely_true_positive"
    return None


async def rule_stats(session: AsyncSession, keys: set[str] | None = None) -> dict[str, dict[str, Any]]:
    """How analysts decided incidents containing each rule (each incident counted once per rule)."""
    query = (
        select(Alert.rule_key, Incident.status, func.count(func.distinct(Incident.id)), func.min(Alert.title))
        .join(Incident, Alert.incident_id == Incident.id)
        .where(Alert.rule_key.is_not(None), Incident.status.in_(DECIDED))
        .group_by(Alert.rule_key, Incident.status)
    )
    if keys is not None:
        query = query.where(Alert.rule_key.in_(list(keys)))
    stats: dict[str, dict[str, Any]] = {}
    for key, status, count, title in (await session.execute(query)).all():
        s = stats.setdefault(key, {"rule_key": key, "title": title, "false_positive": 0, "escalated": 0, "resolved": 0})
        s[status], s["title"] = count, min(s["title"], title)
    for s in stats.values():
        s["verdict"] = _verdict(s)
    return stats


async def similar_incidents(session: AsyncSession, incident: Incident, limit: int = 5) -> list[dict[str, Any]]:
    """Past decided incidents whose alert patterns overlap this one (Jaccard on rule keys)."""
    mine = set(await session.scalars(select(Alert.rule_key).where(Alert.incident_id == incident.id, Alert.rule_key.is_not(None))))
    if not mine:
        return []
    pairs = (await session.execute(
        select(Alert.incident_id, Alert.rule_key).join(Incident, Alert.incident_id == Incident.id)
        .where(Incident.id != incident.id, Incident.status.in_(DECIDED), Alert.rule_key.is_not(None)
               , Incident.id.in_(select(Alert.incident_id).where(Alert.rule_key.in_(mine))))
    )).all()
    keys: dict[Any, set[str]] = {}
    for iid, key in pairs:
        keys.setdefault(iid, set()).add(key)
    scored = sorted(((len(mine & k) / len(mine | k), iid) for iid, k in keys.items()), key=lambda x: -x[0])[:limit]
    found = {i.id: i for i in await session.scalars(select(Incident).where(Incident.id.in_([iid for _, iid in scored])))}
    return [
        {"id": iid, "title": found[iid].title, "status": found[iid].status, "risk_score": found[iid].risk_score,
         "similarity": round(sim, 2), "last_seen": aware(found[iid].last_seen)}
        for sim, iid in scored if iid in found and sim >= 0.3
    ]
