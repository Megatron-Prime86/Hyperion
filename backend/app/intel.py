"""Threat intel: local feed (offline fallback + allowlist) plus live providers behind a DB cache,
rate-limit cooldowns and per-source health. A provider failure never fails the pipeline."""
import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import IntelCache, IntelHealth, aware, utcnow

# Local threat-intel feed (simulated indicators; extend or swap for a real feed).
LOCAL_INTEL: dict[str, dict[str, Any]] = {
    "185.220.101.42": {"verdict": "malicious", "tags": ["c2", "exfil-endpoint"]},
    "203.0.113.50": {"verdict": "suspicious", "tags": ["credential-stuffing"]},
    "malicious-update.example": {"verdict": "malicious", "tags": ["phishing", "lookalike-domain"]},
    "update-cdn.example": {"verdict": "malicious", "tags": ["payload-host"]},
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {"verdict": "malicious", "tags": ["loader"]},
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08": {"verdict": "malicious", "tags": ["credential-dumper"]},
    "windowsupdate.com": {"verdict": "benign", "tags": ["allowlist"]},
    "login.microsoftonline.com": {"verdict": "benign", "tags": ["allowlist"]},
}
VERDICT_RANK = {"benign": 0, "suspicious": 1, "malicious": 2}
Fetch = Callable[[httpx.AsyncClient, str, str, str], Awaitable[tuple[str, list[str]]]]


def _verdict(malicious: bool, suspicious: bool) -> str:
    return "malicious" if malicious else "suspicious" if suspicious else "clean"


async def _abuseipdb(c: httpx.AsyncClient, kind: str, ind: str, key: str) -> tuple[str, list[str]]:
    r = await c.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": ind, "maxAgeInDays": 90},
                    headers={"Key": key, "Accept": "application/json"})
    r.raise_for_status()
    score = int(r.json()["data"]["abuseConfidenceScore"])
    return _verdict(score >= 75, score >= 25), [f"abuseipdb:{score}"]


async def _virustotal(c: httpx.AsyncClient, kind: str, ind: str, key: str) -> tuple[str, list[str]]:
    path = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}[kind]
    r = await c.get(f"https://www.virustotal.com/api/v3/{path}/{ind}", headers={"x-apikey": key})
    if r.status_code == 404:
        return "unknown", []
    r.raise_for_status()
    stats = r.json()["data"]["attributes"]["last_analysis_stats"]
    mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
    return _verdict(mal >= 3, mal >= 1 or sus >= 2), [f"virustotal:{mal}/{sum(int(v) for v in stats.values())}"]


async def _otx(c: httpx.AsyncClient, kind: str, ind: str, key: str) -> tuple[str, list[str]]:
    seg = {"ip": "IPv4", "domain": "domain", "hash": "file"}[kind]
    r = await c.get(f"https://otx.alienvault.com/api/v1/indicators/{seg}/{ind}/general", headers={"X-OTX-API-KEY": key})
    if r.status_code == 404:
        return "unknown", []
    r.raise_for_status()
    pulses = int(r.json().get("pulse_info", {}).get("count", 0))
    return _verdict(pulses >= 10, pulses >= 1), [f"otx:pulses={pulses}"]


async def _urlhaus(c: httpx.AsyncClient, kind: str, ind: str, key: str) -> tuple[str, list[str]]:
    r = await c.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": ind}, headers={"Auth-Key": key})
    r.raise_for_status()
    body = r.json()
    if body.get("query_status") == "no_results":
        return "clean", []
    if body.get("query_status") != "ok":
        return "unknown", []
    urls = body.get("urls") or []
    return _verdict(bool(urls), False), [f"urlhaus:urls={len(urls)}"]


@dataclass(frozen=True)
class Provider:
    name: str
    kinds: frozenset[str]
    key: Callable[[], str]
    fetch: Fetch


PROVIDERS = [
    Provider("abuseipdb", frozenset({"ip"}), lambda: settings.abuseipdb_api_key, _abuseipdb),
    Provider("virustotal", frozenset({"ip", "domain", "hash"}), lambda: settings.virustotal_api_key, _virustotal),
    Provider("otx", frozenset({"ip", "domain", "hash"}), lambda: settings.otx_api_key, _otx),
    Provider("urlhaus", frozenset({"ip", "domain"}), lambda: settings.urlhaus_api_key, _urlhaus),
]


def make_client() -> httpx.AsyncClient:  # tests replace this to inject a mock transport
    return httpx.AsyncClient(timeout=settings.intel_timeout_seconds)


def _cooldown_for(exc: Exception) -> timedelta | None:
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        if code == 429:
            retry = exc.response.headers.get("retry-after", "")
            return timedelta(seconds=min(int(retry), 3600) if retry.isdigit() else 60)
        if code in (401, 403):
            return timedelta(minutes=10)  # bad key / quota exhausted: stop hammering
    return None


async def _fetch(client: httpx.AsyncClient, prov: Provider, kind: str, ind: str):
    try:
        verdict, tags = await prov.fetch(client, kind, ind, prov.key())
        return verdict, tags, None
    except Exception as exc:  # network off, timeout, bad JSON, HTTP error: degrade, never raise
        return None, None, exc


async def lookup_intel(session: AsyncSession, iocs: dict[str, list[str]], ip_class: dict[str, Any]) -> dict[str, Any]:
    hits: list[dict[str, Any]] = []
    todo: list[tuple[str, str]] = []
    candidates = ([(i, "ip") for i in iocs["ips"] if ip_class.get(i, {}).get("scope") == "external"]
                  + [(d, "domain") for d in iocs["domains"]] + [(h, "hash") for h in iocs["hashes"]])
    for ind, kind in candidates:
        local = LOCAL_INTEL.get(ind)
        if local:
            hits.append({"indicator": ind, "type": kind, "source": "local-feed", **local})
        else:
            todo.append((ind, kind))
    todo = todo[: settings.intel_max_lookups]
    live = cached = 0
    providers = [p for p in PROVIDERS if p.key()]
    if todo and providers:
        now = utcnow()
        health = {h.source: h for h in await session.scalars(select(IntelHealth))}
        active = [p for p in providers if not (health.get(p.name) and health[p.name].cooldown_until
                                               and aware(health[p.name].cooldown_until) > now)]
        results: dict[tuple[str, str], tuple[str, list[str]]] = {}
        misses: list[tuple[Provider, str, str]] = []
        for ind, kind in todo:
            for prov in active:
                if kind not in prov.kinds:
                    continue
                row = await session.scalar(select(IntelCache).where(IntelCache.source == prov.name, IntelCache.indicator == ind))
                if row and aware(row.expires_at) > now:
                    results[(prov.name, ind)] = (row.verdict, row.tags)
                    cached += 1
                else:
                    misses.append((prov, kind, ind))
        if misses:
            async with make_client() as client:
                fetched = await asyncio.gather(*[_fetch(client, p, k, i) for p, k, i in misses])
            outcome: dict[str, dict[str, Any]] = {}
            for (prov, kind, ind), (verdict, tags, exc) in zip(misses, fetched):
                state = outcome.setdefault(prov.name, {"n": 0, "err": None})
                state["n"] += 1
                if exc is not None:
                    state["err"] = state["err"] or exc
                    continue
                live += 1
                results[(prov.name, ind)] = (verdict, tags)
                row = await session.scalar(select(IntelCache).where(IntelCache.source == prov.name, IntelCache.indicator == ind))
                expires = now + timedelta(hours=settings.intel_cache_hours)
                if row:
                    row.verdict, row.tags, row.fetched_at, row.expires_at = verdict, tags, now, expires
                else:
                    session.add(IntelCache(source=prov.name, indicator=ind, verdict=verdict, tags=tags, fetched_at=now, expires_at=expires))
            for name, state in outcome.items():
                row = health.get(name) or IntelHealth(source=name, lookups=0)
                session.add(row)
                row.lookups = (row.lookups or 0) + state["n"]
                if state["err"] is None:
                    row.ok, row.last_ok_at, row.last_error = True, now, None
                else:
                    exc = state["err"]
                    row.ok, row.last_error_at, row.last_error = False, now, f"{type(exc).__name__}: {exc}"[:300]
                    wait = _cooldown_for(exc)
                    row.cooldown_until = now + wait if wait else row.cooldown_until
            await session.flush()
        for (source, ind), (verdict, tags) in results.items():
            if verdict in ("malicious", "suspicious"):
                kind = next(k for i, k in todo if i == ind)
                hits.append({"indicator": ind, "type": kind, "source": source, "verdict": verdict, "tags": tags})
    worst = max((h["verdict"] for h in hits), key=VERDICT_RANK.get, default="none")
    return {"hits": hits, "worst": worst, "live_lookups": live, "cache_hits": cached}


async def status(session: AsyncSession) -> list[dict[str, Any]]:
    health = {h.source: h for h in await session.scalars(select(IntelHealth))}
    counts = dict((await session.execute(select(IntelCache.source, func.count()).group_by(IntelCache.source))).all())
    out: list[dict[str, Any]] = [{"source": "local-feed", "configured": True, "ok": True, "last_error": None,
                                  "last_ok_at": None, "cooldown_until": None, "lookups": 0, "cache_entries": len(LOCAL_INTEL)}]
    for p in PROVIDERS:
        h = health.get(p.name)
        out.append({"source": p.name, "configured": bool(p.key()), "ok": h.ok if h else True,
                    "last_error": h.last_error if h else None, "last_ok_at": h.last_ok_at if h else None,
                    "cooldown_until": h.cooldown_until if h else None, "lookups": h.lookups if h else 0,
                    "cache_entries": counts.get(p.name, 0)})
    return out
