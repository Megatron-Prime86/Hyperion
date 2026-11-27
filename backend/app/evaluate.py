"""Triage evaluation harness.

    python -m app.evaluate [--cases FILE] [--json OUT]

Runs labelled cases through the real enrichment + correlation + triage code on a throwaway SQLite database
and compares rule-based scoring with the configured LLM (when LLM_PROVIDER is not mock). Live intel providers
are disabled so runs are reproducible; the local feed is used.
"""
import argparse
import asyncio
import json
import tempfile
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import settings
from app.enrichment import enrich
from app.feedback import rule_key
from app.models import Alert, Base, Enrichment
from app.pipeline import correlate, refresh_incident
from app.triage import build_context, deterministic_triage, triage

VERDICTS = ("false_positive", "needs_investigation", "true_positive")
DEFAULT_CASES = Path(__file__).parent / "samples" / "eval_set.json"
_INTEL_KEYS = ("abuseipdb_api_key", "virustotal_api_key", "otx_api_key", "urlhaus_api_key")


async def _run_case(session: AsyncSession, case: dict, use_llm: bool) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    alerts = []
    for raw in case["alerts"]:
        a = dict(raw)
        alerts.append(Alert(
            source=a.get("source", "eval"), title=a["title"], description=a.get("description", ""), severity=a["severity"],
            event_time=now - timedelta(minutes=a.get("minutes_ago", 0)), src_ip=a.get("src_ip"), dst_ip=a.get("dst_ip"),
            user_name=a.get("user"), host=a.get("host"), domain=a.get("domain"), file_hash=a.get("file_hash"), raw={},
            rule_key=rule_key(a.get("source", "eval"), a["title"]),
        ))
    session.add_all(alerts)
    await session.flush()
    for alert in alerts:
        session.add(Enrichment(alert_id=alert.id, **await enrich(alert, session)))
    await session.flush()
    for alert in sorted(alerts, key=lambda x: x.event_time):
        incident = await correlate(session, alert)
    if len({a.incident_id for a in alerts}) != 1:
        raise ValueError(f"case {case['id']}: alerts did not correlate into one incident (share a host, user or src_ip)")
    members = await refresh_incident(session, incident)
    enrichments = {e.alert_id: e for e in await session.scalars(select(Enrichment).where(Enrichment.alert_id.in_([a.id for a in members])))}
    ctx = build_context(incident, members, enrichments)
    det = deterministic_triage(ctx)
    row: dict[str, Any] = {"id": case["id"], "label": case["label"], "note": case.get("note", ""),
                           "det_verdict": det.triage_verdict, "det_score": det.risk_score}
    if use_llm:
        started = time.monotonic()
        result, provider, _ = await triage(ctx)
        row.update(llm_verdict=result.triage_verdict, llm_score=result.risk_score, provider=provider,
                   latency_s=round(time.monotonic() - started, 2))
    await session.commit()
    return row


async def run_cases(cases: list[dict], use_llm: bool | None = None) -> list[dict[str, Any]]:
    use_llm = settings.llm_mode != "mock" if use_llm is None else use_llm
    saved = {k: getattr(settings, k) for k in _INTEL_KEYS}
    for k in saved:
        setattr(settings, k, "")
    try:
        with tempfile.TemporaryDirectory() as tmp:
            engine = create_async_engine(f"sqlite+aiosqlite:///{tmp}/eval.db")
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            async with async_sessionmaker(engine, expire_on_commit=False)() as session:
                rows = [await _run_case(session, case, use_llm) for case in cases]
            await engine.dispose()
    finally:
        for k, v in saved.items():
            setattr(settings, k, v)
    return rows


def _score(rows: list[dict], prefix: str) -> dict[str, Any]:
    cm = {t: {p: 0 for p in VERDICTS} for t in VERDICTS}
    for r in rows:
        cm[r["label"]][r[f"{prefix}_verdict"]] += 1
    n = len(rows) or 1
    return {
        "accuracy": round(sum(cm[v][v] for v in VERDICTS) / n, 3),
        "confusion": cm,  # rows = label, columns = prediction
        "dangerous_misses": cm["true_positive"]["false_positive"],  # real attack called a false positive
        "under_triaged": sum(c for p, c in cm["true_positive"].items() if p != "true_positive"),
        "false_alarms": cm["false_positive"]["true_positive"],  # benign called a true positive
    }


def metrics(rows: list[dict]) -> dict[str, Any]:
    m: dict[str, Any] = {"cases": len(rows), "rule_based": _score(rows, "det")}
    has_llm = bool(rows) and "llm_verdict" in rows[0]
    if has_llm:
        m["llm"] = _score(rows, "llm")
        m["verdict_agreement"] = round(sum(r["det_verdict"] == r["llm_verdict"] for r in rows) / len(rows), 3)
        m["mean_abs_score_diff"] = round(sum(abs(r["det_score"] - r["llm_score"]) for r in rows) / len(rows), 1)
        m["fallback_rate"] = round(sum(r["provider"] == "fallback" for r in rows) / len(rows), 3)
        m["mean_latency_s"] = round(sum(r["latency_s"] for r in rows) / len(rows), 2)
        m["provider"] = Counter(r["provider"] for r in rows).most_common(1)[0][0]
    m["misses"] = [r for r in rows if r["det_verdict"] != r["label"] or (has_llm and r["llm_verdict"] != r["label"])]
    return m


def format_report(m: dict[str, Any]) -> str:
    out = [f"Hyperion triage evaluation: {m['cases']} labelled cases", ""]
    names = [("rule_based", "Rule-based")] + ([("llm", f"LLM ({m['provider']})")] if "llm" in m else [])
    out.append(f"{'':<22}" + "".join(f"{n:>18}" for _, n in names))
    for key, title in (("accuracy", "Accuracy"), ("dangerous_misses", "Dangerous misses"), ("under_triaged", "Under-triaged attacks"), ("false_alarms", "False alarms")):
        out.append(f"{title:<22}" + "".join(f"{m[k][key]:>18}" for k, _ in names))
    if "llm" in m:
        out += ["", f"Verdict agreement (LLM vs rules): {m['verdict_agreement']:.0%}   Mean |score diff|: {m['mean_abs_score_diff']}",
                f"Fallback rate: {m['fallback_rate']:.0%}   Mean latency: {m['mean_latency_s']}s/case"]
    out += ["", "Confusion (rows = label, columns = rule-based prediction FP / NI / TP):"]
    for label, cols in m["rule_based"]["confusion"].items():
        out.append(f"  {label:<20}" + "  ".join(f"{cols[v]:>3}" for v in VERDICTS))
    if m["misses"]:
        out += ["", "Misses:"]
        for r in m["misses"]:
            llm = f"  llm={r['llm_verdict']}({r['llm_score']})" if "llm_verdict" in r else ""
            out.append(f"  {r['id']}  label={r['label']}  rules={r['det_verdict']}({r['det_score']}){llm}  {r['note']}")
    return "\n".join(out)


async def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate Hyperion triage against labelled cases")
    parser.add_argument("--cases", default=str(DEFAULT_CASES))
    parser.add_argument("--json", dest="json_out")
    args = parser.parse_args()
    rows = await run_cases(json.loads(Path(args.cases).read_text()))
    result = metrics(rows)
    print(format_report(result))
    if args.json_out:
        Path(args.json_out).write_text(json.dumps({"metrics": result, "rows": rows}, indent=1))


if __name__ == "__main__":
    asyncio.run(main())
