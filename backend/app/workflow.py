"""Analyst workflow: SLA timers, response playbooks (dry-run by default), Markdown export."""
import ipaddress
from datetime import datetime, timedelta
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.enrichment import ASSET_RULES, classify_ip
from app.models import Alert, AuditLog, Enrichment, Incident, PlaybookRun, aware, utcnow

DEFAULT_TIER = "medium"


# ---------------- SLA ----------------
def _targets(spec: str) -> dict[str, int]:
    out = {}
    for part in spec.split(","):
        tier, _, minutes = part.partition("=")
        if minutes.strip().isdigit():
            out[tier.strip()] = int(minutes)
    return out


def _state(due: datetime, window: timedelta, done_at: datetime | None, now: datetime) -> str:
    if done_at:
        return "met" if aware(done_at) <= due else "missed"
    if now > due:
        return "overdue"
    return "due_soon" if due - now <= window * 0.2 else "ok"


def sla(tier: str | None, created_at: datetime, acknowledged_at: datetime | None, resolved_at: datetime | None,
        now: datetime | None = None) -> dict[str, Any]:
    now, tier = now or utcnow(), tier or DEFAULT_TIER
    ack = timedelta(minutes=_targets(settings.sla_ack_minutes).get(tier, 240))
    res = timedelta(minutes=_targets(settings.sla_resolve_minutes).get(tier, 1440))
    start = aware(created_at)
    return {"ack_due": start + ack, "ack_state": _state(start + ack, ack, acknowledged_at, now),
            "resolve_due": start + res, "resolve_state": _state(start + res, res, resolved_at, now)}


# ---------------- playbooks ----------------
PLAYBOOKS: dict[str, dict[str, str]] = {
    "block_ip": {"label": "Block IP", "kind": "ips", "would": "Would add {t} to the perimeter deny list (inbound and outbound).",
                 "impact": "Traffic to and from this address is dropped. Reversible by removing the rule."},
    "disable_user": {"label": "Disable user", "kind": "users", "would": "Would disable the account '{t}' and revoke its sessions and tokens.",
                     "impact": "The user cannot sign in until re-enabled. Reversible."},
    "isolate_host": {"label": "Isolate host", "kind": "hosts", "would": "Would network-isolate '{t}' through the EDR (management channel stays open).",
                     "impact": "The host loses network access except to the EDR. Reversible."},
}


class PlaybookError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code, self.detail = status_code, detail


def make_client() -> httpx.AsyncClient:  # tests replace this to inject a mock transport
    return httpx.AsyncClient(timeout=10)


def entities(alerts: list[Alert], enrichments: list[Enrichment]) -> dict[str, list[str]]:
    ips = [a.src_ip for a in alerts] + [a.dst_ip for a in alerts] + [i for e in enrichments for i in e.iocs.get("ips", [])]
    return {"ips": list(dict.fromkeys(i for i in ips if i)),
            "users": list(dict.fromkeys(a.user_name for a in alerts if a.user_name)),
            "hosts": list(dict.fromkeys(a.host for a in alerts if a.host))}


def blocked_reason(playbook: str, target: str) -> str | None:
    if playbook == "block_ip":
        scope = classify_ip(target)["scope"]
        return None if scope == "external" else f"Refusing to block a {scope} address"
    if playbook == "disable_user":
        protected = {u.strip().lower() for u in settings.playbook_protected_users.split(",")}
        return "Protected account: disable manually after approval" if target.lower() in protected else None
    if playbook == "isolate_host":
        critical = any(rx.match(target) and level == "critical" for rx, level, _ in ASSET_RULES)
        return "Critical asset (e.g. domain controller): isolate manually after approval" if critical else None
    return "Unknown playbook"


def suggestions(alerts: list[Alert], enrichments: list[Enrichment]) -> list[dict[str, Any]]:
    ents = entities(alerts, enrichments)
    bad = {h["indicator"]: h for e in enrichments for h in e.threat_intel.get("hits", []) if h["verdict"] != "benign"}
    out = []
    for name, spec in PLAYBOOKS.items():
        for target in ents[spec["kind"]][:6]:
            why = blocked_reason(name, target)
            hit = bad.get(target)
            out.append({"playbook": name, "label": spec["label"], "target": target, "allowed": why is None, "blocked_reason": why,
                        "reason": f"Threat intel: {hit['verdict']} ({', '.join(hit['tags'])})" if hit else f"Seen in this incident"})
    return sorted(out, key=lambda s: (not s["allowed"], not s["reason"].startswith("Threat"), s["playbook"]))[:12]


async def run_playbook(session: AsyncSession, incident: Incident, alerts: list[Alert], enrichments: list[Enrichment],
                       playbook: str, target: str, dry_run: bool, actor: str) -> PlaybookRun:
    spec = PLAYBOOKS.get(playbook)
    if spec is None:
        raise PlaybookError(404, "Unknown playbook")
    if target not in entities(alerts, enrichments)[spec["kind"]]:
        raise PlaybookError(422, "Target is not an entity of this incident")
    reason = blocked_reason(playbook, target)
    if reason:
        status, result = "blocked", {"reason": reason}
    elif dry_run:
        status, result = "dry_run", {"would": spec["would"].format(t=target), "impact": spec["impact"]}
    elif not settings.playbook_enable_execution:
        status, result = "blocked", {"reason": "Execution is disabled (PLAYBOOK_ENABLE_EXECUTION=false); nothing was run."}
    elif not settings.playbook_webhook_url:
        status, result = "executed", {"simulated": True, "note": "No PLAYBOOK_WEBHOOK_URL configured; no system was changed."}
    else:
        try:
            async with make_client() as client:
                resp = await client.post(settings.playbook_webhook_url, json={
                    "playbook": playbook, "target": target, "incident_id": str(incident.id), "actor": actor})
            resp.raise_for_status()
            status, result = "executed", {"webhook_status": resp.status_code}
        except Exception as exc:  # recorded, never raised: a failed response action must be visible, not fatal
            status, result = "failed", {"error": f"{type(exc).__name__}: {exc}"[:300]}
    run = PlaybookRun(incident_id=incident.id, playbook=playbook, target=target, dry_run=dry_run, status=status, result=result, actor=actor)
    session.add(run)
    session.add(AuditLog(actor=actor, action=f"playbook.{playbook}.{status}", target_type="incident", target_id=str(incident.id),
                         note=f"{target}{' (dry run)' if dry_run else ''}", detail={"target": target, "dry_run": dry_run, "result": result}))
    incident.updated_at = utcnow()
    await session.commit()
    await session.refresh(run)
    return run


# ---------------- export ----------------
def incident_markdown(d, audit) -> str:
    """Render an IncidentDetail (API model) plus its audit entries as a Markdown report."""
    incident, alerts, enrichments, triage, comments, runs, s = d, d.alerts, d.enrichments, d.triage, d.comments, d.playbook_runs, d.sla
    esc = lambda v: str(v if v is not None else "").replace("|", "\\|").replace("\n", " ")
    lines = [f"# {incident.title}", "",
             f"- **Status:** {incident.status}  |  **Risk:** {incident.risk_score}/100 ({incident.risk_tier})  |  **Assignee:** {incident.assignee or 'unassigned'}",
             f"- **Entity:** {incident.entity_type}={incident.entity_value}  |  **Alerts:** {incident.alert_count}",
             f"- **First seen:** {aware(incident.first_seen):%Y-%m-%d %H:%M:%S} UTC  |  **Last seen:** {aware(incident.last_seen):%Y-%m-%d %H:%M:%S} UTC",
             f"- **SLA:** acknowledge {s['ack_state']} (due {s['ack_due']:%H:%M}), resolve {s['resolve_state']} (due {s['resolve_due']:%Y-%m-%d %H:%M})", ""]
    if triage:
        lines += ["## AI triage", f"*{triage.triage_verdict}, provider: {triage.provider}*", "", triage.executive_summary, "", "**Evidence**"]
        lines += [f"- {e}" for e in triage.evidence_highlights] + ["", "**Recommended next steps**"]
        lines += [f"{i}. {x}" for i, x in enumerate(triage.recommended_next_steps, 1)] + [""]
    tech = {t["id"]: t for e in enrichments for t in e.mitre.get("techniques", [])}
    if tech:
        lines += ["## MITRE ATT&CK", *[f"- {t['id']} {t['name']} ({t['tactic']})" for t in tech.values()], ""]
    lines += ["## Alert timeline", "", "| Time (UTC) | Severity | Source | Alert | Entities |", "|---|---|---|---|---|"]
    for a in sorted(alerts, key=lambda x: aware(x.event_time)):
        ents = ", ".join(f"{k}={v}" for k, v in (("user", a.user), ("host", a.host), ("src", a.src_ip), ("dst", a.dst_ip)) if v)
        lines.append(f"| {aware(a.event_time):%H:%M:%S} | {a.severity} | {esc(a.source)} | {esc(a.title)}{f' (x{a.dup_count})' if a.dup_count > 1 else ''} | {esc(ents)} |")
    if comments:
        lines += ["", "## Analyst notes", *[f"- **{c.author}** ({aware(c.created_at):%Y-%m-%d %H:%M} UTC): {esc(c.body)}" for c in comments]]
    if runs:
        lines += ["", "## Response actions", *[f"- {aware(r.created_at):%H:%M} {r.playbook} on `{r.target}`: **{r.status}** by {r.actor}" for r in runs]]
    if audit:
        lines += ["", "## Audit trail", *[f"- {aware(a.created_at):%Y-%m-%d %H:%M:%S} {a.actor}: {a.action}{f' ({esc(a.note)})' if a.note else ''}" for a in audit]]
    return "\n".join(lines) + "\n"
