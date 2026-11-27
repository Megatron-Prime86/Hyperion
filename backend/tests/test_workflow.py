"""Phase 7: assignment, comments, SLA, playbooks, export, live events, notifications."""
import json
from contextlib import asynccontextmanager
from datetime import timedelta

import httpx
import pytest

from app import notify, workflow
from app.config import settings
from app.main import app
from app.models import utcnow
from test_pipeline import _alert, client  # noqa: F401  (shared fixture: admin session + API key)


async def _incident(client, **kw):
    res = (await client.post("/api/v1/alerts/ingest", json=_alert(**kw))).json()["alerts"][0]
    return res["incident_id"]


async def _detail(client, iid):
    return (await client.get(f"/api/v1/incidents/{iid}")).json()


@asynccontextmanager
async def _analyst():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        token = (await c.post("/api/v1/auth/login", json={"username": "analyst", "password": "analyst-pass"})).json()["access_token"]
        c.headers.update({"Authorization": f"Bearer {token}", "X-API-Key": "test-key"})
        yield c


# ---------------- assignment, comments ----------------
async def test_assign_users_and_unassign(client):
    iid = await _incident(client, user="asg")
    assert {u["username"] for u in (await client.get("/api/v1/users")).json()} == {"admin", "analyst"}
    assert (await client.post(f"/api/v1/incidents/{iid}/assign", json={"assignee": "ghost"})).status_code == 422
    out = (await client.post(f"/api/v1/incidents/{iid}/assign", json={"assignee": "analyst"})).json()
    assert out["assignee"] == "analyst" and out["acknowledged_at"] and out["sla"]["ack_state"] == "met"
    assert (await client.post(f"/api/v1/incidents/{iid}/assign", json={"assignee": None})).json()["assignee"] is None
    log = [a for a in (await client.get("/api/v1/audit")).json() if a["action"] == "incident.assign"]
    assert len(log) == 2 and log[0]["note"] == "analyst -> unassigned"


async def test_comments(client):
    iid = await _incident(client, user="cmt")
    assert (await client.post(f"/api/v1/incidents/{iid}/comments", json={"body": ""})).status_code == 422
    c = (await client.post(f"/api/v1/incidents/{iid}/comments", json={"body": "  Called the user, confirmed phishing.  "})).json()
    assert c["author"] == "admin" and c["body"] == "Called the user, confirmed phishing."
    assert [x["body"] for x in (await _detail(client, iid))["comments"]] == [c["body"]]
    assert (await client.post(f"/api/v1/incidents/{utcnow().timestamp():.0f}/comments", json={"body": "x"})).status_code == 422


# ---------------- SLA ----------------
def test_sla_states(monkeypatch):
    now = utcnow()
    monkeypatch.setattr(settings, "sla_ack_minutes", "critical=15,high=60")
    monkeypatch.setattr(settings, "sla_resolve_minutes", "critical=240")
    at = lambda mins_ago, **kw: workflow.sla("critical", now - timedelta(minutes=mins_ago), kw.get("ack"), kw.get("res"), now)
    assert at(5)["ack_state"] == "ok" and at(13)["ack_state"] == "due_soon" and at(20)["ack_state"] == "overdue"
    created = now - timedelta(minutes=30)
    assert workflow.sla("critical", created, created + timedelta(minutes=10), None, now)["ack_state"] == "met"
    assert workflow.sla("critical", created, created + timedelta(minutes=20), None, now)["ack_state"] == "missed"
    assert workflow.sla("critical", created, None, now, now)["resolve_state"] == "met"
    assert workflow.sla(None, created, None, None, now)["ack_state"] == "ok"  # untriaged uses medium targets (240m)
    assert workflow.sla("zzz", created, None, None, now)["resolve_state"] == "ok"  # unknown tier falls back to defaults


async def test_actions_stamp_sla(client):
    iid = await _incident(client, user="sla")
    d = await _detail(client, iid)
    assert d["sla"]["ack_state"] in ("ok", "due_soon") and d["resolved_at"] is None
    await client.post(f"/api/v1/incidents/{iid}/action", json={"action": "resolve"})
    d = await _detail(client, iid)
    assert d["acknowledged_at"] and d["resolved_at"] and d["sla"]["resolve_state"] == "met"


# ---------------- playbooks ----------------
HOT = dict(title="Beacon", src_ip="185.220.101.42", dst_ip="10.0.0.5", user="j.doe", host="DC-01")


async def test_playbook_suggestions_and_dry_run(client):
    iid = await _incident(client, **HOT)
    by = {(s["playbook"], s["target"]): s for s in (await _detail(client, iid))["playbooks"]}
    assert by[("block_ip", "185.220.101.42")]["allowed"] and by[("block_ip", "185.220.101.42")]["reason"].startswith("Threat intel")
    assert "internal" in by[("block_ip", "10.0.0.5")]["blocked_reason"]
    assert "critical" in by[("isolate_host", "DC-01")]["blocked_reason"].lower()
    assert by[("disable_user", "j.doe")]["allowed"]
    run = (await client.post(f"/api/v1/incidents/{iid}/playbooks/block_ip", json={"target": "185.220.101.42"})).json()
    assert run["status"] == "dry_run" and run["dry_run"] and "185.220.101.42" in run["result"]["would"]
    blocked = (await client.post(f"/api/v1/incidents/{iid}/playbooks/isolate_host", json={"target": "DC-01"})).json()
    assert blocked["status"] == "blocked"
    assert (await client.post(f"/api/v1/incidents/{iid}/playbooks/block_ip", json={"target": "8.8.8.8"})).status_code == 422
    assert (await client.post(f"/api/v1/incidents/{iid}/playbooks/format_disk", json={"target": "x"})).status_code == 404
    d = await _detail(client, iid)
    assert [r["status"] for r in d["playbook_runs"]] == ["blocked", "dry_run"]
    actions = [a["action"] for a in (await client.get("/api/v1/audit")).json()]
    assert "playbook.block_ip.dry_run" in actions and "playbook.isolate_host.blocked" in actions


async def test_playbook_execution_is_gated(client, monkeypatch):
    iid = await _incident(client, **HOT)
    body = {"target": "185.220.101.42", "dry_run": False}
    async with _analyst() as analyst:
        assert (await analyst.post(f"/api/v1/incidents/{iid}/playbooks/block_ip", json=body)).status_code == 403
        assert (await analyst.post(f"/api/v1/incidents/{iid}/playbooks/block_ip", json={"target": body["target"]})).status_code == 200
    off = (await client.post(f"/api/v1/incidents/{iid}/playbooks/block_ip", json=body)).json()
    assert off["status"] == "blocked" and "disabled" in off["result"]["reason"]
    monkeypatch.setattr(settings, "playbook_enable_execution", True)
    sim = (await client.post(f"/api/v1/incidents/{iid}/playbooks/block_ip", json=body)).json()
    assert sim["status"] == "executed" and sim["result"]["simulated"] is True
    calls = []

    def handler(request):
        calls.append(json.loads(request.content))
        return httpx.Response(200)

    monkeypatch.setattr(settings, "playbook_webhook_url", "https://soar.example/hook")
    monkeypatch.setattr(workflow, "make_client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    live = (await client.post(f"/api/v1/incidents/{iid}/playbooks/block_ip", json=body)).json()
    assert live["status"] == "executed" and calls[0]["playbook"] == "block_ip" and calls[0]["target"] == "185.220.101.42"
    monkeypatch.setattr(workflow, "make_client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(500))))
    bad = (await client.post(f"/api/v1/incidents/{iid}/playbooks/block_ip", json=body)).json()
    assert bad["status"] == "failed" and "HTTPStatusError" in bad["result"]["error"]


# ---------------- export ----------------
async def test_markdown_export(client):
    iid = await _incident(client, title="Odd|pipe\nnewline", user="exp", host="WKSTN-1", src_ip="185.220.101.42")
    await client.post(f"/api/v1/incidents/{iid}/comments", json={"body": "Confirmed with owner"})
    await client.post(f"/api/v1/incidents/{iid}/playbooks/block_ip", json={"target": "185.220.101.42"})
    r = await client.get(f"/api/v1/incidents/{iid}/export")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/markdown")
    assert "attachment" in r.headers["content-disposition"] and iid[:8] in r.headers["content-disposition"]
    for part in ("## AI triage", "## Alert timeline", "Odd\\|pipe newline", "Confirmed with owner", "block_ip", "## Audit trail", "SLA"):
        assert part in r.text, part


# ---------------- live events ----------------
async def test_event_stream(client):
    since = (utcnow() - timedelta(minutes=1)).isoformat()
    iid = await _incident(client, user="live", title="Live one")
    r = await client.get("/api/v1/events", params={"since": since, "once": "true"})
    assert r.headers["content-type"].startswith("text/event-stream")
    assert "event: ready" in r.text and "event: incident" in r.text and iid in r.text
    data = json.loads([ln for ln in r.text.splitlines() if ln.startswith("data: ") and iid in ln][0][6:])
    assert data["type"] == "incident_changed" and data["new"] is True and data["title"].startswith("Live one")
    anon = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")
    async with anon:
        assert (await anon.get("/api/v1/events", params={"once": "true"})).status_code == 401


# ---------------- notifications ----------------
class FakeSMTP:
    sent: list = []

    def __init__(self, host, port, timeout=None):
        self.host = host

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self):
        pass

    def login(self, user, password):
        pass

    def send_message(self, msg):
        FakeSMTP.sent.append(msg)


async def test_notifications_slack_and_email(client, monkeypatch):
    posts = []
    status = {"code": 200}

    def handler(request):
        posts.append(json.loads(request.content))
        return httpx.Response(status["code"])

    FakeSMTP.sent.clear()
    monkeypatch.setattr(settings, "slack_webhook_url", "https://hooks.slack.test/x")
    monkeypatch.setattr(settings, "smtp_host", "smtp.test")
    monkeypatch.setattr(settings, "notify_email_to", "soc@example.com, lead@example.com")
    monkeypatch.setattr(notify, "make_client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    hostile = "Malware <b>&</b>\r\nBcc: evil@example.com"
    crit = dict(title=hostile, severity="critical", host="WKSTN-9", file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    iid = await _incident(client, **crit)
    assert len(posts) == 1 and "&lt;b&gt;&amp;&lt;/b&gt;" in posts[0]["text"] and f"/incidents/{iid}" in posts[0]["text"]
    assert len(FakeSMTP.sent) == 1 and "\n" not in FakeSMTP.sent[0]["Subject"] and FakeSMTP.sent[0]["Bcc"] is None
    assert FakeSMTP.sent[0]["To"] == "soc@example.com, lead@example.com"
    await _incident(client, title="Follow-up on same host", severity="high", host="WKSTN-9")
    assert len(posts) == 1 and len(FakeSMTP.sent) == 1  # notified once per incident
    await _incident(client, title="Medium thing", host="WKSTN-quiet")
    assert len(posts) == 1  # below NOTIFY_MIN_TIER
    entry = next(a for a in (await client.get("/api/v1/audit")).json() if a["action"] == "notify.incident")
    assert entry["detail"] == {"slack": "sent", "email": "sent"}
    # a failing channel never breaks ingestion and leaves the incident eligible for a retry
    status["code"] = 500
    res = await client.post("/api/v1/alerts/ingest", json=_alert(title="Beacon", severity="critical", host="WKSTN-10", dst_ip="185.220.101.42"))
    assert res.status_code == 200 and res.json()["alerts"][0]["incident_id"]
    failed = next(a for a in (await client.get("/api/v1/audit")).json() if a["action"] == "notify.incident")
    assert failed["detail"]["slack"] == "failed: HTTPStatusError" and failed["detail"]["email"] == "sent"


async def test_notification_test_endpoint_is_admin_only(client, monkeypatch):
    assert (await client.post("/api/v1/notifications/test")).json() == {"configured": {"slack": False, "email": False}, "results": {}}
    async with _analyst() as analyst:
        assert (await analyst.post("/api/v1/notifications/test")).status_code == 403
