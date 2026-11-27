"""Source adapters: normalise vendor alert formats into AlertIn-shaped dicts, plus recorded sample packs."""
import ipaddress
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

PACKS = ("wazuh", "cloudtrail")
_SAMPLES = Path(__file__).parent / "samples"
_NOISE = {"-", "", "::1", "127.0.0.1", "unknown", "none", "null"}


def _d(v: Any) -> dict:
    return v if isinstance(v, dict) else {}


def _s(v: Any, limit: int = 256) -> str | None:
    if v is None or isinstance(v, (dict, list)):
        return None
    text = str(v).strip()
    return None if text.lower() in _NOISE else text[:limit]


def _first(*values: Any) -> str | None:
    return next((s for s in map(_s, values) if s), None)


def _ip(v: Any) -> str | None:
    text = _s(v)
    try:
        return str(ipaddress.ip_address(text)) if text else None
    except ValueError:
        return None


def _time(v: Any) -> str | None:
    if not isinstance(v, str):
        return None
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).isoformat()


def wazuh_to_alert(a: dict) -> dict:
    rule, agent, data = _d(a.get("rule")), _d(a.get("agent")), _d(a.get("data"))
    ev, fim = _d(_d(data.get("win")).get("eventdata")), _d(a.get("syscheck"))
    level = rule.get("level") if isinstance(rule.get("level"), int) else 3
    user = _first(data.get("dstuser"), data.get("srcuser"), ev.get("targetUserName"), ev.get("subjectUserName"))
    title = _s(rule.get("description"), 500) or f"Wazuh rule {_s(rule.get('id')) or 'alert'}"
    detail = _s(a.get("full_log"), 2000) or title
    if fim.get("path"):
        detail = f"{_s(fim.get('event')) or 'changed'}: {_s(fim.get('path'), 500)}. {detail}"[:2000]
    return {
        "source": "wazuh",
        "external_id": _s(a.get("id"), 128),
        "title": title,
        "description": detail,
        "severity": "info" if level <= 3 else "low" if level <= 6 else "medium" if level <= 9 else "high" if level <= 12 else "critical",
        "event_time": _time(a.get("timestamp").replace("+0000", "+00:00") if isinstance(a.get("timestamp"), str) else None),
        "src_ip": _ip(_first(data.get("srcip"), ev.get("ipAddress"), ev.get("sourceIp"))),
        "dst_ip": _ip(_first(data.get("dstip"))),
        "user": None if user and user.endswith("$") else user,
        "host": _s(agent.get("name")),
        "file_hash": _first(fim.get("sha256_after"), fim.get("md5_after")),
        "raw": a,
    }


_CT_TITLES = {
    "StopLogging": ("CloudTrail logging was stopped", "high"),
    "DeleteTrail": ("CloudTrail trail deleted", "high"),
    "CreateAccessKey": ("New IAM access key created", "medium"),
    "AttachUserPolicy": ("IAM policy attached to a user", "high"),
    "PutBucketPolicy": ("S3 bucket policy changed", "medium"),
}


def cloudtrail_to_alert(r: dict) -> dict:
    name = _s(r.get("eventName")) or "UnknownEvent"
    ident, resp = _d(r.get("userIdentity")), _d(r.get("responseElements"))
    err = _s(r.get("errorCode"))
    title, severity = _CT_TITLES.get(name, (name, "low"))
    if name == "ConsoleLogin":
        failed = resp.get("ConsoleLogin") == "Failure" or bool(err)
        title, severity = ("Failed sign-in to AWS console", "medium") if failed else ("AWS console sign-in", "info")
    elif err:
        severity = "medium" if err in ("AccessDenied", "UnauthorizedOperation", "Client.UnauthorizedOperation") else severity
    who = _first(ident.get("userName"), str(ident.get("arn") or "").rsplit("/", 1)[-1], ident.get("principalId"))
    params = _d(r.get("requestParameters"))
    extra = f" Policy: {params['policyArn']}." if params.get("policyArn") else ""
    return {
        "source": "cloudtrail",
        "external_id": _s(r.get("eventID"), 128),
        "title": title,
        "description": f"{name} by {who or 'unknown'} from {_s(r.get('sourceIPAddress')) or 'unknown'} "
                       f"in {_s(r.get('awsRegion')) or 'unknown'}.{extra} {_s(r.get('errorMessage'), 500) or ''}".strip(),
        "severity": severity,
        "event_time": _time(r.get("eventTime")),
        "src_ip": _ip(r.get("sourceIPAddress")),
        "user": who,
        "raw": r,
    }


ADAPTERS = {"wazuh": wazuh_to_alert, "cloudtrail": cloudtrail_to_alert}


def records(source: str, body: Any) -> list[dict]:
    """Accept one record, a list, or a wrapper ({"alerts": [...]} / CloudTrail {"Records": [...]})."""
    if isinstance(body, dict):
        for key in ("alerts", "Records"):
            if isinstance(body.get(key), list):
                body = body[key]
                break
    items = body if isinstance(body, list) else [body]
    return [ADAPTERS[source](i) for i in items if isinstance(i, dict)]


def load_pack(name: str) -> list[dict]:
    """Recorded sample alerts, normalised and re-based so the newest one is two minutes old."""
    alerts = records(name, json.loads((_SAMPLES / f"{name}.json").read_text()))
    stamps = [datetime.fromisoformat(a["event_time"]) for a in alerts if a["event_time"]]
    shift = datetime.now(timezone.utc) - timedelta(minutes=2) - max(stamps)
    for a in alerts:
        if a["event_time"]:
            a["event_time"] = (datetime.fromisoformat(a["event_time"]) + shift).isoformat()
        a["scenario"] = name
    return alerts
