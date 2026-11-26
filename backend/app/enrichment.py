"""IOC extraction, IP classification, local threat intel (+optional AbuseIPDB), asset criticality, MITRE mapping."""
import ipaddress
import json
import re
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.intel import lookup_intel
from app.models import Alert

IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
HASH = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
FILE_EXT = {"exe", "dll", "ps1", "sys", "txt", "log", "bat", "cmd", "zip", "json", "py", "js", "tmp", "dat", "lnk"}
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]

# (host/user regex, level, reason)
ASSET_RULES = [
    (re.compile(r"^(dc|pdc|ad)[-_]?\d*", re.I), "critical", "Domain controller"),
    (re.compile(r"^(db|sql|erp|fin)[-_]?\d*", re.I), "high", "Data / business-critical server"),
    (re.compile(r"^(vpn|fw|gw|bk|bkp|backup)[-_]?", re.I), "high", "Infrastructure / backup system"),
    (re.compile(r"^(wkstn|ws|lt|laptop)[-_]?\d*", re.I), "low", "Standard workstation"),
]
PRIVILEGED_USER = re.compile(r"^(svc|sa|adm|admin)[_.-]", re.I)
LEVEL_SCORE = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# (regex over title+description, technique id, name, tactic)
MITRE_RULES = [
    (r"phish|lookalike", "T1566.002", "Phishing: Spearphishing Link", "Initial Access"),
    (r"repeated failed|failed (password|sign-?in)|brute|password spray", "T1110", "Brute Force", "Credential Access"),
    (r"authentication succeeded|authenticated to the vpn", "T1078", "Valid Accounts", "Initial Access"),
    (r"mfa device|authenticator was registered", "T1098.005", "Account Manipulation: Device Registration", "Persistence"),
    (r"powershell", "T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution"),
    (r"download cradle|fetched a payload", "T1105", "Ingress Tool Transfer", "Command and Control"),
    (r"lsass|credential dump", "T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access"),
    (r"lateral|smb", "T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
    (r"archive|staged", "T1560", "Archive Collected Data", "Collection"),
    (r"uploaded to an external|exfil|posted .* to ", "T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    (r"access key", "T1098.001", "Account Manipulation: Additional Cloud Credentials", "Persistence"),
    (r"logging was stopped|trail deleted|disable.*logging", "T1562.008", "Impair Defenses: Disable Cloud Logs", "Defense Evasion"),
    (r"sudo|privilege escalation", "T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "Privilege Escalation"),
]
_MITRE = [(re.compile(p, re.I), *rest) for p, *rest in MITRE_RULES]


def _uniq(items) -> list[str]:
    return list(dict.fromkeys(i for i in items if i))


def extract_iocs(alert: Alert) -> dict[str, list[str]]:
    text = " ".join([alert.title or "", alert.description or "", json.dumps(alert.raw or {}, default=str)[:4000]])
    domains = [d.lower() for d in DOMAIN.findall(text) if d.rsplit(".", 1)[-1].lower() not in FILE_EXT]
    return {
        "ips": _uniq([alert.src_ip, alert.dst_ip, *IPV4.findall(text)]),
        "domains": _uniq([(alert.domain or "").lower(), *domains]),
        "hashes": _uniq([(alert.file_hash or "").lower(), *[h.lower() for h in HASH.findall(text)]]),
        "users": _uniq([alert.user_name]),
        "hosts": _uniq([alert.host]),
    }


def classify_ip(value: str) -> dict[str, Any]:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return {"scope": "invalid"}
    if any(ip in net for net in DOC_NETS):
        scope = "external"  # documentation ranges stand in for public addresses in the simulator
    elif ip.is_loopback:
        scope = "loopback"
    elif ip.is_private or ip.is_link_local:
        scope = "internal"
    elif ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        scope = "reserved"
    else:
        scope = "external"
    return {"scope": scope, "version": ip.version}


def asset_criticality(iocs: dict[str, list[str]]) -> dict[str, Any]:
    assets: list[dict[str, str]] = []
    for host in iocs["hosts"]:
        rule = next(((lvl, why) for rx, lvl, why in ASSET_RULES if rx.match(host)), ("medium", "Unclassified asset"))
        assets.append({"type": "host", "name": host, "level": rule[0], "reason": rule[1]})
    for user in iocs["users"]:
        priv = bool(PRIVILEGED_USER.match(user))
        assets.append({"type": "user", "name": user, "level": "high" if priv else "low",
                       "reason": "Service / privileged account" if priv else "Standard user"})
    top = max((a["level"] for a in assets), key=LEVEL_SCORE.get, default="low")
    return {"assets": assets, "max_level": top, "max_score": LEVEL_SCORE[top]}


def _rule_mitre(alert: Alert) -> list[dict[str, str]]:
    """Techniques the source already tagged (Wazuh rule.mitre); raw is untrusted, so validate shapes."""
    rule = alert.raw.get("rule") if isinstance(alert.raw, dict) else None
    mitre = rule.get("mitre") if isinstance(rule, dict) else None
    if not isinstance(mitre, dict):
        return []
    lists = {k: [str(x)[:100] for x in mitre.get(k, []) if isinstance(x, (str, int))] if isinstance(mitre.get(k), list) else []
             for k in ("id", "technique", "tactic")}
    return [{"id": tid, "name": (lists["technique"] + [tid] * 99)[n], "tactic": (lists["tactic"] + ["Unknown"] * 99)[n]}
            for n, tid in enumerate(lists["id"][:10])]


def map_mitre(alert: Alert) -> dict[str, Any]:
    text = f"{alert.title} {alert.description}"
    techniques = [{"id": i, "name": n, "tactic": t} for rx, i, n, t in _MITRE if rx.search(text)]
    known = {t["id"] for t in techniques}
    techniques += [t for t in _rule_mitre(alert) if t["id"] not in known]
    return {"techniques": techniques, "tactics": _uniq(t["tactic"] for t in techniques)}


async def enrich(alert: Alert, session: AsyncSession) -> dict[str, Any]:
    iocs = extract_iocs(alert)
    ip_class = {ip: classify_ip(ip) for ip in iocs["ips"]}
    return {
        "iocs": iocs,
        "ip_classification": ip_class,
        "threat_intel": await lookup_intel(session, iocs, ip_class),
        "asset_criticality": asset_criticality(iocs),
        "mitre": map_mitre(alert),
    }
