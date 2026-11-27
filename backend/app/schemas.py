import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Severity = Literal["info", "low", "medium", "high", "critical"]
RiskTier = Literal["low", "medium", "high", "critical"]
Verdict = Literal["false_positive", "needs_investigation", "true_positive"]


def tier_for(score: int) -> str:
    return "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 25 else "low"


class AlertIn(BaseModel):
    model_config = ConfigDict(extra="allow")

    external_id: str | None = Field(default=None, max_length=128)
    source: str = Field(default="unknown", max_length=64)
    title: str = Field(min_length=1, max_length=512)
    description: str = ""
    severity: Severity = "medium"
    status: str = Field(default="new", max_length=32)
    event_time: datetime | None = None
    src_ip: str | None = Field(default=None, max_length=64)
    dst_ip: str | None = Field(default=None, max_length=64)
    user: str | None = Field(default=None, max_length=256)
    host: str | None = Field(default=None, max_length=256)
    domain: str | None = Field(default=None, max_length=256)
    file_hash: str | None = Field(default=None, max_length=128)
    raw: dict[str, Any] = Field(default_factory=dict)


class AlertOut(BaseModel):
    id: uuid.UUID
    external_id: str | None
    source: str
    title: str
    description: str
    severity: str
    status: str
    event_time: datetime
    src_ip: str | None
    dst_ip: str | None
    user: str | None
    host: str | None
    domain: str | None
    file_hash: str | None
    dup_count: int = 1
    last_seen: datetime | None = None
    incident_id: uuid.UUID | None
    created_at: datetime


class IngestResult(BaseModel):
    accepted: int
    duplicates: int = 0
    alerts: list[AlertOut]


class ReplayResult(BaseModel):
    seeded: int
    scenarios: dict[str, int]
    alerts: list[AlertOut]


class HealthOut(BaseModel):
    status: Literal["ok"]
    database: str
    llm_mode: str
    redis_fallback: bool


class TriageResult(BaseModel):
    """Validated triage output (LLM or deterministic)."""

    model_config = ConfigDict(extra="ignore")

    risk_score: int = Field(ge=0, le=100)
    risk_tier: RiskTier
    triage_verdict: Verdict
    executive_summary: str = Field(min_length=1, max_length=2000)
    evidence_highlights: list[str] = Field(max_length=12)
    recommended_next_steps: list[str] = Field(min_length=1, max_length=12)

    @field_validator("evidence_highlights", "recommended_next_steps")
    @classmethod
    def _short_strings(cls, items: list[str]) -> list[str]:
        if any(not isinstance(i, str) or not i.strip() or len(i) > 500 for i in items):
            raise ValueError("items must be non-empty strings up to 500 chars")
        return items

    @model_validator(mode="after")
    def _tier_matches_score(self):
        self.risk_tier = tier_for(self.risk_score)  # score is authoritative
        return self


class TriageReportOut(TriageResult):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    incident_id: uuid.UUID
    provider: str
    model: str | None
    created_at: datetime


class EnrichmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    alert_id: uuid.UUID
    iocs: dict[str, Any]
    ip_classification: dict[str, Any]
    threat_intel: dict[str, Any]
    asset_criticality: dict[str, Any]
    mitre: dict[str, Any]


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    title: str
    status: str
    severity: str
    risk_score: int | None
    risk_tier: str | None
    entity_type: str | None
    entity_value: str | None
    alert_count: int
    summary: str | None
    first_seen: datetime
    last_seen: datetime


class SimilarIncident(BaseModel):
    id: uuid.UUID
    title: str
    status: str
    risk_score: int | None
    similarity: float
    last_seen: datetime


class IncidentDetail(IncidentOut):
    similar: list[SimilarIncident] = []
    alerts: list[AlertOut]
    enrichments: list[EnrichmentOut]
    triage: TriageReportOut | None


class ActionIn(BaseModel):
    action: Literal["acknowledge", "escalate", "false_positive", "resolve"]
    note: str | None = Field(default=None, max_length=2000)


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    actor: str
    action: str
    target_type: str
    target_id: str | None
    note: str | None
    detail: dict[str, Any]
    created_at: datetime


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class TokenOut(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    username: str
    role: Literal["analyst", "admin"]
