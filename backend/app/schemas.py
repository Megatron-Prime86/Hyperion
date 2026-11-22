import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["info", "low", "medium", "high", "critical"]


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
    incident_id: uuid.UUID | None
    created_at: datetime


class IngestResult(BaseModel):
    accepted: int
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
