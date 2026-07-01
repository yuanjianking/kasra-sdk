"""Kasra L3 Rule Engine — Audit event models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from kasra.models.enums import ActionType, Severity, Stage
from kasra.utils.time import utcnow


class AuditEvent(BaseModel):
    """An audit event record for the compliance log."""

    event_id: str = Field(default="", description="Unique event identifier")
    timestamp: datetime = Field(default_factory=utcnow, description="Event timestamp")
    stage: Stage = Field(default=Stage.INPUT, description="Pipeline stage that generated this event")
    rule_id: str = Field(default="", description="Rule ID that triggered")
    rule_name: str = Field(default="", description="Rule name")
    severity: Severity = Field(default=Severity.P2, description="Effective severity")
    action: ActionType = Field(default=ActionType.WARN, description="Action taken")
    user_id: str | None = Field(default=None, description="User identifier")
    session_id: str | None = Field(default=None, description="Session identifier")
    request_id: str | None = Field(default=None, description="Request identifier")
    source: str = Field(default="api", description="Request source")
    content_snippet: str | None = Field(default=None, description="Snippet of matched content (max 200 chars)")
    content_length: int = Field(default=0, description="Length of original content")
    match_count: int = Field(default=0, ge=0, description="Number of matches")
    matched_spans: list[dict[str, Any]] = Field(default_factory=list, description="Matched span positions")
    action_taken: str = Field(default="warn", description="The action that was actually executed")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional audit metadata")
    gdpr_relevant: bool = Field(default=False, description="Whether this event is GDPR-relevant")
