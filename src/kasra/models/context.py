"""Kasra L3 Rule Engine — Context models for requests, sessions, and files."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from kasra.utils.time import utcnow


class RequestContext(BaseModel):
    """Context for a single request being evaluated."""

    request_id: str = Field(default="", description="Unique request identifier")
    content: str = Field(default="", description="Original content being evaluated")
    content_length: int = Field(default=0, ge=0, description="Length of original content")
    source: str = Field(default="api", description="Request source: api, cli, mcp, webhook")
    user_id: str | None = Field(default=None, description="Authenticated user identifier")
    ip_address: str | None = Field(default=None, description="Client IP address")
    user_agent: str | None = Field(default=None, description="Client user agent string")
    headers: dict[str, str] = Field(default_factory=dict, description="Request headers")
    suspicion_score: int = Field(default=0, ge=0, description="Runtime suspicion score for this request")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional request metadata")
    timestamp: datetime = Field(default_factory=utcnow, description="Request timestamp")


class SessionContext(BaseModel):
    """Session-level context for multi-turn conversation monitoring."""

    session_id: str = Field(default="", description="Unique session identifier")
    user_id: str | None = Field(default=None, description="Authenticated user identifier")
    history_count: int = Field(default=0, description="Number of messages in session history")
    is_polluted: bool = Field(default=False, description="Whether session has been flagged as polluted")
    suspicion_score: int = Field(default=0, ge=0, description="Cumulative suspicion score for split attack detection")
    previous_results: list[str] = Field(default_factory=list, description="Rule IDs that triggered in this session")
    created_at: datetime = Field(default_factory=utcnow, description="Session creation time")
    last_activity: datetime = Field(default_factory=utcnow, description="Last activity time")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional session metadata")


class FileContext(BaseModel):
    """Context for a file being scanned (batch pipeline)."""

    file_path: str = Field(..., description="Absolute or relative file path")
    file_size: int = Field(default=0, ge=0, description="File size in bytes")
    mime_type: str | None = Field(default=None, description="Detected MIME type")
    encoding: str | None = Field(default=None, description="Detected character encoding")
    language: str | None = Field(default=None, description="Detected programming language (if code file)")
    content: str = Field(default="", description="File content as string")
    is_binary: bool = Field(default=False, description="Whether the file is binary")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional file metadata")
