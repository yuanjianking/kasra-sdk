"""Kasra L3 Rule Engine — Global configuration model.

Uses ``pydantic-settings`` to layer:
  Code defaults → YAML files (default.yaml + override.yaml) → env vars (KASRA_*)

Every section maps to a nested ``BaseModel`` so that users get typed,
validated configuration regardless of source.
"""

from __future__ import annotations

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


# ---------------------------------------------------------------------------
# Nested configuration models — one per YAML section
# ---------------------------------------------------------------------------

class EngineConfig(BaseModel):
    """Settings for the core rule engine."""

    max_concurrent_rules: int = Field(default=20, ge=1, le=200)
    rule_timeout_seconds: float = Field(default=5.0, ge=0.1, le=60.0)
    cache_compiled_patterns: bool = True


class InputPipelineConfig(BaseModel):
    """Settings for the input (pre-request) detection pipeline."""

    enabled: bool = True
    preprocess: bool = True
    default_action: str = "block"


class OutputPipelineConfig(BaseModel):
    """Settings for the streaming output detection pipeline."""

    enabled: bool = True
    stream_buffer_size: int = Field(default=4096, ge=256, le=1_000_000)
    boundary_type: str = "sentence"
    flush_timeout_ms: int = Field(default=500, ge=50, le=30_000)
    retroactive_block_strategy: str = "redact_and_notify"
    retain_full_content: bool = True


class BatchPipelineConfig(BaseModel):
    """Settings for the batch file-scan pipeline."""

    enabled: bool = True
    max_file_size_mb: int = Field(default=10, ge=1, le=500)
    exclude_patterns: list[str] = Field(
        default_factory=lambda: [
            "node_modules/**",
            ".git/**",
            "__pycache__/**",
            "vendor/**",
            "*.min.js",
            "*.pyc",
            "*.egg-info/**",
        ]
    )
    parallel_files: int = Field(default=4, ge=1, le=32)


class BehaviorPipelineConfig(BaseModel):
    """Settings for the session-level behaviour monitoring pipeline."""

    enabled: bool = True
    session_history_ttl_hours: int = Field(default=24, ge=1, le=720)
    baseline_days: int = Field(default=7, ge=1, le=90)
    escalation_window_minutes: int = Field(default=60, ge=5, le=1440)


class PipelineConfig(BaseModel):
    """Aggregate pipeline settings."""

    input: InputPipelineConfig = InputPipelineConfig()
    output: OutputPipelineConfig = OutputPipelineConfig()
    batch: BatchPipelineConfig = BatchPipelineConfig()
    behavior: BehaviorPipelineConfig = BehaviorPipelineConfig()


class AuditConfig(BaseModel):
    """Settings for the audit logging subsystem."""

    enabled: bool = True
    log_to_console: bool = True
    jsonl_path: str = "kasra-audit.jsonl"
    max_queue_size: int = Field(default=10000, ge=100, le=1_000_000)
    batch_write_interval_seconds: float = Field(default=2.0, ge=0.1, le=60.0)


class OverrideConfig(BaseModel):
    """Runtime overrides for rule severity, action, and enabled-state."""

    severity: dict[str, str] = Field(default_factory=dict)
    action: dict[str, str] = Field(default_factory=dict)
    disabled_rules: list[str] = Field(default_factory=list)
    enabled_only_rules: list[str] = Field(default_factory=list)


class PluginConfig(BaseModel):
    """Plugin hook configuration."""

    enabled: bool = False
    paths: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Top-level settings
# ---------------------------------------------------------------------------

class GlobalConfig(BaseSettings):
    """Top-level configuration for the Kasra L3 Rule Engine.

    Load order:
        1. Code-level defaults (these field defaults)
        2. YAML defaults file (``config/default.yaml``)
        3. YAML override file (``config/override.yaml``)
        4. Environment variables prefixed with ``KASRA_``

    Example env vars:
        - ``KASRA_ENGINE_MAX_CONCURRENT_RULES=50``
        - ``KASRA_AUDIT_LOG_TO_CONSOLE=false``
    """

    engine: EngineConfig = EngineConfig()
    pipeline: PipelineConfig = PipelineConfig()
    audit: AuditConfig = AuditConfig()
    overrides: OverrideConfig = OverrideConfig()
    plugins: PluginConfig = PluginConfig()

    model_config = SettingsConfigDict(
        env_prefix="KASRA_",
        env_nested_delimiter="__",
        nested_model_default_partial_update=True,
    )
