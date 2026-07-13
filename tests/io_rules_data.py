"""
Test data: I/O rules loaded from the production database.
Contains 111 rules (I + O series).
"""
from __future__ import annotations

import json
from pathlib import Path
from kasra.models.rule import RuleDefinition

_JSON_PATH = Path(__file__).resolve().parent / "io_rules_data.json"


def load_io_rules() -> list[RuleDefinition]:
    """Return I/O detection rules as RuleDefinition objects."""
    if not _JSON_PATH.exists():
        return []
    data = json.loads(_JSON_PATH.read_bytes())
    return [RuleDefinition.model_validate(d) for d in data]
