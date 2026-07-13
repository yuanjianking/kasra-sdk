"""Rule storage — the engine no longer reads rules from disk.

Use ``RuleEngine.load_rules_from_list()`` to inject rules.
``RuleLoader`` was removed in v0.4.
"""

from kasra.rules.store import RuleStore

__all__ = [
    "RuleStore",
]
