"""Action executors for detection results."""

from kasra.actions.base import ActionExecutor, ActionResult, ActionRegistry
from kasra.actions.block import BlockAction
from kasra.actions.warn import WarnAction
from kasra.actions.redact import RedactAction
from kasra.actions.clean import CleanAction
from kasra.actions.truncate import TruncateAction
from kasra.actions.soft_allow import SoftAllowAction
from kasra.actions.dynamic import DynamicAction

__all__ = [
    "ActionExecutor",
    "ActionResult",
    "ActionRegistry",
    "BlockAction",
    "WarnAction",
    "RedactAction",
    "CleanAction",
    "TruncateAction",
    "SoftAllowAction",
    "DynamicAction",
]
