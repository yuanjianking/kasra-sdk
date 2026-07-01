"""Plugin hook system for extensibility."""

from kasra.hooks.base import Hook
from kasra.hooks.registry import HookRegistry

__all__ = [
    "Hook",
    "HookRegistry",
]
