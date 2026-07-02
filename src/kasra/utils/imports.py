"""Kasra L3 Rule Engine — Import utilities.

Helpers for deferred / lazy imports and optional-dependency guards.
"""

from __future__ import annotations

import importlib
from types import ModuleType
from typing import Any


def lazy_import(module_path: str, attr: str | None = None) -> Any:
    """Defer importing *attr* from *module_path* until the result is called.

    When *attr* is ``None`` the module itself is returned.

    Usage::

        ActionType = lazy_import("kasra.models.enums", "ActionType")

        # … later …
        self._registry.register(ActionType.BLOCK, BlockAction())
    """
    return _LazyModule(module_path, attr)


class _LazyModule:
    """Proxy that imports the real module on first attribute access."""

    def __init__(self, module_path: str, attr: str | None) -> None:
        self._module_path = module_path
        self._attr = attr
        self._resolved: ModuleType | None = None

    def _resolve(self) -> ModuleType:
        if self._resolved is None:
            self._resolved = importlib.import_module(self._module_path)
        return self._resolved

    def __getattr__(self, name: str) -> Any:
        resolved = self._resolve()
        if self._attr is not None:
            # First resolve the named attribute from the module,
            # then chain the requested name onto it.
            obj = getattr(resolved, self._attr)
            return getattr(obj, name)
        return getattr(resolved, name)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        # When used as ``LazyImport("mod", "func")()``
        if self._attr is not None:
            return getattr(self._resolve(), self._attr)(*args, **kwargs)
        return self._resolve(*args, **kwargs)


def optional_import(
    module_path: str,
    attr: str | None = None,
    fallback: Any = None,
    package_name: str | None = None,
) -> Any:
    """Import *attr* from *module_path*, returning *fallback* if not installed.

    Usage::

        semgrep = optional_import("semgrep", fallback=None)
        if semgrep is None:
            # semgrep not installed — fall back to regex
    """
    try:
        mod = importlib.import_module(module_path, package=package_name)
        return getattr(mod, attr) if attr else mod
    except ImportError:
        return fallback
