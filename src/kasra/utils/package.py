"""Kasra L3 Rule Engine — Package data / resource resolution.

Provides a single reliable way to locate data directories
(``rules``, ``config``) whether the package is running from
source or installed via ``pip``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Literal

_DATA_DIR_PREFIX = "_"  # we ship config/ → kasra/_config/ in the wheel

_DATA_DIRS: dict[str, list[str]] = {
    # Order: installed-package subdir (via force-include) first,
    # then dev-tree sibling (relative to __file__).
    "config": ["_config"],
}


def _package_root() -> Path | None:
    """Return the ``kasra`` package directory, or ``None``."""
    try:
        # Python ≥ 3.9
        import importlib.resources

        return importlib.resources.files("kasra")  # type: ignore[arg-type]
    except (ImportError, ModuleNotFoundError, TypeError, Exception):
        pass

    # Fallback (zip-safety, etc.)
    try:
        return Path(__file__).resolve().parent.parent
    except NameError:
        return None


def find_data_dir(name: Literal["config"]) -> Path:
    """Locate a Kasra data directory (*name* is ``"config"``).

    Resolution order:
      1. Environment variable ``KASRA_{name.upper()}_DIR``.
      2. ``importlib.resources.files("kasra") / "_{name}"`` (installed wheel).
      3. ``<package_root>/../{name}`` (dev tree).
      4. ``<cwd>/{name}`` (working directory).

    Returns the first match; if none exist, returns the dev-tree path
    (the caller will raise a clear error).

    .. note::
       The ``"rules"`` data directory was removed in v0.4 — the engine
       no longer reads rules from disk. Rules are loaded from the database.
    """
    name_upper = name.upper()

    # 1. env var
    env_key = f"KASRA_{name_upper}_DIR"
    env_val = os.environ.get(env_key)
    if env_val:
        env_path = Path(env_val)
        if env_path.is_dir():
            return env_path.resolve()

    # 2. importlib.resources (installed wheel)
    pkg_root = _package_root()
    if pkg_root is not None:
        for subpath in _DATA_DIRS[name]:
            candidate = pkg_root / subpath
            try:
                if candidate.is_dir():
                    return candidate.resolve()
            except (OSError, TypeError):
                pass

    # 3. Dev tree (<package_root>/../../<name>)
    if pkg_root is not None:
        dev = pkg_root.parent.parent / name
        try:
            if dev.is_dir():
                return dev.resolve()
        except OSError:
            pass

    # 4. CWD
    cwd = Path.cwd() / name
    if cwd.is_dir():
        return cwd.resolve()

    # Last resort — let the caller fail with a clear message
    return (pkg_root or Path.cwd()).parent / name
