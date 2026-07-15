#!/usr/bin/env python3
"""Kasra Rule Engine — ``python -m kasra`` entry point.

The CLI was removed in v0.4. Use the Kasra API for rule management
and scanning, or install ``kasra-mcp`` for local file scanning.
"""

from __future__ import annotations

import sys


def main() -> None:
    print("Kasra Rule Engine v0.4+")
    print("  CLI removed — use the Kasra API (REST) or `kasra-mcp` for local scanning.")
    print("  See: https://kasra.security/docs")
    sys.exit(0)


if __name__ == "__main__":
    main()
