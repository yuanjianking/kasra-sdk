"""Incremental scanning — only re-scan changed files.

Usage::

    from kasra.scanner import CodeReviewScanner
    from kasra.scanner.incremental import IncrementalScanner

    scanner = CodeReviewScanner()
    scanner.load_rules()

    inc = IncrementalScanner(scanner, cache_dir=".kasra-cache")
    result = inc.scan("./src")  # first run: full scan
    result = inc.scan("./src")  # second run: only changed files

Cache format (``.kasra-cache/``)::

    <rel_path>.hash  → hex digest of (mtime_ns + file_size + content_hash)
    <rel_path>.meta  → JSON with file_mtime, file_size, rule_count, timestamp
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from kasra.scanner.models import CodeReviewResult
from kasra.scanner.scanner import CodeReviewScanner


class IncrementalScanner:
    """Wraps ``CodeReviewScanner`` and caches file hashes to skip unchanged files.

    First scan is always full.  Subsequent scans skip files whose content
    hash hasn't changed.
    """

    def __init__(self,
                 scanner: CodeReviewScanner,
                 cache_dir: str | Path = ".kasra-cache") -> None:
        self._scanner = scanner
        self._cache_dir = Path(cache_dir)

    @property
    def scanner(self) -> CodeReviewScanner:
        return self._scanner

    def scan(self, path: str | Path) -> CodeReviewResult:
        """Scan *path*, skipping files with unchanged hashes."""
        scan_path = Path(path)
        result = CodeReviewResult(scan_path=str(scan_path.resolve()))

        if not scan_path.exists():
            result.error = f"Path does not exist: {scan_path}"
            return result

        if not self._scanner.rules:
            result.error = "No rules loaded."
            return result

        import time
        start = time.monotonic()
        if scan_path.is_file():
            self._scanner._scan_file(scan_path, result)
        else:
            self._scan_dir(scan_path, result)
        result.duration_ms = (time.monotonic() - start) * 1000
        return result

    def clear_cache(self) -> int:
        """Delete all cached hashes.  Returns count of files removed."""
        if not self._cache_dir.is_dir():
            return 0
        count = 0
        for f in self._cache_dir.iterdir():
            if f.suffix in (".hash", ".meta"):
                f.unlink()
                count += 1
        return count

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _file_hash(filepath: Path) -> str:
        """Compute a content-based hash for *filepath*."""
        h = hashlib.sha256()
        try:
            mtime = filepath.stat().st_mtime_ns
            h.update(str(mtime).encode())
            size = filepath.stat().st_size
            h.update(str(size).encode())
            with open(filepath, "rb") as f:
                # Read first 64 KB + last 64 KB for a fast fingerprint
                head = f.read(65536)
                h.update(head)
                tail_start = max(0, size - 65536)
                if tail_start > 65536:
                    f.seek(tail_start)
                    tail = f.read(65536)
                    h.update(tail)
        except OSError:
            pass
        return h.hexdigest()[:32]

    def _scan_dir(self, directory: Path, result: CodeReviewResult) -> None:
        """Walk directory and scan files, skipping cached ones.

        Delegates extension/size checks to ``_scan_file`` — the incremental
        scanner only decides whether to *call* ``_scan_file`` or skip.
        """
        from kasra.scanner.scanner import IGNORE_DIRS

        self._cache_dir.mkdir(parents=True, exist_ok=True)

        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]
            dirs.sort()
            files.sort()

            for filename in files:
                filepath = Path(root) / filename
                rel_path = filepath.relative_to(directory)
                cache_key = str(rel_path).replace(os.sep, "_")
                hash_path = self._cache_dir / f"{cache_key}.hash"

                # Compute current hash
                current_hash = self._file_hash(filepath)

                # Skip if cached hash matches
                if hash_path.exists():
                    try:
                        if hash_path.read_text().strip() == current_hash:
                            result.files_skipped += 1
                            continue
                    except OSError:
                        pass

                # Delegate to the real scanner (handles ext/size/binary checks)
                self._scanner._scan_file(filepath, result)

                # Cache the hash
                try:
                    hash_path.write_text(current_hash)
                except OSError:
                    pass

    def _scan_file(self, filepath: Path, result: CodeReviewResult) -> None:
        """Delegate to the inner scanner for one file."""
        # import the scanner's _scan_file logic
        self._scanner._scan_file(filepath, result)
        self._stats["scanned"] += 1
