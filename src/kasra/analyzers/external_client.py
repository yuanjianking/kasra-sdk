"""Kasra L3 Rule Engine — External lookup clients.

Provides embedded/local lookup for CVE data, domain reputation,
and package registry verification.

All clients follow the same pattern:
  - Lookup returns a list of ``ExternalLookupResult``.
  - Returns empty list on any error (never throws).
  - Embedded data is a static JSON file loaded at first use.

v1 implements:
  - CVE lookup via embedded ``cve-data.json`` (shipped with package).
  - Domain reputation via embedded whitelist (O-35).
  - Package registry verification via embedded known-packages list.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from kasra.analyzers.context import ExternalLookupResult


# ---------------------------------------------------------------------------
# CVE Lookup
# ---------------------------------------------------------------------------

class CveLookupClient:
    """Embedded CVE lookup against local ``cve-data.json``.

    The data file is shipped with the package under ``rules/cve-data.json``
    and loaded on first access.  Version comparison is best-effort string
    comparison (supports semver up to 3 segments).
    """

    def __init__(self, data_path: str | os.PathLike | None = None) -> None:
        self._data_path = data_path
        self._entries: list[dict[str, Any]] | None = None

    def lookup(self, package_name: str, version: str | None = None) -> list[ExternalLookupResult]:
        """Look up CVE entries for *package_name*.

        If *version* is provided, only entries whose vulnerable range
        includes that version are returned.

        Returns:
            A list of ``ExternalLookupResult`` (empty if none found).
        """
        entries = self._load()
        results: list[ExternalLookupResult] = []

        for entry in entries:
            if entry["package"].lower() != package_name.lower():
                # Also match partial names (e.g. "log4j" matches in "log4j-core")
                if package_name.lower() not in entry["package"].lower() and entry["package"].lower() not in package_name.lower():
                    continue

            if version and not self._version_in_range(version, entry.get("vulnerable", "<0.0.0")):
                continue

            results.append(ExternalLookupResult(
                source="cve",
                query=f"{package_name}@{version}" if version else package_name,
                found=True,
                data={
                    "cve_id": entry.get("cve", ""),
                    "severity": entry.get("severity", "UNKNOWN"),
                    "description": entry.get("description", ""),
                    "fixed_version": entry.get("fixed", ""),
                    "ecosystem": entry.get("ecosystem", ""),
                },
            ))

        return results

    def list_all(self) -> list[dict[str, Any]]:
        """Return all CVE entries (for diagnostics)."""
        return list(self._load())

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _load(self) -> list[dict[str, Any]]:
        if self._entries is not None:
            return self._entries
        try:
            if self._data_path:
                path = Path(self._data_path)
                if path.exists():
                    raw = path.read_bytes()
                    data = json.loads(raw)
                    self._entries = data.get("entries", [])
                else:
                    self._entries = []
            else:
                # CVE data file removed in v0.4 — feature disabled
                self._entries = []
        except Exception:
            self._entries = []
        return self._entries or []

    @staticmethod
    def _version_in_range(version: str, range_spec: str) -> bool:
        """Check if *version* falls within a vulnerable range spec.

        Range spec examples: ``<2.17.0``, ``<2.6.7,<3.1.1``.
        Supports ``<``, ``<=``, ``=`` operators on up-to-3-segment versions.
        """
        if not range_spec:
            return True

        conditions = [c.strip() for c in range_spec.split(",")]
        ver = CveLookupClient._parse_version(version)
        if ver is None:
            return True  # Can't parse → assume vulnerable

        for cond in conditions:
            if cond.startswith("<="):
                limit = CveLookupClient._parse_version(cond[2:])
                if limit and ver > limit:
                    return False
            elif cond.startswith("<"):
                limit = CveLookupClient._parse_version(cond[1:])
                if limit and ver >= limit:
                    return False
            elif cond.startswith("="):
                exact = CveLookupClient._parse_version(cond[1:])
                if exact and ver != exact:
                    return False

        return True

    @staticmethod
    def _parse_version(v: str) -> tuple[int, ...] | None:
        """Parse a version string into a comparable tuple.

        Handles ``1``, ``1.2``, ``1.2.3``, ``1.2.3-alpha``.
        """
        if not v:
            return None
        # Strip pre-release suffix
        clean = re.split(r"[-_]", v.strip())[0]
        parts = clean.split(".")
        try:
            return tuple(int(p) for p in parts)
        except (ValueError, TypeError):
            return None


# ---------------------------------------------------------------------------
# Domain Reputation
# ---------------------------------------------------------------------------

class DomainReputationClient:
    """Embedded domain whitelist for phishing link detection (O-35).

    Maintains a whitelist of known-safe domains and a blocklist of
    known-malicious TLDs / patterns.
    """

    # Known-safe domains (exact match and suffix match)
    _WHITELIST_SUFFIXES: set[str] = {
        # Major tech platforms
        "github.com", "github.io", "githubusercontent.com",
        "gitlab.com", "gitlab.io", "bitbucket.org",
        "npmjs.com", "npmjs.org", "pypi.org",
        "pypi.io", "maven.org", "mvnrepository.com",
        "docker.com", "docker.io", "hub.docker.com",
        "golang.org", "pkg.go.dev", "crates.io",
        "rubygems.org", "nuget.org", "packagist.org",
        "cocoapods.org", "homebrew.sh",
        # Cloud platforms
        "aws.amazon.com", "aws.com", "amazonaws.com",
        "cloud.google.com", "googleapis.com",
        "azure.com", "azure.microsoft.com",
        "azureedge.net", "azurefd.net",
        "aliyun.com", "aliyuncs.com",
        "digitalocean.com", "vercel.com", "netlify.com",
        "cloudflare.com", "heroku.com",
        # Documentation
        "python.org", "docs.python.org",
        "developer.mozilla.org", "mdn.mozilla.org", "mozilla.org",
        "w3.org", "ietf.org", "rfc-editor.org",
        "stackoverflow.com", "stackexchange.com",
        "readthedocs.io", "readthedocs.org",
        "devdocs.io", "dev.to",
        # Chinese tech
        "csdn.net", "zhihu.com", "cnblogs.com",
        "jianshu.com", "segmentfault.com",
        "oschina.net", "cnblogs.com",
        # AI/ML platforms
        "openai.com", "anthropic.com", "huggingface.co",
        "pytorch.org", "tensorflow.org",
    }

    _SUSPICIOUS_TLDS: set[str] = {
        "xyz", "top", "club", "online", "site", "live", "work",
        "info", "biz", "gq", "ml", "cf", "ga", "tk", "zip",
        "review", "trade", "webcam", "men", "download", "loan",
        "win", "bid", "date", "racing", "science",
    }

    _URL_SHORTENERS: set[str] = {
        "bit.ly", "tinyurl.com", "shorturl.at", "goo.gl",
        "ow.ly", "is.gd", "tiny.cc", "buff.ly", "rb.gy",
        "t.co", "short.link", "shr.lc",
    }

    def lookup(self, domain: str) -> ExternalLookupResult:
        """Check domain reputation.

        Returns:
            An ``ExternalLookupResult`` with ``found=True`` if
            the domain is suspicious.
        """
        domain = domain.strip().lower()

        # Check URL shorteners — always suspicious
        for shortener in self._URL_SHORTENERS:
            if shortener in domain or domain.endswith("." + shortener):
                return ExternalLookupResult(
                    source="domain_reputation",
                    query=domain,
                    found=True,
                    data={"risk": "url_shortener", "detail": f"Known URL shortener: {shortener}"},
                )

        # Check whitelist — these are always safe
        for suffix in self._WHITELIST_SUFFIXES:
            if domain == suffix or domain.endswith("." + suffix):
                return ExternalLookupResult(
                    source="domain_reputation",
                    query=domain,
                    found=False,
                    data={"risk": "none", "detail": "Domain is whitelisted"},
                )

        # Check suspicious TLDs
        for tld in self._SUSPICIOUS_TLDS:
            if domain.endswith(f".{tld}") or f".{tld}/" in domain:
                return ExternalLookupResult(
                    source="domain_reputation",
                    query=domain,
                    found=True,
                    data={"risk": "suspicious_tld", "detail": f"Suspicious TLD: .{tld}"},
                )

        # Domain with login/phish keywords in the path
        if re.search(r"(?:login|signin|verify|authenticate|account|secure|banking|wallet|update|confirm)", domain):
            return ExternalLookupResult(
                source="domain_reputation",
                query=domain,
                found=True,
                data={"risk": "phishing_keyword", "detail": "Domain contains phishing-related keywords"},
            )

        return ExternalLookupResult(
            source="domain_reputation",
            query=domain,
            found=False,
            data={"risk": "unknown", "detail": "Domain not in whitelist or blocklist"},
        )


# ---------------------------------------------------------------------------
# Package Registry
# ---------------------------------------------------------------------------

class PackageRegistryClient:
    """Embedded known-packages list for dependency confusion detection.

    Contains the top ~100 most-starred packages per ecosystem.
    Any package name not in this list is flagged as a potential
    dependency confusion risk (O-33).
    """

    _KNOWN_PACKAGES: dict[str, set[str]] = {
        "pypi": {
            "requests", "numpy", "pandas", "matplotlib", "scipy",
            "scikit-learn", "tensorflow", "torch", "pytorch",
            "django", "flask", "fastapi", "sqlalchemy",
            "pillow", "opencv-python", "nltk", "transformers",
            "click", "pydantic", "uvicorn", "gunicorn",
            "celery", "redis", "psycopg2", "pymongo",
            "beautifulsoup4", "selenium", "pytest", "black",
            "flake8", "mypy", "ruff", "isort",
            "boto3", "google-cloud-storage", "azure-storage-blob",
            "cryptography", "pyjwt", "passlib", "bcrypt",
            "httpx", "aiohttp", "websockets", "starlette",
            "jinja2", "markdown", "pyyaml", "toml",
            "loguru", "structlog", "rich", "tqdm",
            "jsonschema", "orjson", "msgpack", "protobuf",
            "alembic", "migrate", "psutil", "watchdog",
        },
        "npm": {
            "react", "react-dom", "vue", "angular", "svelte",
            "next", "nuxt", "gatsby", "remix",
            "express", "koa", "fastify", "hapi",
            "lodash", "axios", "node-fetch", "undici",
            "typescript", "eslint", "prettier", "webpack",
            "vite", "rollup", "parcel", "esbuild",
            "tailwindcss", "sass", "postcss", "autoprefixer",
            "jest", "vitest", "mocha", "cypress",
            "prisma", "typeorm", "sequelize", "mongoose",
            "chalk", "commander", "yargs", "inquirer",
            "socket.io", "ws", "graphql", "apollo-server",
            "cheerio", "puppeteer", "playwright", "nodemailer",
            "jsonwebtoken", "passport", "bcryptjs", "zod",
            "dayjs", "date-fns", "luxon", "uuid",
            "nanoid", "immer", "zustand", "redux",
        },
        "cargo": {
            "serde", "tokio", "axum", "actix-web",
            "rocket", "warp", "hyper", "reqwest",
            "rand", "chrono", "regex", "clap",
            "serde_json", "toml", "anyhow", "thiserror",
            "tracing", "log", "env_logger", "color-eyre",
            "sqlx", "diesel", "sea-orm", "rusqlite",
            "tower", "tonic", "prost", "opentelemetry",
            "openssl", "ring", "rustls", "native-tls",
            "image", "plotters", "csv", "polars",
            "criterion", "mockall", "rstest", "proptest",
        },
        "go": {
            "gin", "echo", "fiber", "chi", "mux",
            "cobra", "viper", "zap", "zerolog", "logrus",
            "gorm", "sqlx", "ent", "mongo-go-driver",
            "grpc", "protobuf", "connect-go", "buf",
            "prometheus", "otel", "opentelemetry-go",
            "redis", "minio-go", "aws-sdk-go", "google-cloud-go",
            "testify", "mock", "gomock", "ginkgo",
            "jwt-go", "oauth2", "crypto", "net",
            "temporal", "cobra", "pflag",
        },
    }

    def lookup(self, package_name: str, ecosystem: str = "pypi") -> ExternalLookupResult:
        """Check if *package_name* is a known package in *ecosystem*.

        Returns ``found=True`` if the package IS in the known list
        (safe).  Returns ``found=False`` if NOT in the list
        (potential dependency confusion risk).
        """
        known = self._KNOWN_PACKAGES.get(ecosystem, set())
        pkg_lower = package_name.strip().lower()

        if pkg_lower in known:
            return ExternalLookupResult(
                source="package_registry",
                query=f"{ecosystem}:{package_name}",
                found=True,
                data={"ecosystem": ecosystem, "known": True},
            )

        # Not in known list → potential dependency confusion
        return ExternalLookupResult(
            source="package_registry",
            query=f"{ecosystem}:{package_name}",
            found=False,
            data={"ecosystem": ecosystem, "known": False},
        )

    def is_known(self, package_name: str, ecosystem: str = "pypi") -> bool:
        """Quick check if *package_name* is a known package."""
        return package_name.strip().lower() in self._KNOWN_PACKAGES.get(ecosystem, set())
