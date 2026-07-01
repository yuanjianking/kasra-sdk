#!/usr/bin/env python3
"""Kasra L3 Rule Engine — CLI entry point.

Usage::

    kasra-scan info                     # Show engine info
    kasra-scan list-rules               # List all loaded rules
    kasra-scan input <text>             # Scan input text
    kasra-scan input --stdin            # Scan input from stdin
    kasra-scan scan <path>              # Scan a file or directory
    kasra-scan scan                     # Scan current directory
    kasra-scan --help                   # Show help

Installed as the ``kasra-scan`` console script via ``pyproject.toml``.
"""

from __future__ import annotations

import argparse
import signal
import sys
from pathlib import Path
from typing import NoReturn

from kasra.core.engine import RuleEngine
from kasra.models.enums import Severity


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kasra-scan",
        description="Kasra L3 Rule Engine — AI Development Security Governance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  kasra-scan scan ./src           Scan a directory\n"
            "  kasra-scan input --stdin         Read input from stdin\n"
            "  kasra-scan list-rules            Show all loaded rules\n"
        ),
    )
    parser.add_argument(
        "--rules-dir",
        default=None,
        help="Path to rule JSON bundle directory (default: auto-detect)",
    )
    parser.add_argument(
        "--config-dir",
        default=None,
        help="Path to config directory (default: auto-detect)",
    )

    sub = parser.add_subparsers(
        dest="command",
        required=True,
        help="Sub-command (see sub-command --help)",
    )

    # kasra-scan scan <path>
    scan_p = sub.add_parser("scan", help="Scan a file or directory for rule violations")
    scan_p.add_argument("path", nargs="?", default=".", help="File or directory to scan")

    # kasra-scan input <text>
    input_p = sub.add_parser(
        "input",
        help="Evaluate input text against rules",
        description=(
            "Evaluate input text against loaded rules. "
            "Provide text inline or use --stdin."
        ),
    )
    input_p.add_argument("text", nargs="?", help="Text to evaluate (or use --stdin)")
    input_p.add_argument("--stdin", action="store_true", help="Read text from stdin")

    # kasra-scan list-rules
    sub.add_parser("list-rules", help="List all loaded rule definitions")

    # kasra-scan info
    sub.add_parser("info", help="Show engine configuration and rule counts")

    # kasra-scan health
    sub.add_parser("health", help="Health check — verifies engine loads correctly")

    # kasra-scan metrics
    metrics_p = sub.add_parser("metrics", help="Show detection metrics from MetricsCollector")
    metrics_p.add_argument("--reset", action="store_true", help="Reset collected metrics")

    return parser


def scan(args: argparse.Namespace) -> None:
    """``kasra-scan`` entry point (console script)."""
    engine = RuleEngine(
        rules_dir=args.rules_dir,
        config_dir=args.config_dir,
    )

    count = engine.load_rules()
    print(f"Loaded {count} rules from {engine.store.count()} series\n")

    try:
        command = args.command

        if command == "info":
            _show_info(engine)
        elif command == "list-rules":
            _list_rules(engine)
        elif command == "scan":
            path = Path(args.path)
            if not path.exists():
                print(f"Error: path not found: {path}")
                sys.exit(1)
            if path.is_dir():
                _scan_directory(engine, path)
            else:
                _scan_single_file(engine, path)
        elif command == "input":
            if args.stdin:
                text = sys.stdin.read()
            elif args.text:
                text = args.text
            else:
                print("Error: --stdin or text argument required for 'input' command")
                sys.exit(1)
            result = engine.detect_input(text)
            _print_result(result)
        elif command == "health":
            _health_check(engine)
        elif command == "metrics":
            _show_metrics(engine, getattr(args, "reset", False))
        else:
            _build_parser().print_help()
    finally:
        engine.stop()


def _list_rules(engine: RuleEngine) -> None:
    rules = engine.get_rules()
    for rule in rules:
        print(
            f"{rule.id:<10} {rule.severity.value:<4} {rule.action.value:<12} "
            f"{rule.category:<22} {rule.name}"
        )


def _show_info(engine: RuleEngine) -> None:
    cfg = engine.config
    print(f"Kasra L3 Rule Engine v{engine.store.count()} rules loaded")
    print(f"  Rules directory:   {engine._loader.rules_dir}")
    print(f"  Engine config:     {cfg.engine}")
    print(f"  Input pipeline:    {'enabled' if cfg.pipeline.input.enabled else 'disabled'}")
    print(f"  Output pipeline:   {'enabled' if cfg.pipeline.output.enabled else 'disabled'}")
    print(f"  Batch pipeline:    {'enabled' if cfg.pipeline.batch.enabled else 'disabled'}")
    print(f"  Behavior pipeline: {'enabled' if cfg.pipeline.behavior.enabled else 'disabled'}")

    sev_counts = engine.store.count_by_severity()
    for sev in Severity:
        print(f"    {sev.value}: {sev_counts.get(sev, 0)} rules")


def _scan_directory(engine: RuleEngine, path: Path) -> None:
    results = engine.scan_directory(path)
    triggered = [r for r in results if r.triggered_rules]

    print(f"Scanned {len(results)} files, {len(triggered)} triggered rules")

    for result in triggered:
        file_path = (result.metadata or {}).get("file_path", "unknown")
        sev = result.overall_severity.value
        actions = ", ".join(r.rule_id for r in result.triggered_rules)
        print(f"  {sev} {file_path}: {actions}")


def _scan_single_file(engine: RuleEngine, path: Path) -> None:
    result = engine.scan_file(str(path))
    _print_file_result(path.name, result)


def _print_result(result) -> None:
    status = "❌ BLOCKED" if result.blocked else "⚠ WARNINGS" if result.warnings else "✅ PASS"
    print(f"Status: {status}")
    print(f"Severity: {result.overall_severity.value}")
    print(f"Action: {result.overall_action.value}")
    print(f"Time: {result.execution_time_ms:.1f}ms")

    if result.warnings:
        print("\nWarnings:")
        for w in result.warnings:
            print(f"  • {w}")

    if result.triggered_rules:
        print("\nTriggered rules:")
        for dr in result.triggered_rules:
            print(f"  [{dr.severity.value}] {dr.rule_id}: {dr.rule_name} ({dr.match_count} matches)")

    print()


def _print_file_result(filename: str, result) -> None:
    if result.triggered_rules:
        sev = result.overall_severity.value
        rules = ", ".join(r.rule_id for r in result.triggered_rules)
        print(f"  {sev} {filename}: {rules}")
    else:
        print(f"  ✅ {filename}: clean")


def _health_check(engine: RuleEngine) -> None:
    """Health check — verify engine loads correctly."""
    engine._config.audit.enabled = False
    status = "healthy"
    checks = []

    # 1. Rules loaded
    if engine.rule_count > 0:
        checks.append(("rules_loaded", True, str(engine.rule_count)))
    else:
        checks.append(("rules_loaded", False, "0"))
        status = "unhealthy"

    # 2. Pipelines functional
    try:
        r = engine.detect_input("test")
        checks.append(("input_pipeline", True, f"{len(r.all_results)} rules"))
    except Exception as e:
        checks.append(("input_pipeline", False, str(e)))
        status = "unhealthy"

    try:
        r = engine.detect_output("test")
        checks.append(("output_pipeline", True, f"{len(r.all_results)} rules"))
    except Exception as e:
        checks.append(("output_pipeline", False, str(e)))
        status = "unhealthy"

    # 3. Analysis context
    r = engine.detect_output("def hello():\n    print('world')")
    lang = r.analysis_context.detected_language if r.analysis_context else None
    checks.append(("language_detection", lang is not None, lang or "none"))

    print(f"status: {status}")
    for name, ok, detail in checks:
        print(f"  {'✅' if ok else '❌'} {name}: {detail}")

    sys.exit(0 if status == "healthy" else 1)


def _show_metrics(engine: RuleEngine, reset: bool = False) -> None:
    """Display detection metrics from MetricsCollector."""
    mc = None
    for hook in engine.hook_registry.hooks:
        if hasattr(hook, "snapshot"):
            mc = hook
            break

    if mc is None:
        print("MetricsCollector not registered. Engine metrics unavailable.")
        return

    metrics = mc.snapshot()
    print(f"Detection metrics:")
    print(f"  Total detections: {metrics['total_detections']}")
    print(f"  Avg latency:      {metrics['avg_latency_ms']} ms")
    print(f"  Total latency:    {metrics['total_latency_ms']} ms")

    if metrics["trigger_counts"]:
        print(f"\nTop triggered rules:")
        for rule_id, count in metrics["trigger_counts"].items():
            print(f"  {rule_id}: {count}x")

    if metrics["rule_stats"]:
        print(f"\nPer-rule latency:")
        for rule_id, stats in sorted(metrics["rule_stats"].items()):
            print(f"  {rule_id}: avg={stats['avg_ms']}ms max={stats['max_ms']}ms ({stats['calls']} calls)")

    if reset:
        mc.reset()
        print("\nMetrics reset.")


def main() -> None:
    """CLI entry point (console_scripts hook)."""
    # Handle Ctrl+C gracefully
    signal.signal(signal.SIGINT, _handle_sigint)

    parser = _build_parser()

    # No args → show help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()
    scan(args)


def _handle_sigint(signum: int, frame) -> None:  # type: ignore[no-untyped-def]
    """Print a newline and exit cleanly on Ctrl+C."""
    print()
    sys.exit(130)


if __name__ == "__main__":
    main()
