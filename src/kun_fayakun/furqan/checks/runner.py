# Bismillah ir-Rahman ir-Rahim
"""
Furqan-lint v2.0 runner -- coordinates all check families on Python files.

This module is the heart of `kun furqan lint`. It:
1. Loads config from .furqan.toml or pyproject.toml
2. Walks a directory or takes a single file
3. Parses each .py file into an AST
4. Runs all four check families (RING-CLOSE, MARAD, TRUST-BOUNDARY, SCAN-INCOMPLETE)
5. Filters findings by config (select, ignore, severity, per-file)
6. Formats output (text, json, sarif)
7. Returns an exit code (0 = clean, 1 = findings, 2 = parse error)
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import List

from kun_fayakun.furqan.checks.finding import Finding, Severity
from kun_fayakun.furqan.checks.config import Config, load_config
from kun_fayakun.furqan.checks.formatters import format_text, format_json, format_sarif
from kun_fayakun.furqan.checks.ring_close import check_ring_close
from kun_fayakun.furqan.checks.marad import check_marad
from kun_fayakun.furqan.checks.trust_boundary import check_trust_boundary
from kun_fayakun.furqan.checks.scan_incomplete import check_scan_incomplete


EXCLUDED_DIRS: frozenset = frozenset({
    ".venv", "venv", "__pycache__", ".git", "node_modules",
    ".tox", ".mypy_cache", ".ruff_cache", ".pytest_cache",
    "target", "vendor", "build", "dist", ".eggs", "*.egg-info",
})


def lint_source(source: str, path: str, config: Config | None = None) -> List[Finding]:
    """Run all check families on a single Python source string.

    Returns a list of Finding objects, sorted by line number.
    If config is provided, findings are filtered accordingly.
    """
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError:
        return []

    findings: List[Finding] = []
    findings.extend(check_ring_close(tree, path))
    findings.extend(check_marad(tree, path))
    findings.extend(check_trust_boundary(tree, path))
    findings.extend(check_scan_incomplete(source, tree, path))

    if config:
        findings = config.filter_findings(findings)

    findings.sort(key=lambda f: (f.path, f.line, f.col))
    return findings


def lint_file(path: Path, config: Config | None = None) -> tuple[List[Finding], int]:
    """Lint a single Python file.

    Returns (findings, exit_code) where exit_code is:
    - 0 if no findings
    - 1 if findings exist
    - 2 if the file could not be parsed
    """
    if config and config.should_exclude_path(path):
        return [], 0

    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"  ERROR  Cannot read {path}: {exc}", file=sys.stderr)
        return [], 2

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        line = exc.lineno if exc.lineno is not None else 0
        print(f"  SYNTAX ERROR  {path}:{line}  {exc.msg}", file=sys.stderr)
        return [], 2

    findings: List[Finding] = []
    findings.extend(check_ring_close(tree, str(path)))
    findings.extend(check_marad(tree, str(path)))
    findings.extend(check_trust_boundary(tree, str(path)))
    findings.extend(check_scan_incomplete(source, tree, str(path)))

    if config:
        findings = config.filter_findings(findings)

    findings.sort(key=lambda f: (f.path, f.line, f.col))
    return findings, 1 if findings else 0


def lint_directory(directory: Path, config: Config | None = None) -> tuple[List[Finding], int]:
    """Lint all .py files in a directory recursively."""
    all_findings: List[Finding] = []
    exit_code = 0

    py_files = sorted(
        p for p in directory.rglob("*.py")
        if p.is_file()
        and not any(part in EXCLUDED_DIRS for part in p.parts)
    )

    if config:
        py_files = [p for p in py_files if not config.should_exclude_path(p)]

    if not py_files:
        print(f"  No .py files found in {directory}")
        return [], 0

    for path in py_files:
        findings, code = lint_file(path, config)
        all_findings.extend(findings)
        exit_code = max(exit_code, code)

    return all_findings, exit_code


def run(args: list[str]) -> int:
    """Entry point for `kun furqan lint`."""
    # Parse CLI arguments
    paths: list[str] = []
    remaining = list(args)

    # Skip "lint" if it's the first arg (dispatched from kun cli)
    if remaining and remaining[0] == "lint":
        remaining = remaining[1:]

    if not remaining or remaining[0] in ("-h", "--help"):
        _print_usage()
        return 0

    # Load config from file first, then override with CLI
    config = load_config()

    while remaining:
        arg = remaining.pop(0)
        if arg in ("-v", "--verbose"):
            config.verbose = True
        elif arg in ("-h", "--help"):
            _print_usage()
            return 0
        elif arg == "--format" and remaining:
            fmt = remaining.pop(0)
            if fmt in ("text", "json", "sarif"):
                config.output_format = fmt
            else:
                print(f"Unknown format: {fmt}. Use text, json, or sarif.", file=sys.stderr)
                return 2
        elif arg == "--select" and remaining:
            rules = remaining.pop(0).split(",")
            config.select = set(r.strip() for r in rules)
        elif arg == "--ignore" and remaining:
            rules = remaining.pop(0).split(",")
            config.ignore.update(r.strip() for r in rules)
        elif arg == "--min-severity" and remaining:
            sev = remaining.pop(0).upper()
            from kun_fayakun.furqan.checks.config import SEVERITY_BY_NAME
            if sev in SEVERITY_BY_NAME:
                config.min_severity = SEVERITY_BY_NAME[sev]
            else:
                print(f"Unknown severity: {sev}. Use LOW, MEDIUM, HIGH, or CRITICAL.", file=sys.stderr)
                return 2
        elif arg.startswith("-"):
            print(f"Unknown option: {arg}", file=sys.stderr)
            return 2
        else:
            paths.append(arg)

    if not paths:
        paths = ["."]

    # Banner (only for text output)
    if config.output_format == "text":
        print("Bismillah ir-Rahman ir-Rahim")
        print()
        print("furqan-lint v2.0 -- structural honesty checks for Python")
        print()

    all_findings: List[Finding] = []
    exit_code = 0
    file_count = 0

    for p_str in paths:
        target = Path(p_str)
        if not target.exists():
            print(f"  Not found: {target}", file=sys.stderr)
            exit_code = max(exit_code, 2)
            continue

        if target.is_file():
            findings, code = lint_file(target, config)
            all_findings.extend(findings)
            exit_code = max(exit_code, code)
            file_count += 1
        else:
            findings, code = lint_directory(target, config)
            all_findings.extend(findings)
            exit_code = max(exit_code, code)
            py_files = [
                p for p in target.rglob("*.py")
                if not any(part in EXCLUDED_DIRS for part in p.parts)
                and not (config and config.should_exclude_path(p))
            ]
            file_count += len(py_files)

    # Output findings
    if config.output_format == "json":
        print(format_json(all_findings))
    elif config.output_format == "sarif":
        print(format_sarif(all_findings))
    else:
        # Text output
        if all_findings:
            output = format_text(all_findings, verbose=config.verbose)
            print(output)
            print()

        # Summary
        crit = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in all_findings if f.severity == Severity.HIGH)
        med = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in all_findings if f.severity == Severity.LOW)

        if all_findings:
            print(f"Found {len(all_findings)} finding(s) in {file_count} file(s):")
            parts = []
            if crit:
                parts.append(f"{crit} CRITICAL")
            if high:
                parts.append(f"{high} HIGH")
            if med:
                parts.append(f"{med} MEDIUM")
            if low:
                parts.append(f"{low} LOW")
            print(f"  {', '.join(parts)}")
        else:
            print(f"PASS  {file_count} file(s) scanned. Zero findings.")

        print()
        print("Bismillah ir-Rahman ir-Rahim")

    return min(exit_code, 1) if all_findings else exit_code


def _print_usage() -> None:
    print("furqan-lint v2.0 -- structural honesty checks for Python")
    print()
    print("Usage:")
    print("  kun furqan lint [options] [path ...]")
    print()
    print("Options:")
    print("  -v, --verbose              Show detailed explanations")
    print("  --format text|json|sarif   Output format (default: text)")
    print("  --select RC,MR,TB-001      Run only these families/rules")
    print("  --ignore TB-001,SI-004     Suppress these rules")
    print("  --min-severity MEDIUM      Skip findings below this level")
    print("  -h, --help                 Show this help message")
    print()
    print("Config file: .furqan.toml or [tool.furqan] in pyproject.toml")
    print()
    print("Check families:")
    print("  RING-CLOSE (RC-*)       Unclosed resources (files, locks, sockets)")
    print("  MARAD (MR-*)            Silent failure / swallowed exceptions")
    print("  TRUST-BOUNDARY (TB-*)   Security-relevant type confusion patterns")
    print("  SCAN-INCOMPLETE (SI-*)  Catch-all types, blanket suppressions, stale TODOs")
    print()
    print("Fix categories (tawba operations):")
    print("  simplify      Remove the unauthorized addition")
    print("  recalibrate   Align surface with substrate")
    print("  enrich        Add what is missing")


# Bismillah ir-Rahman ir-Rahim
