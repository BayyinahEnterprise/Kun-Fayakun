# Bismillah ir-Rahman ir-Rahim
"""
Furqan-lint v2.0 runner -- coordinates structural honesty checks across languages.

This module is the heart of `kun furqan lint`. It:
1. Loads config from .furqan.toml or pyproject.toml
2. Walks a directory or takes a single file
3. Routes Python files through the AST-based check families
4. Routes C, Java, and other supported languages through tree-sitter adapters
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
from kun_fayakun.furqan.checks.secrets import check_secrets
from kun_fayakun.furqan.checks.injection import check_injection
from kun_fayakun.furqan.checks.crypto import check_crypto
from kun_fayakun.furqan.checks.adapters.base import get_adapter, supported_extensions


EXCLUDED_DIRS: frozenset = frozenset({
    ".venv", "venv", "__pycache__", ".git", "node_modules",
    ".tox", ".mypy_cache", ".ruff_cache", ".pytest_cache",
    ".eggs",
})


def _is_excluded(path: Path, scan_root: Path) -> bool:
    """Check if a path should be excluded, relative to the scan root.

    Only matches directory names that are direct children of the scan root
    or intermediate directories, not ancestor paths like /tmp/build/.
    """
    try:
        rel = path.relative_to(scan_root)
    except ValueError:
        rel = path
    return any(part in EXCLUDED_DIRS for part in rel.parts[:-1])


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
    findings.extend(check_secrets(tree, path))
    findings.extend(check_injection(tree, path))
    findings.extend(check_crypto(tree, path))

    if config:
        findings = config.filter_findings(findings)

    findings.sort(key=lambda f: (f.path, f.line, f.col))
    return findings


def lint_file(path: Path, config: Config | None = None) -> tuple[List[Finding], int]:
    """Lint a single file (Python, C, Java, or other supported language).

    Returns (findings, exit_code) where exit_code is:
    - 0 if no findings
    - 1 if findings exist
    - 2 if the file could not be parsed
    """
    if config and config.should_exclude_path(path):
        return [], 0

    # Route non-Python files through adapters
    adapter = get_adapter(str(path))
    if adapter is not None:
        return _lint_file_adapted(path, adapter, config)

    # Python path: AST-based checks
    return _lint_file_python(path, config)


def _lint_file_python(path: Path, config: Config | None = None) -> tuple[List[Finding], int]:
    """Lint a Python file via AST-based checks."""
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
    findings.extend(check_secrets(tree, str(path)))
    findings.extend(check_injection(tree, str(path)))
    findings.extend(check_crypto(tree, str(path)))

    if config:
        findings = config.filter_findings(findings)

    findings.sort(key=lambda f: (f.path, f.line, f.col))
    return findings, 1 if findings else 0


def _lint_file_adapted(path: Path, adapter, config: Config | None = None) -> tuple[List[Finding], int]:
    """Lint a non-Python file via a tree-sitter adapter."""
    try:
        source_bytes = path.read_bytes()
    except OSError as exc:
        print(f"  ERROR  Cannot read {path}: {exc}", file=sys.stderr)
        return [], 2

    findings = adapter.check(source_bytes, str(path))

    if config:
        findings = config.filter_findings(findings)

    findings.sort(key=lambda f: (f.path, f.line, f.col))
    return findings, 1 if findings else 0


def lint_directory(directory: Path, config: Config | None = None) -> tuple[List[Finding], int]:
    """Lint all supported files in a directory recursively."""
    all_findings: List[Finding] = []
    exit_code = 0

    exts = supported_extensions()
    source_files = sorted(
        p for p in directory.rglob("*")
        if p.is_file()
        and p.suffix.lower() in exts
        and not _is_excluded(p, directory)
    )

    if config:
        source_files = [p for p in source_files if not config.should_exclude_path(p)]

    if not source_files:
        print(f"  WARNING: No supported files found in {directory}", file=sys.stderr)
        return [], 2  # exit nonzero -- scanning nothing is not a pass

    for path in source_files:
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
        print("furqan-lint v2.0 -- structural honesty checks for Python, C, C++, Java, C#, and Ada/SPARK")
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
            exts = supported_extensions()
            scanned = [
                p for p in target.rglob("*")
                if p.is_file()
                and p.suffix.lower() in exts
                and not _is_excluded(p, target)
                and not (config and config.should_exclude_path(p))
            ]
            file_count += len(scanned)

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
    print("furqan-lint v2.0 -- structural honesty checks")
    print()
    print("Usage:")
    print("  kun furqan lint [options] [path ...]")
    print()
    print("Supported languages:")
    print("  Python (.py)         40 rules via AST analysis")
    print("  C (.c, .h)           14 rules via tree-sitter (automotive, medical, aerospace)")
    print("  C++ (.cpp, .cc, ...) 21 rules via tree-sitter (AUTOSAR, aerospace, trading)")
    print("  Java (.java)         10 rules via tree-sitter (financial, medical, enterprise)")
    print("  C# (.cs)             12 rules via tree-sitter (FDA medical, financial, .NET)")
    print("  Ada/SPARK (.adb/ads) 11 rules via tree-sitter (DO-178C, IEC 60880, EN 50128)")
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
    print("  TRUST-BOUNDARY (TB-*)   Security and trust boundary violations")
    print("  SCAN-INCOMPLETE (SI-*)  Catch-all types, blanket suppressions, stale TODOs")
    print()
    print("Fix categories (tawba operations):")
    print("  simplify      Remove the unauthorized addition")
    print("  recalibrate   Align surface with substrate")
    print("  enrich        Add what is missing")


# Bismillah ir-Rahman ir-Rahim
