# Bismillah ir-Rahman ir-Rahim
"""
Furqan-lint v2.0 runner -- coordinates all check families on Python files.

This module is the heart of `kun furqan lint`. It:
1. Walks a directory or takes a single file
2. Parses each .py file into an AST
3. Runs all four check families (RING-CLOSE, MARAD, TRUST-BOUNDARY, SCAN-INCOMPLETE)
4. Collects and formats findings
5. Returns an exit code (0 = clean, 1 = findings, 2 = parse error)
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import List

from kun_fayakun.furqan.checks.finding import Finding, Severity
from kun_fayakun.furqan.checks.ring_close import check_ring_close
from kun_fayakun.furqan.checks.marad import check_marad
from kun_fayakun.furqan.checks.trust_boundary import check_trust_boundary
from kun_fayakun.furqan.checks.scan_incomplete import check_scan_incomplete


EXCLUDED_DIRS: frozenset = frozenset({
    ".venv", "venv", "__pycache__", ".git", "node_modules",
    ".tox", ".mypy_cache", ".ruff_cache", ".pytest_cache",
    "target", "vendor", "build", "dist", ".eggs", "*.egg-info",
})


def lint_source(source: str, path: str) -> List[Finding]:
    """Run all check families on a single Python source string.

    Returns a list of Finding objects, sorted by line number.
    """
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError:
        return []  # Caller handles parse errors separately

    findings: List[Finding] = []
    findings.extend(check_ring_close(tree, path))
    findings.extend(check_marad(tree, path))
    findings.extend(check_trust_boundary(tree, path))
    findings.extend(check_scan_incomplete(source, tree, path))

    findings.sort(key=lambda f: (f.path, f.line, f.col))
    return findings


def lint_file(path: Path) -> tuple[List[Finding], int]:
    """Lint a single Python file.

    Returns (findings, exit_code) where exit_code is:
    - 0 if no findings
    - 1 if findings exist
    - 2 if the file could not be parsed
    """
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

    findings.sort(key=lambda f: (f.path, f.line, f.col))
    return findings, 1 if findings else 0


def lint_directory(directory: Path) -> tuple[List[Finding], int]:
    """Lint all .py files in a directory recursively.

    Returns (all_findings, max_exit_code).
    """
    all_findings: List[Finding] = []
    exit_code = 0
    file_count = 0

    py_files = sorted(
        p for p in directory.rglob("*.py")
        if p.is_file()
        and not any(part in EXCLUDED_DIRS for part in p.parts)
    )

    if not py_files:
        print(f"  No .py files found in {directory}")
        return [], 0

    for path in py_files:
        findings, code = lint_file(path)
        all_findings.extend(findings)
        exit_code = max(exit_code, code)
        file_count += 1

    return all_findings, exit_code


def format_findings(findings: List[Finding], verbose: bool = False) -> str:
    """Format findings for terminal output."""
    if not findings:
        return ""

    lines: List[str] = []
    current_path = ""

    for f in findings:
        if f.path != current_path:
            if current_path:
                lines.append("")
            current_path = f.path

        severity_color = {
            Severity.CRITICAL: "\033[1;31m",  # bold red
            Severity.HIGH: "\033[31m",         # red
            Severity.MEDIUM: "\033[33m",       # yellow
            Severity.LOW: "\033[36m",          # cyan
        }
        reset = "\033[0m"

        # Check if stdout supports color
        use_color = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

        if use_color:
            color = severity_color.get(f.severity, "")
            line = f"{f.path}:{f.line}:{f.col}: {color}{f.rule}{reset} [{f.severity.value}] {f.message}"
        else:
            line = str(f)

        lines.append(line)

        if verbose and f.detail:
            # Indent detail lines
            for detail_line in f.detail.split("\n"):
                lines.append(f"    {detail_line}")

        # Show fix category
        lines.append(f"    fix: {f.fix.value}")

    return "\n".join(lines)


def run(args: list[str]) -> int:
    """Entry point for `kun furqan lint`."""
    verbose = False
    paths: list[str] = []

    # Parse arguments
    remaining = list(args)
    if not remaining or remaining[0] in ("-h", "--help"):
        _print_usage()
        return 0

    # The first arg should be "lint" (dispatched from kun cli)
    if remaining and remaining[0] == "lint":
        remaining = remaining[1:]

    while remaining:
        arg = remaining.pop(0)
        if arg in ("-v", "--verbose"):
            verbose = True
        elif arg in ("-h", "--help"):
            _print_usage()
            return 0
        else:
            paths.append(arg)

    if not paths:
        paths = ["."]

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
            findings, code = lint_file(target)
            all_findings.extend(findings)
            exit_code = max(exit_code, code)
            file_count += 1
        else:
            findings, code = lint_directory(target)
            all_findings.extend(findings)
            exit_code = max(exit_code, code)
            py_files = list(target.rglob("*.py"))
            file_count += len([
                f for f in py_files
                if not any(part in EXCLUDED_DIRS for part in f.parts)
            ])

    # Print findings
    if all_findings:
        output = format_findings(all_findings, verbose=verbose)
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
    return exit_code


def _print_usage() -> None:
    print("furqan-lint v2.0 -- structural honesty checks for Python")
    print()
    print("Usage:")
    print("  kun furqan lint [options] [path ...]")
    print()
    print("Options:")
    print("  -v, --verbose    Show detailed explanations for each finding")
    print("  -h, --help       Show this help message")
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
