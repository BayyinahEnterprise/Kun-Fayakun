# Bismillah ir-Rahman ir-Rahim
"""
RING-CLOSE checks: the ending must verify against the beginning.

Detects unclosed resources, unmatched acquire/release, and open-without-close
patterns that ruff and mypy do not catch.

Rules:
    RC-001  File opened without context manager (open() not in `with`)
    RC-002  Lock acquired without context manager (.acquire() not in `with`)
    RC-003  Socket/connection created without context manager
    RC-004  Cursor created without close() in the same scope
    RC-005  tempfile created without context manager or cleanup
"""

from __future__ import annotations

import ast
from typing import List

from kun_fayakun.furqan.checks.finding import Finding, Fix, Severity


def check_ring_close(tree: ast.Module, path: str) -> List[Finding]:
    """Run all RING-CLOSE checks on an AST."""
    findings: List[Finding] = []
    findings.extend(_check_open_without_with(tree, path))
    findings.extend(_check_lock_without_with(tree, path))
    findings.extend(_check_socket_without_with(tree, path))
    findings.extend(_check_cursor_without_close(tree, path))
    findings.extend(_check_tempfile_without_cleanup(tree, path))
    return findings


def _check_open_without_with(tree: ast.Module, path: str) -> List[Finding]:
    """RC-001: open() called outside a `with` statement."""
    findings: List[Finding] = []
    with_targets = set()

    # Collect all open() calls that ARE inside a with statement
    for node in ast.walk(tree):
        if isinstance(node, ast.With):
            for item in node.items:
                if isinstance(item.context_expr, ast.Call):
                    call = item.context_expr
                    if _is_open_call(call):
                        with_targets.add(id(call))

    # Find all open() calls that are NOT in a with
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_open_call(node):
            if id(node) not in with_targets:
                # Check if the result is assigned (not just called and discarded)
                findings.append(Finding(
                    rule="RC-001",
                    path=path,
                    line=node.lineno,
                    col=node.col_offset,
                    message="open() called without context manager -- file handle may never close",
                    severity=Severity.HIGH,
                    fix=Fix.ENRICH,
                    detail="Use `with open(...) as f:` to guarantee the file handle closes. "
                           "The ring must close: every opened resource needs a matching close.",
                ))
    return findings


def _check_lock_without_with(tree: ast.Module, path: str) -> List[Finding]:
    """RC-002: .acquire() called without context manager."""
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "acquire":
                # Check if this acquire is inside a with statement
                # Simple heuristic: if acquire() is called as a bare statement,
                # it should be in a with or have a matching release
                findings.append(Finding(
                    rule="RC-002",
                    path=path,
                    line=node.lineno,
                    col=node.col_offset,
                    message=".acquire() called -- prefer `with lock:` to guarantee release",
                    severity=Severity.MEDIUM,
                    fix=Fix.RECALIBRATE,
                    detail="Lock acquire without guaranteed release is an open ring. "
                           "Use the lock as a context manager: `with lock:` instead of "
                           "lock.acquire() / lock.release().",
                ))
    return findings


def _check_socket_without_with(tree: ast.Module, path: str) -> List[Finding]:
    """RC-003: socket.socket() or connection created without context manager."""
    findings: List[Finding] = []
    with_targets = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.With):
            for item in node.items:
                if isinstance(item.context_expr, ast.Call):
                    with_targets.add(id(item.context_expr))

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_connection_call(node):
            if id(node) not in with_targets:
                findings.append(Finding(
                    rule="RC-003",
                    path=path,
                    line=node.lineno,
                    col=node.col_offset,
                    message="Connection/socket created without context manager",
                    severity=Severity.HIGH,
                    fix=Fix.ENRICH,
                    detail="Network connections and sockets must close. "
                           "Use a context manager to guarantee cleanup.",
                ))
    return findings


def _check_cursor_without_close(tree: ast.Module, path: str) -> List[Finding]:
    """RC-004: .cursor() called without close or context manager."""
    findings: List[Finding] = []
    with_targets = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.With):
            for item in node.items:
                if isinstance(item.context_expr, ast.Call):
                    with_targets.add(id(item.context_expr))

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "cursor" and id(node) not in with_targets:
                findings.append(Finding(
                    rule="RC-004",
                    path=path,
                    line=node.lineno,
                    col=node.col_offset,
                    message="Database cursor created without context manager",
                    severity=Severity.MEDIUM,
                    fix=Fix.ENRICH,
                    detail="Cursors hold database resources. Use `with conn.cursor() as cur:` "
                           "to guarantee cleanup.",
                ))
    return findings


def _check_tempfile_without_cleanup(tree: ast.Module, path: str) -> List[Finding]:
    """RC-005: tempfile.mktemp/mkstemp/NamedTemporaryFile without context manager."""
    findings: List[Finding] = []
    with_targets = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.With):
            for item in node.items:
                if isinstance(item.context_expr, ast.Call):
                    with_targets.add(id(item.context_expr))

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_tempfile_call(node):
            if id(node) not in with_targets:
                findings.append(Finding(
                    rule="RC-005",
                    path=path,
                    line=node.lineno,
                    col=node.col_offset,
                    message="Temporary file created without context manager or cleanup",
                    severity=Severity.MEDIUM,
                    fix=Fix.ENRICH,
                    detail="Temporary files that are not cleaned up leak disk space. "
                           "Use a context manager or ensure explicit cleanup.",
                ))
    return findings


# ── Helpers ──

def _is_open_call(node: ast.Call) -> bool:
    """Check if a Call node is a call to open() or io.open()."""
    if isinstance(node.func, ast.Name) and node.func.id == "open":
        return True
    if isinstance(node.func, ast.Attribute) and node.func.attr == "open":
        return True
    return False


def _is_connection_call(node: ast.Call) -> bool:
    """Check if a Call node creates a socket or connection."""
    if isinstance(node.func, ast.Attribute):
        if node.func.attr in ("socket", "connect", "create_connection"):
            return True
    if isinstance(node.func, ast.Name):
        if node.func.id in ("socket", "create_connection"):
            return True
    return False


def _is_tempfile_call(node: ast.Call) -> bool:
    """Check if a Call node creates a temporary file."""
    if isinstance(node.func, ast.Attribute):
        if node.func.attr in ("mktemp", "mkstemp", "NamedTemporaryFile", "TemporaryFile",
                                "TemporaryDirectory", "SpooledTemporaryFile"):
            return True
    if isinstance(node.func, ast.Name):
        if node.func.id in ("NamedTemporaryFile", "TemporaryFile",
                             "TemporaryDirectory", "SpooledTemporaryFile"):
            return True
    return False


# Bismillah ir-Rahman ir-Rahim
