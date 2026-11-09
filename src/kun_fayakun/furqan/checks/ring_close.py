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

    # Collect all open() calls that ARE inside a with/async with statement
    for node in ast.walk(tree):
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                ctx = item.context_expr
                if isinstance(ctx, ast.Call):
                    if _is_open_call(ctx):
                        with_targets.add(id(ctx))
                    # contextlib.closing(open(...))
                    if _is_closing_call(ctx) and ctx.args:
                        inner = ctx.args[0]
                        if isinstance(inner, ast.Call) and _is_open_call(inner):
                            with_targets.add(id(inner))

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
    """RC-002: .acquire() called outside a `with` block and no .release() in scope."""
    findings: List[Finding] = []
    # Collect all acquire() calls that are inside a with statement
    with_acquire_ids: set = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.With):
            for child in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                # acquire() inside a with body is likely paired with the with
                pass
            for item in node.items:
                # The with target itself might use the lock
                for child in ast.walk(item.context_expr):
                    if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                        if child.func.attr == "acquire":
                            with_acquire_ids.add(id(child))

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "acquire" and id(node) not in with_acquire_ids:
                # Check if there's a matching .release() in the enclosing scope
                scope = _find_enclosing_scope(node, tree)
                if scope:
                    scope_text = ast.dump(scope)
                    if "release" in scope_text:
                        continue  # Has a release -- possibly paired via try/finally
                findings.append(Finding(
                    rule="RC-002",
                    path=path,
                    line=node.lineno,
                    col=node.col_offset,
                    message=".acquire() without matching release or context manager",
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


def _find_enclosing_scope(node: ast.AST, tree: ast.Module) -> ast.AST | None:
    """Find the enclosing function/class body for a node."""
    # Build parent map
    parent_map: dict = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parent_map[id(child)] = parent

    current = parent_map.get(id(node))
    while current:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
            return current
        current = parent_map.get(id(current))
    return tree


# ── Helpers ──

def _is_open_call(node: ast.Call) -> bool:
    """Check if a Call node is a call to the built-in open() or io.open().

    Does NOT flag Image.open, webbrowser.open, or other .open() methods
    that are not file-handle constructors.
    """
    # Built-in open()
    if isinstance(node.func, ast.Name) and node.func.id == "open":
        return True
    # io.open() or builtins.open()
    if isinstance(node.func, ast.Attribute) and node.func.attr == "open":
        obj = node.func.value
        if isinstance(obj, ast.Name) and obj.id in ("io", "builtins", "codecs"):
            return True
        # Bare .open() on unknown object -- too many false positives
        # (Image.open, webbrowser.open, zipfile.open, etc)
        return False
    return False


def _is_closing_call(node: ast.Call) -> bool:
    """Check if a Call node is contextlib.closing()."""
    if isinstance(node.func, ast.Attribute) and node.func.attr == "closing":
        return True
    if isinstance(node.func, ast.Name) and node.func.id == "closing":
        return True
    return False


def _is_connection_call(node: ast.Call) -> bool:
    """Check if a Call node creates a socket or network connection.

    Only matches calls that are clearly socket/connection constructors,
    not bare .connect() which could be a Django signal or any other API.
    """
    if isinstance(node.func, ast.Attribute):
        # socket.socket(), socket.create_connection()
        if node.func.attr in ("socket", "create_connection"):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "socket":
                return True
        # http.client.HTTPConnection(), HTTPSConnection()
        if node.func.attr in ("HTTPConnection", "HTTPSConnection"):
            return True
    if isinstance(node.func, ast.Name):
        # Direct import: from socket import socket
        if node.func.id in ("HTTPConnection", "HTTPSConnection"):
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
