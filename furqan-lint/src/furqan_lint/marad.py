# Bismillah ir-Rahman ir-Rahim
"""
MARAD checks: disease as diagnostic signal.

When something is wrong, the code must signal it. The ABSENCE of the
expected signal IS the diagnostic -- Surah 9's missing bismillah signals
marad mode.

Rules:
    MR-001  Bare `except:` with no re-raise -- exception swallowed silently
    MR-002  `except Exception` that logs/passes without re-raising
    MR-003  Exception caught and named but never referenced in handler
    MR-005  Empty except block (pass/... only)
    MR-007  try-except-continue (errors silently skipped in loop)
"""

from __future__ import annotations

import ast
from typing import List

from furqan_lint.finding import Finding, Fix, Severity


def check_marad(tree: ast.Module, path: str) -> List[Finding]:
    """Run all MARAD checks on an AST."""
    findings: List[Finding] = []
    findings.extend(_check_bare_except(tree, path))
    findings.extend(_check_empty_except(tree, path))
    findings.extend(_check_generic_error_message(tree, path))
    findings.extend(_check_exception_swallowed(tree, path))
    findings.extend(_check_try_except_continue(tree, path))
    return findings


def _check_bare_except(tree: ast.Module, path: str) -> List[Finding]:
    """MR-001: Bare `except:` catches everything including SystemExit and KeyboardInterrupt."""
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            # Check if the handler re-raises
            if not _handler_reraises(node):
                findings.append(Finding(
                    rule="MR-001",
                    path=path,
                    line=node.lineno,
                    col=node.col_offset,
                    message="Bare `except:` swallows all exceptions including SystemExit",
                    severity=Severity.CRITICAL,
                    fix=Fix.RECALIBRATE,
                    detail="Catch specific exceptions. A bare except that does not re-raise "
                           "is structurally dishonest: it claims to handle everything while "
                           "handling nothing. The diagnostic signal is silenced.",
                ))
    return findings


def _check_empty_except(tree: ast.Module, path: str) -> List[Finding]:
    """MR-005: Except block contains only `pass` or `...` (Ellipsis)."""
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            body = node.body
            if len(body) == 1:
                stmt = body[0]
                is_pass = isinstance(stmt, ast.Pass)
                is_ellipsis = (isinstance(stmt, ast.Expr) and
                               isinstance(stmt.value, ast.Constant) and
                               stmt.value.value is ...)
                if is_pass or is_ellipsis:
                    exc_name = _handler_type_name(node)
                    findings.append(Finding(
                        rule="MR-005",
                        path=path,
                        line=node.lineno,
                        col=node.col_offset,
                        message=f"Empty except block for {exc_name} -- failure silenced entirely",
                        severity=Severity.HIGH,
                        fix=Fix.ENRICH,
                        detail="An empty except block is the code equivalent of a missing "
                               "bismillah: the expected signal is absent, and its absence "
                               "IS the diagnostic. At minimum, log the exception.",
                    ))
    return findings


def _check_generic_error_message(tree: ast.Module, path: str) -> List[Finding]:
    """MR-003/MR-006: Exception caught but error message discards all diagnostic info.

    This is A8 (Nifaq) in code: the message is fluent but carries no structural truth.
    """
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.name:
            # The exception is bound to a name -- check if it's ever used
            exc_name = node.name
            body_names = set()
            for child in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                if isinstance(child, ast.Name) and child.id == exc_name:
                    body_names.add(id(child))

            if not body_names:
                # Exception is caught, named, but never referenced in the handler
                findings.append(Finding(
                    rule="MR-003",
                    path=path,
                    line=node.lineno,
                    col=node.col_offset,
                    message=f"Exception bound as `{exc_name}` but never used -- diagnostic discarded",
                    severity=Severity.HIGH,
                    fix=Fix.ENRICH,
                    detail="The exception carries diagnostic information (type, message, traceback). "
                           "Catching it, naming it, and then ignoring it is nifaq: a surface that "
                           "looks like error handling while the substrate shows the error is swallowed. "
                           "Use the exception in your log message or re-raise it.",
                ))
    return findings


def _check_exception_swallowed(tree: ast.Module, path: str) -> List[Finding]:
    """MR-002: except Exception with only logging/pass, no re-raise."""
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            type_name = _handler_type_name(node)
            if type_name in ("Exception", "BaseException"):
                if not _handler_reraises(node) and len(node.body) <= 3:
                    # Short handler that catches broad exception without re-raising
                    if not any(isinstance(s, ast.Return) for s in node.body):
                        findings.append(Finding(
                            rule="MR-002",
                            path=path,
                            line=node.lineno,
                            col=node.col_offset,
                            message=f"`except {type_name}` without re-raise -- broad exception swallowed",
                            severity=Severity.HIGH,
                            fix=Fix.RECALIBRATE,
                            detail="Catching Exception or BaseException without re-raising claims "
                                   "to handle every possible failure mode. Either narrow the exception "
                                   "type to what you actually handle, or re-raise after logging.",
                        ))
    return findings


def _check_try_except_continue(tree: ast.Module, path: str) -> List[Finding]:
    """MR-007: try-except-continue in a loop -- errors silently skipped."""
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            if (len(node.body) == 1
                    and isinstance(node.body[0], ast.Continue)):
                findings.append(Finding(
                    rule="MR-007",
                    path=path,
                    line=node.lineno,
                    col=node.col_offset,
                    message="try/except with bare `continue` -- loop errors silently skipped",
                    severity=Severity.MEDIUM,
                    fix=Fix.ENRICH,
                    detail="Catching an exception and immediately continuing the loop "
                           "means every failure is invisible. At minimum, log the error "
                           "before continuing so the failure rate is observable.",
                ))
    return findings


# ── Helpers ──

def _handler_reraises(handler: ast.ExceptHandler) -> bool:
    """Check if an except handler contains a `raise` statement."""
    for node in ast.walk(ast.Module(body=handler.body, type_ignores=[])):
        if isinstance(node, ast.Raise):
            return True
    return False


def _handler_type_name(handler: ast.ExceptHandler) -> str:
    """Get the name of the caught exception type."""
    if handler.type is None:
        return "(bare except)"
    if isinstance(handler.type, ast.Name):
        return handler.type.id
    if isinstance(handler.type, ast.Attribute):
        return handler.type.attr
    if isinstance(handler.type, ast.Tuple):
        names = []
        for elt in handler.type.elts:
            if isinstance(elt, ast.Name):
                names.append(elt.id)
            elif isinstance(elt, ast.Attribute):
                names.append(elt.attr)
        return "(" + ", ".join(names) + ")"
    return "(complex)"


# Bismillah ir-Rahman ir-Rahim
