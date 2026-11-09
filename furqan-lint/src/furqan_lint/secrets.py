# Bismillah ir-Rahman ir-Rahim
"""
SECRETS checks: hardcoded credentials and sensitive defaults.

Trust-boundary violations where secrets are embedded in source code
rather than injected from the environment at runtime.

Rules:
    TB-010  Hardcoded password string assignment
    TB-011  Password/secret/token in function default argument
    TB-012  Hardcoded /tmp path (predictable, world-writable)
    TB-013  Binding to 0.0.0.0 (all interfaces)
    TB-014  Flask/Django debug mode enabled in source
"""

from __future__ import annotations

import ast
import re
from typing import List

from furqan_lint.finding import Finding, Fix, Severity

# Patterns that suggest a variable holds a secret
_SECRET_NAMES = re.compile(
    r"(password|passwd|pwd|secret|token|api_key|apikey|"
    r"auth_key|authkey|private_key|access_key|secret_key)",
    re.IGNORECASE,
)

# String values that look like real passwords (not empty/placeholder)
_PLACEHOLDER = re.compile(
    r"^(|none|null|todo|fixme|changeme|xxx|placeholder|example|test|default)$",
    re.IGNORECASE,
)


def check_secrets(tree: ast.Module, path: str) -> List[Finding]:
    """Run all secrets/hardcoded-credential checks."""
    findings: List[Finding] = []
    findings.extend(_check_hardcoded_password(tree, path))
    findings.extend(_check_password_default(tree, path))
    findings.extend(_check_tmp_path(tree, path))
    findings.extend(_check_bind_all_interfaces(tree, path))
    findings.extend(_check_debug_mode(tree, path))
    return findings


def _check_hardcoded_password(tree: ast.Module, path: str) -> List[Finding]:
    """TB-010: Assignment to a variable whose name suggests a secret, with a string literal."""
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                name = _get_name(target)
                if name and _SECRET_NAMES.search(name):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        val = node.value.value
                        if val and not _PLACEHOLDER.match(val):
                            findings.append(Finding(
                                rule="TB-010",
                                path=path,
                                line=node.lineno,
                                col=node.col_offset,
                                message=f"Hardcoded secret in `{name}` -- move to environment variable",
                                severity=Severity.HIGH,
                                fix=Fix.RECALIBRATE,
                                detail="Secrets embedded in source code are readable by anyone "
                                       "with access to the repository. Use os.environ, a secrets "
                                       "manager, or a .env file excluded from version control.",
                            ))
    return findings


def _check_password_default(tree: ast.Module, path: str) -> List[Finding]:
    """TB-011: Function parameter with a secret-like name and a string default."""
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = node.args
            all_args = args.args + args.posonlyargs + args.kwonlyargs
            all_defaults = (
                [None] * (len(args.args) - len(args.defaults)) + args.defaults
                + [None] * (len(args.kwonlyargs) - len(args.kw_defaults)) + args.kw_defaults
            )
            # Realign -- only look at args that have defaults
            for arg_node, default in zip(all_args, all_defaults):
                if default is None:
                    continue
                if _SECRET_NAMES.search(arg_node.arg):
                    if isinstance(default, ast.Constant) and isinstance(default.value, str):
                        val = default.value
                        if val and not _PLACEHOLDER.match(val):
                            findings.append(Finding(
                                rule="TB-011",
                                path=path,
                                line=arg_node.lineno if hasattr(arg_node, 'lineno') else node.lineno,
                                col=arg_node.col_offset if hasattr(arg_node, 'col_offset') else node.col_offset,
                                message=f"Secret-like parameter `{arg_node.arg}` has a hardcoded default",
                                severity=Severity.HIGH,
                                fix=Fix.RECALIBRATE,
                                detail="A function parameter named like a secret should not have "
                                       "a hardcoded string default. Use None and require the caller "
                                       "to provide the value from a secure source.",
                            ))
    return findings


def _check_tmp_path(tree: ast.Module, path: str) -> List[Finding]:
    """TB-012: Hardcoded /tmp path."""
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            val = node.value
            if val.startswith("/tmp/") or val == "/tmp":
                findings.append(Finding(
                    rule="TB-012",
                    path=path,
                    line=node.lineno,
                    col=node.col_offset,
                    message="Hardcoded /tmp path -- predictable and world-writable",
                    severity=Severity.MEDIUM,
                    fix=Fix.RECALIBRATE,
                    detail="Use tempfile.mkdtemp() or tempfile.mkstemp() for a secure "
                           "temporary path. Hardcoded /tmp paths are predictable and "
                           "subject to symlink attacks on multi-user systems.",
                ))
    return findings


def _check_bind_all_interfaces(tree: ast.Module, path: str) -> List[Finding]:
    """TB-013: Binding to 0.0.0.0 (all interfaces)."""
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and node.value == "0.0.0.0":
            findings.append(Finding(
                rule="TB-013",
                path=path,
                line=node.lineno,
                col=node.col_offset,
                message="Binding to 0.0.0.0 exposes the service on all network interfaces",
                severity=Severity.MEDIUM,
                fix=Fix.RECALIBRATE,
                detail="Bind to 127.0.0.1 for local-only access, or use a "
                       "configuration variable so the bind address is explicit.",
            ))
    return findings


def _check_debug_mode(tree: ast.Module, path: str) -> List[Finding]:
    """TB-014: Flask/Django debug mode enabled in source."""
    findings: List[Finding] = []
    for node in ast.walk(tree):
        # app.run(debug=True) or DEBUG = True
        if isinstance(node, ast.keyword) and node.arg == "debug":
            if isinstance(node.value, ast.Constant) and node.value.value is True:
                findings.append(Finding(
                    rule="TB-014",
                    path=path,
                    line=node.lineno,
                    col=node.col_offset,
                    message="Debug mode enabled in source code -- exposes internals in production",
                    severity=Severity.HIGH,
                    fix=Fix.RECALIBRATE,
                    detail="Set debug mode from an environment variable, not in source. "
                           "Debug mode exposes stack traces, allows code execution via "
                           "the debugger, and leaks configuration details.",
                ))
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "DEBUG":
                    if isinstance(node.value, ast.Constant) and node.value.value is True:
                        findings.append(Finding(
                            rule="TB-014",
                            path=path,
                            line=node.lineno,
                            col=node.col_offset,
                            message="DEBUG = True in source code",
                            severity=Severity.HIGH,
                            fix=Fix.RECALIBRATE,
                            detail="Set DEBUG from an environment variable. "
                                   "Hardcoded True in source risks deploying with debug on.",
                        ))
    return findings


def _get_name(node: ast.expr) -> str | None:
    """Extract a simple name from an assignment target."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


# Bismillah ir-Rahman ir-Rahim
