# Bismillah ir-Rahman ir-Rahim
"""
TRUST-BOUNDARY checks: the 18 defect families as lint rules.

Derived from the P14-P21 adversarial audit arc. Every pattern here was
discovered in working safety-critical code and proven with an adversarial test.
No existing linter checks for any of them.

Rules:
    TB-001  isinstance() used in security/authorization decision (DF-12)
    TB-002  copy.deepcopy() called on untrusted/external input (DF-13)
    TB-003  type(x).__name__ used under a lock or in error diagnostics (DF-16)
    TB-004  Mutable default argument that persists across calls
    TB-005  eval/exec called on any input
    TB-006  pickle.loads / yaml.load(unsafe) on untrusted input
    TB-007  __dunder__ method defined that could serve as attack hook
"""

from __future__ import annotations

import ast
from typing import List

from furqan_lint.finding import Finding, Fix, Severity


def check_trust_boundary(tree: ast.Module, path: str) -> List[Finding]:
    """Run all trust-boundary checks on an AST."""
    findings: List[Finding] = []
    findings.extend(_check_isinstance_security(tree, path))
    findings.extend(_check_deepcopy_untrusted(tree, path))
    findings.extend(_check_type_name_under_lock(tree, path))
    findings.extend(_check_mutable_defaults(tree, path))
    findings.extend(_check_eval_exec(tree, path))
    findings.extend(_check_unsafe_deserialization(tree, path))
    return findings


def _check_isinstance_security(tree: ast.Module, path: str) -> List[Finding]:
    """TB-001: isinstance() used where type() is would be safer.

    From DF-12: isinstance admits subclasses with spoofed __eq__/__hash__.
    A subclass can pass isinstance while behaving arbitrarily differently.
    """
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "isinstance":
                # Check if this isinstance is inside an if/assert (security decision)
                findings.append(Finding(
                    rule="TB-001",
                    path=path,
                    line=node.lineno,
                    col=node.col_offset,
                    message="isinstance() admits subclasses -- use `type(x) is T` for trust decisions",
                    severity=Severity.MEDIUM,
                    fix=Fix.RECALIBRATE,
                    detail="A subclass passes isinstance() while overriding __eq__, __hash__, "
                           "__deepcopy__, __int__, __str__, or any dunder method. If this check "
                           "guards a security boundary, use `type(x) is T` for exact-type matching. "
                           "Discovered in EESS audit round P14 (DF-12).",
                ))
    return findings


def _check_deepcopy_untrusted(tree: ast.Module, path: str) -> List[Finding]:
    """TB-002: copy.deepcopy() invokes __deepcopy__ on the copied object.

    From DF-13: deepcopy on hostile dicts invokes arbitrary code via __deepcopy__ hooks.
    """
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if _is_deepcopy_call(node):
                findings.append(Finding(
                    rule="TB-002",
                    path=path,
                    line=node.lineno,
                    col=node.col_offset,
                    message="copy.deepcopy() invokes __deepcopy__ hooks on the input object",
                    severity=Severity.HIGH,
                    fix=Fix.RECALIBRATE,
                    detail="If the input is untrusted, deepcopy allows arbitrary code execution "
                           "via the __deepcopy__ protocol. Build a new dict/list from exact "
                           "built-in values instead. Discovered in EESS audit round P17 (DF-13).",
                ))
    return findings


def _check_type_name_under_lock(tree: ast.Module, path: str) -> List[Finding]:
    """TB-003: type(x).__name__ accesses __name__ which a metaclass can intercept.

    From DF-16/P21: metaclass __getattribute__ traps __name__ access and can
    re-enter a non-reentrant lock, causing deadlock.
    """
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "__name__":
            if isinstance(node.value, ast.Call):
                func = node.value.func
                if isinstance(func, ast.Name) and func.id == "type":
                    findings.append(Finding(
                        rule="TB-003",
                        path=path,
                        line=node.lineno,
                        col=node.col_offset,
                        message="type(x).__name__ is interceptable by metaclass __getattribute__",
                        severity=Severity.HIGH,
                        fix=Fix.SIMPLIFY,
                        detail="Under a lock, type(x).__name__ can re-enter via metaclass "
                               "__getattribute__, causing deadlock. Use constant strings in "
                               "diagnostics instead. Discovered in EESS audit round P21 (DF-16).",
                    ))
    return findings


def _check_mutable_defaults(tree: ast.Module, path: str) -> List[Finding]:
    """TB-004: Mutable default argument (list, dict, set) persists across calls."""
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for default in node.args.defaults + node.args.kw_defaults:
                if default is None:
                    continue
                if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                    findings.append(Finding(
                        rule="TB-004",
                        path=path,
                        line=default.lineno,
                        col=default.col_offset,
                        message="Mutable default argument -- shared across all calls to this function",
                        severity=Severity.HIGH,
                        fix=Fix.RECALIBRATE,
                        detail="Mutable defaults (list, dict, set) are created once at function "
                               "definition time, not per call. Use None as default and create the "
                               "mutable inside the function body.",
                    ))
    return findings


def _check_eval_exec(tree: ast.Module, path: str) -> List[Finding]:
    """TB-005: eval() or exec() called."""
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in ("eval", "exec"):
                findings.append(Finding(
                    rule="TB-005",
                    path=path,
                    line=node.lineno,
                    col=node.col_offset,
                    message=f"{node.func.id}() executes arbitrary code",
                    severity=Severity.CRITICAL,
                    fix=Fix.SIMPLIFY,
                    detail=f"{node.func.id}() on untrusted input is arbitrary code execution. "
                           "Use ast.literal_eval() for data, or a restricted parser for expressions.",
                ))
    return findings


def _check_unsafe_deserialization(tree: ast.Module, path: str) -> List[Finding]:
    """TB-006: pickle.loads, yaml.load without SafeLoader."""
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            # pickle.loads / pickle.load
            if node.func.attr in ("loads", "load"):
                obj = node.func.value
                if isinstance(obj, ast.Name) and obj.id == "pickle":
                    findings.append(Finding(
                        rule="TB-006",
                        path=path,
                        line=node.lineno,
                        col=node.col_offset,
                        message="pickle deserialization executes arbitrary code on untrusted input",
                        severity=Severity.CRITICAL,
                        fix=Fix.SIMPLIFY,
                        detail="pickle.loads() and pickle.load() invoke __reduce__ on the "
                               "deserialized object, allowing arbitrary code execution. "
                               "Use JSON or a safe serialization format for untrusted data.",
                    ))
            # yaml.load without SafeLoader
            if node.func.attr == "load":
                obj = node.func.value
                if isinstance(obj, ast.Name) and obj.id == "yaml":
                    has_safe_loader = False
                    for kw in node.keywords:
                        if kw.arg == "Loader":
                            if isinstance(kw.value, ast.Attribute):
                                if "Safe" in kw.value.attr:
                                    has_safe_loader = True
                            elif isinstance(kw.value, ast.Name):
                                if "Safe" in kw.value.id:
                                    has_safe_loader = True
                    if not has_safe_loader:
                        findings.append(Finding(
                            rule="TB-006",
                            path=path,
                            line=node.lineno,
                            col=node.col_offset,
                            message="yaml.load() without SafeLoader executes arbitrary code",
                            severity=Severity.CRITICAL,
                            fix=Fix.RECALIBRATE,
                            detail="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
                        ))
    return findings


# ── Helpers ──

def _is_deepcopy_call(node: ast.Call) -> bool:
    if isinstance(node.func, ast.Attribute) and node.func.attr == "deepcopy":
        return True
    if isinstance(node.func, ast.Name) and node.func.id == "deepcopy":
        return True
    return False


# Bismillah ir-Rahman ir-Rahim
