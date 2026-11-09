# Bismillah ir-Rahman ir-Rahim
"""
TRUST-BOUNDARY checks: patterns at boundaries where type assumptions
can be violated.

Rules:
    TB-001  isinstance() admits subclasses that may override behavior
    TB-002  copy.deepcopy() invokes __deepcopy__ hooks on the input
    TB-003  type(x).__name__ interceptable by metaclass __getattribute__
    TB-004  Mutable default argument that persists across calls
    TB-005  eval/exec called on any input
    TB-006  pickle.loads / yaml.load(unsafe) deserialization
"""

from __future__ import annotations

import ast
from typing import List

from kun_fayakun.furqan.checks.finding import Finding, Fix, Severity


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
    """TB-001: isinstance() admits subclasses that may override behavior.

    A subclass can pass isinstance while overriding any dunder method.
    This is informational -- most isinstance calls are ordinary type
    dispatch, not security decisions. Severity LOW.
    """
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "isinstance":
                findings.append(Finding(
                    rule="TB-001",
                    path=path,
                    line=node.lineno,
                    col=node.col_offset,
                    message="isinstance() admits subclasses that may override behavior",
                    severity=Severity.LOW,
                    fix=Fix.RECALIBRATE,
                    detail="A subclass passes isinstance() while overriding __eq__, __hash__, "
                           "or any dunder method. In most code this is fine -- isinstance is "
                           "the correct way to do type dispatch. Review only if this check "
                           "guards a trust boundary where exact type identity matters.",
                ))
    return findings


def _check_deepcopy_untrusted(tree: ast.Module, path: str) -> List[Finding]:
    """TB-002: copy.deepcopy() invokes __deepcopy__ hooks on the input.

    Informational: most deepcopy calls are safe. The risk exists only
    when the copied object could have a hostile __deepcopy__ method.
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
                    message="deepcopy() invokes __deepcopy__ hooks on the input object",
                    severity=Severity.LOW,
                    fix=Fix.RECALIBRATE,
                    detail="deepcopy calls __deepcopy__ on the input, which a hostile object "
                           "can override. In most code this is safe. Review only if the input "
                           "crosses a trust boundary (user-supplied, deserialized, external).",
                ))
    return findings


def _check_type_name_under_lock(tree: ast.Module, path: str) -> List[Finding]:
    """TB-003: type(x).__name__ is interceptable by metaclass __getattribute__.

    Informational: in ordinary code this is fine. The risk exists only
    when used under a non-reentrant lock with objects that have custom
    metaclasses. We cannot detect the lock context statically.
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
                        message="type(x).__name__ interceptable by metaclass __getattribute__",
                        severity=Severity.LOW,
                        fix=Fix.SIMPLIFY,
                        detail="A metaclass can override __getattribute__ and intercept the "
                               "__name__ access. In most code this is harmless. Review if "
                               "used under a lock or with objects of unknown provenance.",
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
