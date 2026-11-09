# Bismillah ir-Rahman ir-Rahim
"""
SCAN-INCOMPLETE checks: what has not been examined cannot be trusted.

The Furqan principle: every claim of completeness must be verifiable.
Code that uses catch-all types, silences warnings, or leaves TODOs
is declaring "I have not finished looking."

Rules:
    SI-001  `Any` type annotation -- disables type checking at that boundary
    SI-002  `# type: ignore` without specific error code
    SI-003  `# noqa` without specific rule code
    SI-004  TODO/FIXME/HACK/XXX older than 90 days (stale incomplete scan)
    SI-005  `**kwargs` passed through without validation or documentation
    SI-006  `assert` used for runtime validation (stripped in -O mode)
    SI-007  `hasattr` on a class attribute -- hides AttributeError
"""

from __future__ import annotations

import ast
import re
from typing import List

from furqan_lint.finding import Finding, Fix, Severity


def check_scan_incomplete(source: str, tree: ast.Module, path: str) -> List[Finding]:
    """Run all SCAN-INCOMPLETE checks.

    Unlike other check families, this one needs the raw source text
    in addition to the AST, because some patterns (type: ignore, noqa,
    TODO comments) live in comments that the AST discards.
    """
    findings: List[Finding] = []
    findings.extend(_check_any_annotation(tree, path))
    findings.extend(_check_type_ignore_blanket(source, path))
    findings.extend(_check_noqa_blanket(source, path))
    findings.extend(_check_stale_todo(source, path))
    findings.extend(_check_kwargs_passthrough(tree, path))
    findings.extend(_check_assert_validation(tree, path))
    findings.extend(_check_hasattr_class(tree, path))
    return findings


def _check_any_annotation(tree: ast.Module, path: str) -> List[Finding]:
    """SI-001: `Any` used as a type annotation."""
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == "Any":
            # Check if this is in an annotation context
            # (We flag all uses of the name `Any` -- if it's imported from typing,
            # it's almost certainly being used as a type annotation)
            findings.append(Finding(
                rule="SI-001",
                path=path,
                line=node.lineno,
                col=node.col_offset,
                message="`Any` type annotation disables type checking at this boundary",
                severity=Severity.MEDIUM,
                fix=Fix.ENRICH,
                detail="Every `Any` annotation is an incomplete scan: the type checker "
                       "stops examining values that flow through it. Replace with a "
                       "concrete type, a Protocol, a TypeVar, or Union of the actual types.",
            ))
    return findings


def _check_type_ignore_blanket(source: str, path: str) -> List[Finding]:
    """SI-002: `# type: ignore` without a specific error code."""
    findings: List[Finding] = []
    pattern = re.compile(r"#\s*type:\s*ignore(?!\[)")
    for lineno, line in enumerate(source.splitlines(), 1):
        match = pattern.search(line)
        if match:
            findings.append(Finding(
                rule="SI-002",
                path=path,
                line=lineno,
                col=match.start(),
                message="Blanket `# type: ignore` -- specify the error code being suppressed",
                severity=Severity.LOW,
                fix=Fix.RECALIBRATE,
                detail="Use `# type: ignore[specific-error]` so the suppression is auditable. "
                       "A blanket ignore silences every type error on the line, including "
                       "ones you haven't seen yet.",
            ))
    return findings


def _check_noqa_blanket(source: str, path: str) -> List[Finding]:
    """SI-003: `# noqa` without a specific rule code."""
    findings: List[Finding] = []
    pattern = re.compile(r"#\s*noqa(?!:|\s*:)")
    for lineno, line in enumerate(source.splitlines(), 1):
        match = pattern.search(line)
        if match:
            # Make sure it's not `# noqa: E501` (which IS specific)
            rest = line[match.end():]
            if not rest.strip().startswith(":"):
                findings.append(Finding(
                    rule="SI-003",
                    path=path,
                    line=lineno,
                    col=match.start(),
                    message="Blanket `# noqa` -- specify which rule is being suppressed",
                    severity=Severity.LOW,
                    fix=Fix.RECALIBRATE,
                    detail="Use `# noqa: E501` (or whatever code applies) so the suppression "
                           "is auditable. A blanket noqa silences every linter warning on the "
                           "line, including ones you haven't seen yet.",
                ))
    return findings


def _check_stale_todo(source: str, path: str) -> List[Finding]:
    """SI-004: TODO/FIXME/HACK/XXX comments."""
    findings: List[Finding] = []
    pattern = re.compile(r"#\s*(TODO|FIXME|HACK|XXX)\b", re.IGNORECASE)
    for lineno, line in enumerate(source.splitlines(), 1):
        match = pattern.search(line)
        if match:
            tag = match.group(1).upper()
            findings.append(Finding(
                rule="SI-004",
                path=path,
                line=lineno,
                col=match.start(),
                message=f"`{tag}` comment -- an acknowledged incomplete scan",
                severity=Severity.LOW,
                fix=Fix.ENRICH,
                detail=f"A {tag} comment is an honest admission that the scan is incomplete. "
                       "Either complete the work or document why it remains open. "
                       "Stale TODOs accumulate until the codebase cannot distinguish "
                       "between 'not yet done' and 'will never be done'.",
            ))
    return findings


def _check_kwargs_passthrough(tree: ast.Module, path: str) -> List[Finding]:
    """SI-005: **kwargs accepted and passed through without validation."""
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.args.kwarg is None:
                continue
            kwarg_name = node.args.kwarg.arg
            # Check if kwargs is used in the body only as **kwargs in another call
            passthrough_name_ids: set = set()
            uses_validated = False
            uses_passthrough = False
            body_module = ast.Module(body=node.body, type_ignores=[])

            # First pass: find all **kwargs passthrough uses
            for child in ast.walk(body_module):
                if isinstance(child, ast.keyword) and child.arg is None:
                    if isinstance(child.value, ast.Name) and child.value.id == kwarg_name:
                        uses_passthrough = True
                        passthrough_name_ids.add(id(child.value))

            # Second pass: check for direct uses that are NOT the passthrough
            for child in ast.walk(body_module):
                if isinstance(child, ast.Name) and child.id == kwarg_name:
                    if id(child) not in passthrough_name_ids:
                        uses_validated = True

            if uses_passthrough and not uses_validated:
                findings.append(Finding(
                    rule="SI-005",
                    path=path,
                    line=node.lineno,
                    col=node.col_offset,
                    message=f"`**{kwarg_name}` accepted and passed through without validation",
                    severity=Severity.MEDIUM,
                    fix=Fix.RECALIBRATE,
                    detail="Accepting **kwargs and passing them through unexamined means this "
                           "function's interface is unbounded -- any keyword argument is accepted "
                           "and forwarded silently. Either document the expected keys, validate "
                           "them, or use explicit parameters.",
                ))
    return findings


def _check_assert_validation(tree: ast.Module, path: str) -> List[Finding]:
    """SI-006: `assert` used for what looks like runtime validation."""
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assert):
            # Heuristic: assert with isinstance, assert with comparison to input
            test = node.test
            is_isinstance = (isinstance(test, ast.Call) and
                             isinstance(test.func, ast.Name) and
                             test.func.id == "isinstance")
            is_comparison = isinstance(test, ast.Compare)

            if is_isinstance or is_comparison:
                findings.append(Finding(
                    rule="SI-006",
                    path=path,
                    line=node.lineno,
                    col=node.col_offset,
                    message="`assert` used for runtime validation -- stripped by `python -O`",
                    severity=Severity.HIGH,
                    fix=Fix.RECALIBRATE,
                    detail="assert statements are removed when Python runs with -O or -OO. "
                           "If this check is a runtime validation (not a development-only "
                           "invariant), use `if not ...: raise ValueError(...)` instead.",
                ))
    return findings


def _check_hasattr_class(tree: ast.Module, path: str) -> List[Finding]:
    """SI-007: hasattr() hides AttributeError, masking real bugs."""
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "hasattr"):
            # hasattr swallows AttributeError -- it's a silent scan skip
            findings.append(Finding(
                rule="SI-007",
                path=path,
                line=node.lineno,
                col=node.col_offset,
                message="`hasattr()` swallows AttributeError -- may hide real bugs",
                severity=Severity.LOW,
                fix=Fix.RECALIBRATE,
                detail="hasattr() works by calling getattr() and catching AttributeError. "
                       "This hides errors in __getattr__ and property implementations. "
                       "Use `getattr(obj, name, sentinel)` or an explicit try/except "
                       "for the specific attribute.",
            ))
    return findings


# Bismillah ir-Rahman ir-Rahim
