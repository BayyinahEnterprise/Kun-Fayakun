"""Return-None type checker for Python.

Closes Phase 1 Gap 1. Furqan's D24 (all-paths-return) treats
``return None`` as a satisfied return path, because the existence of
a ``ReturnStmt`` is what D24 inspects. The Python-level type mismatch
``-> str`` paired with ``return None`` is therefore invisible to D24.
This Phase 2 checker closes that gap directly.

What fires:

* a function declares a non-Optional return type AND the body
  contains ``return None`` or a bare ``return`` on some path.

What does not fire:

* the return type is ``Optional[X]`` or ``X | None`` (None is
  declared);
* the return type is ``-> None`` (None is the declared type);
* the function has no return-type annotation.
"""

from __future__ import annotations

from furqan.errors.marad import Marad
from furqan.parser.ast_nodes import (
    FunctionDef,
    IfStmt,
    Module,
    ReturnStmt,
    Statement,
    TypePath,
    UnionType,
)

# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def check_return_none(module: Module) -> list[Marad]:
    """Return one :class:`Marad` per function that declares a
    non-Optional return type but returns None on some path."""
    diagnostics: list[Marad] = []
    for fn in module.functions:
        if fn.return_type is None:
            continue
        if _allows_none(fn.return_type):
            continue
        if _has_none_return(fn.statements):
            diagnostics.append(_mismatch_marad(fn))
    return diagnostics


# ---------------------------------------------------------------------------
# Type predicates
# ---------------------------------------------------------------------------


def _allows_none(return_type: object) -> bool:
    """True iff the declared return type permits ``None``.

    The adapter translates ``Optional[X]`` and ``X | None`` to
    :class:`UnionType` with one arm whose ``base`` is ``"None"``.
    A bare ``-> None`` annotation translates to a
    :class:`TypePath` with ``base == "None"``.
    """
    if isinstance(return_type, UnionType):
        names = {return_type.left.base, return_type.right.base}
        return "None" in names
    if isinstance(return_type, TypePath):
        # Furqan AST attrs are Any-typed upstream (no py.typed); the
        # `Any == "None"` comparison is bool at runtime but Any to mypy.
        return return_type.base == "None"  # type: ignore[no-any-return]
    return False


def _type_name(return_type: object) -> str:
    """Best-effort short rendering of a return-type clause."""
    if isinstance(return_type, TypePath):
        return return_type.base  # type: ignore[no-any-return]
    if isinstance(return_type, UnionType):
        return f"{return_type.left.base} | {return_type.right.base}"
    return "Unknown"


def _suggested_fix(return_type: object) -> str:
    """Generate the ``minimal_fix`` string with awareness of
    malformed bare annotations.

    v0.3.4 fix for the round-7 review (Observation 3). When the
    user writes a bare ``Optional`` or bare ``Union`` (no
    subscript), the adapter translates the annotation as a plain
    ``TypePath`` whose ``base`` is the literal string ``"Optional"``
    or ``"Union"``. The pre-v0.3.4 inline f-string would then
    suggest ``Optional[Optional]`` as the minimal fix, which is
    not valid typing syntax (mypy rejects bare ``Optional`` with
    "Bare Optional is not allowed"). The real bug is the missing
    type argument, and the suggestion now names that explicitly.
    """
    name = _type_name(return_type)
    if name == "Optional":
        return (
            "Bare 'Optional' is not valid typing syntax. "
            "Use Optional[X] (e.g., Optional[str]) or X | None "
            "to declare an optional return type."
        )
    if name == "Union":
        # ``Union`` requires at least two arms. ``Union[X]`` is
        # well-formed but degenerate (typing folds it to ``X``);
        # the actionable suggestion is ``Union[X, None]`` because
        # the function is returning None and so wants an Optional.
        return (
            "Bare 'Union' is not valid typing syntax. "
            "Use Union[X, None] (e.g., Union[int, None]), "
            "Optional[X], or X | None to declare an optional "
            "return type."
        )
    return (
        f"Either change the return type to "
        f"Optional[{name}], or replace the None return "
        f"with a value of type {name}."
    )


# ---------------------------------------------------------------------------
# Body walking
# ---------------------------------------------------------------------------


def _has_none_return(statements: tuple[Statement, ...]) -> bool:
    """True iff any return statement in the (possibly nested) body
    returns ``None``.

    The adapter maps both ``return None`` and bare ``return`` (no
    value) to ``ReturnStmt(value=IdentExpr(name="__none__"))``.
    :class:`IdentExpr` exposes the marker on the ``name`` attribute
    (verified against furqan==0.10.1).
    """
    for stmt in statements:
        if isinstance(stmt, ReturnStmt):
            value = stmt.value
            if getattr(value, "name", None) == "__none__":
                return True
        if isinstance(stmt, IfStmt):
            if _has_none_return(stmt.body):
                return True
            if _has_none_return(stmt.else_body):
                return True
    return False


# ---------------------------------------------------------------------------
# Diagnostic construction
# ---------------------------------------------------------------------------


def _mismatch_marad(fn: FunctionDef) -> Marad:
    type_text = _type_name(fn.return_type)
    return Marad(
        primitive="return_none_mismatch",
        diagnosis=(
            f"Function '{fn.name}' at line {fn.span.line} declares "
            f"-> {type_text} but returns None on at least one path. "
            f"None is not compatible with the declared return type."
        ),
        location=fn.span,
        minimal_fix=_suggested_fix(fn.return_type),
        regression_check=(
            f"After the fix, re-run `furqan-lint check <file>` and "
            f"confirm function '{fn.name}' produces zero "
            f"return_none_mismatch marads."
        ),
    )
