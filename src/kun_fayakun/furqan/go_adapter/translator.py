"""Translate goast JSON output into a Furqan ``Module``.

The translator (current as of v0.8.0) supports D24 (all-paths-return) and D11
(status-coverage with the Go ``(T, error)`` firing shape). The
translation is intentionally lossy: it preserves enough
control-flow shape and return-type structure for those two
checkers and discards everything else (interface dispatch,
method receivers, generic parameters, etc.).

Return-type translation rules
=============================

The goast binary emits ``return_type_names`` as an ordered list
(last is conventional ``error`` position per Go convention).
v0.8.0 maps:

* 0 elements (``func f()`` no return) -> ``return_type = None``.
* 1 element (``func f() T``) -> ``return_type = TypePath(base=T)``.
* 2 elements where last is ``"error"`` (``func f() (T, error)``) ->
  ``return_type = UnionType(left=TypePath(T), right=TypePath("error"))``.
  The translator places ``error`` in the right arm by convention;
  the predicate ``_is_error_return`` is symmetric across arms so
  a future translator change that reorders does not silently
  break D11.
* 2 elements where last is NOT ``"error"`` (``func f() (T, U)``) ->
  ``return_type = TypePath(base="(T, U)")`` (treated as opaque
  non-may-fail tuple per locked decision 4).
* 3+ elements (``func f() (T, T, error)`` etc.) -> ``return_type
  = TypePath(base="<multi-return>")`` (out of scope for v0.8.x
  per locked decision 4; documented limit pinned by
  test_go_three_or_more_element_return_documented_limit).

Body translation rules
======================

* ``return`` statements become ``ReturnStmt`` with one
  ``IdentExpr`` per expression. Each expression's text is the
  marker name; ``"nil"`` translates to
  ``IdentExpr(name="__opaque__")`` per locked decision 5 (NOT
  ``"__none__"`` to avoid accidental cross-language firing of
  the Python-only ``check_return_none`` checker).
* ``if`` blocks become ``IfStmt`` with body and else_body.
* ``assign`` statements with an ``rhs_call`` contribute a
  ``CallRef`` to the function's ``calls`` tuple. The LHS is
  recorded so the runner can detect error-discard via ``_``.
* ``opaque`` statements (for/switch/select/defer/etc.) are
  translated as opaque markers wrapped in
  ``IfStmt(condition=opaque, body=(), else_body=())`` to model
  "may run zero or N times". A future phase may extend.
"""

from __future__ import annotations

from typing import Any

from furqan.parser.ast_nodes import (
    BismillahBlock,
    CallRef,
    FunctionDef,
    IdentExpr,
    IfStmt,
    Module,
    ReturnStmt,
    SourceSpan,
    TypePath,
    UnionType,
)


def translate(data: dict[str, Any], filename: str | None = None) -> Module:
    """Translate goast JSON output into a Furqan ``Module``.

    ``data`` is the dict returned by
    ``furqan_lint.go_adapter.parse_file``. ``filename`` overrides
    the module's source path for diagnostic display; if absent,
    the JSON's ``filename`` key is used.
    """
    source_path = filename or data.get("filename", "<unknown>")
    package_name = data.get("package", "main")
    span = _span(source_path, 1, 0)

    bismillah = BismillahBlock(
        name=package_name,
        authority=("go_module",),
        serves=(("structural_honesty",),),
        scope=(package_name,),
        not_scope=(),
        span=span,
        alias_used="bismillah",
    )

    functions: list[FunctionDef] = []
    for fn_data in data.get("functions", []):
        functions.append(_translate_function(fn_data, source_path))

    return Module(
        bismillah=bismillah,
        functions=tuple(functions),
        source_path=source_path,
        compound_types=(),
    )


def _translate_function(fn_data: dict[str, Any], source_path: str) -> FunctionDef:
    name = fn_data.get("name", "<anonymous>")
    line = fn_data.get("line", 1)
    col = fn_data.get("col", 0)
    span = _span(source_path, line, col)

    rt_list = _translate_return_types_or_empty(fn_data.get("return_type_names", []), span)
    return_type: TypePath | UnionType | None = rt_list[0] if rt_list else None

    body_data = fn_data.get("body_statements", [])
    statements: list[Any] = []
    calls: list[CallRef] = []
    for stmt_data in body_data:
        translated = _translate_statement(stmt_data, source_path)
        statements.extend(translated)
        # Extract calls from this statement's rhs_call (assign)
        # and recursively from nested if bodies.
        _extract_calls_into(stmt_data, source_path, calls)

    return FunctionDef(
        name=name,
        calls=tuple(calls),
        span=span,
        params=(),
        return_type=return_type,
        accesses=(),
        statements=tuple(statements),
    )


def _translate_return_types_or_empty(
    type_names: list[str], span: SourceSpan
) -> list[TypePath | UnionType]:
    """Translate the ordered list of return-type names per the
    translator's rules in this module's docstring.

    Returns a single-element list containing the translated type,
    or an empty list for 0-element returns. The list shape (vs.
    ``TypePath | UnionType | None``) keeps the optional out of
    the function signature so D11 does not see a may-fail
    producer (the absence-of-return-type is a structural
    distinction, not a may-fail status). The caller does
    ``rt_list[0] if rt_list else None`` to recover the optional
    at the assignment boundary, matching the Rust adapter's
    ``_function_return_type_or_empty`` shape.

    Mapping:
        []                 -> 0-element returns;
        [TypePath]         -> 1-element OR 2-element-non-error;
        [UnionType]        -> 2-element-with-error-last;
        [TypePath("<multi-return>")] -> 3+-element (documented limit).
    """
    if not type_names:
        return []
    if len(type_names) == 1:
        return [TypePath(base=type_names[0], layer=None, span=span)]
    if len(type_names) == 2:
        if type_names[-1] == "error":
            return [
                UnionType(
                    left=TypePath(base=type_names[0], layer=None, span=span),
                    right=TypePath(base="error", layer=None, span=span),
                    span=span,
                )
            ]
        # Two-element non-error tuple: opaque per locked decision 4.
        return [
            TypePath(
                base=f"({', '.join(type_names)})",
                layer=None,
                span=span,
            )
        ]
    # Three-or-more-element returns: out of scope for v0.8.x.
    # Documented limit pinned by
    # test_go_three_or_more_element_return_documented_limit.
    return [TypePath(base="<multi-return>", layer=None, span=span)]


def _translate_statement(stmt_data: dict[str, Any], source_path: str) -> list[Any]:
    """Translate one body_statement entry to zero or more Furqan
    statements. Recursive on if-blocks.
    """
    stype = stmt_data.get("type", "opaque")
    line = stmt_data.get("line", 1)
    span = _span(source_path, line, 0)

    if stype == "return":
        # Each expression becomes its own ReturnStmt? No - one
        # ReturnStmt per return-statement, with the value being
        # the first expression's marker. For multi-value returns,
        # we collapse to a single ReturnStmt; D24 only checks
        # presence.
        exprs = stmt_data.get("expressions", [])
        value = _opaque_marker(span) if not exprs else _expression_marker(exprs[0], span)
        return [ReturnStmt(value=value, span=span)]

    if stype == "if":
        body_data = stmt_data.get("body", [])
        else_data = stmt_data.get("else_body", [])
        body_stmts: list[Any] = []
        for s in body_data:
            body_stmts.extend(_translate_statement(s, source_path))
        else_stmts: list[Any] = []
        for s in else_data:
            else_stmts.extend(_translate_statement(s, source_path))
        return [
            IfStmt(
                condition=_opaque_marker(span),
                body=tuple(body_stmts),
                span=span,
                else_body=tuple(else_stmts),
            )
        ]

    if stype == "assign":
        # An assignment is not itself a control-flow statement;
        # the call (if any) is captured separately into
        # FunctionDef.calls. The assign as a body statement
        # contributes nothing structural to D24.
        return []

    # Opaque statements (for, switch, select, defer, etc.) wrap
    # as a may-runs-zero-or-N-times marker so D24 treats them as
    # not-guaranteed-to-return.
    return [
        IfStmt(
            condition=_opaque_marker(span),
            body=(),
            span=span,
            else_body=(),
        )
    ]


def _extract_calls_into(
    stmt_data: dict[str, Any],
    source_path: str,
    calls: list[CallRef],
) -> None:
    """Walk a statement tree and append CallRef entries to
    ``calls`` for each rhs_call found. Used by D11.

    Recursive on if-blocks. Assigns are the canonical site for
    rhs_call; bare expression statements (which goast surfaces
    as assigns with empty LHS) are also covered.
    """
    stype = stmt_data.get("type", "opaque")
    if stype == "assign":
        rhs_call = stmt_data.get("rhs_call")
        if rhs_call:
            line = rhs_call.get("line", 1)
            span = _span(source_path, line, 0)
            calls.append(
                CallRef(
                    path=(rhs_call.get("name", "<unknown>"),),
                    span=span,
                )
            )
    elif stype == "if":
        for s in stmt_data.get("body", []):
            _extract_calls_into(s, source_path, calls)
        for s in stmt_data.get("else_body", []):
            _extract_calls_into(s, source_path, calls)


def _expression_marker(expr_text: str, span: SourceSpan) -> IdentExpr:
    """Translate a return expression's text to an IdentExpr marker.

    ``nil`` becomes ``IdentExpr(name="__opaque__")`` per locked
    decision 5; everything else also becomes ``__opaque__``.
    The marker name distinction (``__none__`` vs ``__opaque__``)
    is reserved for Python-specific semantics and the v0.8.0 Go
    adapter explicitly does not emit ``__none__`` to avoid
    accidental firing of ``check_return_none`` on idiomatic Go
    ``(T, error)`` returns.
    """
    return _opaque_marker(span)


def _opaque_marker(span: SourceSpan) -> IdentExpr:
    """The opaque-value marker. D24 inspects structure only;
    expression values are deliberately not preserved."""
    return IdentExpr(name="__opaque__", span=span)


def _span(filename: str, line: int, col: int) -> SourceSpan:
    return SourceSpan(file=filename, line=line, column=col)
