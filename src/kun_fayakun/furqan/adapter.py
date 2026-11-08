"""Translate a Python ``ast.Module`` into a Furqan ``Module``.

The adapter is structural, not semantic. It carries shape across the
language boundary so Furqan's structural-honesty checkers can run on
Python source without modification. Two translation contracts:

1. The Python module yields one Furqan ``Module`` with a synthetic
   ``BismillahBlock``. The Bismillah is a placeholder; D24 and D11 do
   not introspect it. Phase 2 may derive its fields from a
   ``__furqan_serves__`` module variable.
2. Every Python expression collapses to one of two opaque
   ``IdentExpr`` markers: ``__none__`` (the literal ``None``) or
   ``__opaque__`` (everything else). D24 only inspects whether a
   ``ReturnStmt`` exists on a path; D11 only inspects call sites and
   declared return types. Neither needs real expression structure.
"""

from __future__ import annotations

import ast
from pathlib import Path

from furqan.parser.ast_nodes import (
    BismillahBlock,
    CallRef,
    CompoundTypeDef,
    FunctionDef,
    IdentExpr,
    IfStmt,
    LayerBlock,
    Module,
    ParamDecl,
    ReturnStmt,
    SourceSpan,
    TypePath,
    UnionType,
)

# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def translate_file(path: Path) -> Module:
    """Parse a Python file at ``path`` and return a Furqan ``Module``."""
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    return _translate_module(tree, str(path))


def translate_source(source: str, filename: str = "<string>") -> Module:
    """Parse a Python source string and return a Furqan ``Module``."""
    tree = ast.parse(source, filename=filename)
    return _translate_module(tree, filename)


def translate_tree(tree: ast.Module, filename: str) -> Module:
    """Translate a pre-parsed ``ast.Module`` into a Furqan ``Module``.

    Lets a caller (e.g. the CLI) parse the source once and reuse the
    raw AST for both the Furqan translation and Python-native
    checkers (R3 zero-return, which needs decorators that the
    translation does not preserve).
    """
    return _translate_module(tree, filename)


# ---------------------------------------------------------------------------
# Module translation
# ---------------------------------------------------------------------------


def _translate_module(tree: ast.Module, filename: str) -> Module:
    """Translate an ``ast.Module`` into a Furqan ``Module``.

    DEFECT 1 FIX: iterate ``tree.body`` only, not ``ast.walk``. Walking
    the whole tree would re-collect class methods as top-level
    functions and double-count nested function definitions. Methods
    are gathered explicitly inside the ``ClassDef`` branch below.
    """
    functions: list[FunctionDef] = []
    compound_types: list[CompoundTypeDef] = []

    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            functions.append(_translate_function(node, filename))
        elif isinstance(node, ast.ClassDef):
            compound_types.append(_translate_class(node, filename))
            # Class methods become top-level functions in the Furqan
            # Module. CompoundTypeDef has no methods field in the
            # AST, so this is the only place to put them.
            #
            # v0.3.2 fix (Finding 3): descend recursively through
            # nested ``ClassDef`` bodies so methods of
            # ``Outer.Inner``, ``Outer.Inner.Innermost``, etc. are
            # also collected. Pre-v0.3.2 the descent stopped at one
            # level and methods of nested classes were silently
            # dropped, producing false negatives on D24 and
            # ``return_none_mismatch`` for any nested-class method.
            #
            # Methods of classes defined inside a function body are
            # NOT collected: that case is pinned as a documented
            # limitation (private local-class scope).
            functions.extend(_collect_class_methods(node, filename))

    module_name = Path(filename).stem
    sp = _span(filename, 1, 0)

    bismillah = BismillahBlock(
        name=module_name,
        authority=("python_module",),
        serves=(("structural_honesty",),),
        scope=(module_name,),
        not_scope=(),
        span=sp,
        alias_used="bismillah",
    )

    return Module(
        bismillah=bismillah,
        functions=tuple(functions),
        source_path=filename,
        compound_types=tuple(compound_types),
    )


def _collect_class_methods(
    class_node: ast.ClassDef,
    filename: str,
) -> list[FunctionDef]:
    """Yield translated ``FunctionDef`` nodes for every method in
    ``class_node`` and recursively in any nested classes.

    v0.3.2 fix for Finding 3 of the round-5 review. Pre-v0.3.2,
    ``_translate_module`` walked one level into a class body and
    only collected ``FunctionDef``/``AsyncFunctionDef`` children.
    Methods of an inner class (e.g., ``Outer.Inner.method``) were
    silently dropped, so D24 and ``return_none_mismatch`` couldn't
    fire on them. The recursive descent here closes that gap.

    Lambdas, comprehensions, and any non-class non-function children
    are ignored. Nested ``ClassDef`` inside a function body is NOT
    walked: that path is reached from inside ``_translate_function``,
    which deliberately scopes call extraction to the function's
    direct body and leaves locally-scoped classes invisible. Pinned
    as a documented limitation.
    """
    methods: list[FunctionDef] = []
    for child in class_node.body:
        if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
            methods.append(_translate_function(child, filename))
        elif isinstance(child, ast.ClassDef):
            methods.extend(_collect_class_methods(child, filename))
    return methods


# ---------------------------------------------------------------------------
# Class translation
# ---------------------------------------------------------------------------


def _translate_class(node: ast.ClassDef, filename: str) -> CompoundTypeDef:
    """Translate a Python class to a ``CompoundTypeDef``.

    Phase 1 does not separate zahir from batin. Both layers are empty
    ``LayerBlock`` shells. The class name is captured so a future
    ring-close R1 type-resolution pass can find it.
    """
    sp = _span(filename, node.lineno, node.col_offset)
    return CompoundTypeDef(
        name=node.name,
        zahir=LayerBlock(
            layer="zahir",
            fields=(),
            span=sp,
            alias_used="zahir",
        ),
        batin=LayerBlock(
            layer="batin",
            fields=(),
            span=sp,
            alias_used="batin",
        ),
        span=sp,
    )


# ---------------------------------------------------------------------------
# Function translation
# ---------------------------------------------------------------------------


def _translate_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    filename: str,
) -> FunctionDef:
    params: list[ParamDecl] = []
    for arg in node.args.args:
        type_path = _translate_annotation(arg.annotation, filename)
        params.append(
            ParamDecl(
                name=arg.arg,
                type_path=type_path,
                span=_span(filename, arg.lineno, arg.col_offset),
            )
        )

    # v1.0.1: generators and ``-> None`` procedures carry no
    # value-return contract. A generator's annotation describes what it
    # yields, and falling off its end (or a bare ``return``) just stops
    # iteration; a ``-> None`` procedure may fall through or return
    # early by design. Translating either with a return type made D24
    # report "missing return" and D11 report "status collapse" on
    # correct code, so both are translated as having no return-type
    # contract (the same treatment as an unannotated function).
    return_type = None
    if (
        node.returns is not None
        and not _is_generator(node)
        and not _is_none_annotation(node.returns)
    ):
        return_type = _translate_return_annotation(node.returns, filename)

    # v1.0.1: an unconditional exit (``raise``, ``sys.exit(...)``,
    # ``os._exit(...)``, ``os.abort()``) is a terminal path, not a
    # fall-through. It is modelled as terminal ONLY in functions that
    # contain at least one explicit ``return``: functions with zero
    # returns stay entirely in R3's (zero_return) jurisdiction, so
    # their diagnostics are unchanged and never double-reported.
    statements = _translate_body(
        node.body,
        filename,
        exit_is_terminal=_contains_return(node),
    )
    calls = _extract_calls(node, filename)

    return FunctionDef(
        name=node.name,
        calls=tuple(calls),
        span=_span(filename, node.lineno, node.col_offset),
        params=tuple(params),
        return_type=return_type,
        accesses=(),
        statements=tuple(statements),
    )


# ---------------------------------------------------------------------------
# Type annotation translation
# ---------------------------------------------------------------------------


def _translate_annotation(
    node: ast.expr | None,
    filename: str,
) -> TypePath:
    """Translate a parameter type annotation to a ``TypePath``.

    Untyped parameters get the sentinel ``Any``. The checkers that
    look at parameter types (none in Phase 1) can pattern-match on
    ``Any`` to skip them.
    """
    if node is None:
        return TypePath(
            base="Any",
            layer=None,
            span=_span(filename, 0, 0),
            layer_alias_used=None,
        )
    return TypePath(
        base=_annotation_name(node),
        layer=None,
        span=_span(filename, node.lineno, node.col_offset),
        layer_alias_used=None,
    )


def _translate_return_annotation(
    node: ast.expr,
    filename: str,
) -> TypePath | UnionType:
    """Translate a return-type annotation, mapping ``Optional[X]``,
    ``X | None``, and ``Union[X, None]`` to a Furqan ``UnionType``.

    v0.3.2 fix for Finding 2 of the round-5 review: when the
    annotation is a string literal (the PEP 484 forward-reference
    form, ubiquitous in ``TYPE_CHECKING`` patterns and ORM models
    that need to break circular imports), the literal is parsed as
    a Python expression and the translator recurses into the result.
    A parse failure falls through to the bare-``TypePath`` path
    rather than raising; the user's annotation is at worst opaque,
    never a hard error.
    """
    sp = _span(filename, node.lineno, node.col_offset)

    # PEP 484 string forward reference: ``-> "Optional[User]"``.
    # Parse once and recurse so the rest of this function sees the
    # real shape.
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        try:
            inner_tree = ast.parse(node.value, mode="eval")
            inner = inner_tree.body
            # Carry the outer span so diagnostics still point at the
            # source location of the string literal, not at line 1
            # of the parsed sub-source.
            inner.lineno = node.lineno
            inner.col_offset = node.col_offset
            return _translate_return_annotation(inner, filename)
        except SyntaxError:
            pass

    if _is_optional(node):
        # _is_optional ensures node is ast.Subscript; help mypy narrow.
        assert isinstance(node, ast.Subscript)
        inner = _extract_optional_inner(node)
        # v0.3.4: ``Optional[None]`` resolves to ``type(None)`` at
        # Python runtime (``typing.Optional[X]`` is defined as
        # ``Union[X, None]``, so ``Optional[None]`` is
        # ``Union[None, None]`` is ``type(None)``). Translate as a
        # bare ``TypePath(base="None")`` to mirror the v0.3.3
        # ``_is_all_none_union`` discipline applied to ``Union[None]``.
        # Without this short-circuit the Optional path produces a
        # binary ``UnionType`` with both arms None, which is not
        # semantically meaningful and would break the day someone
        # refactors the matcher to require distinct arms. Caught by
        # Round-7 review (Observation 1).
        if _is_none_literal(inner):
            return TypePath(
                base="None",
                layer=None,
                span=sp,
                layer_alias_used=None,
            )
        return UnionType(
            left=TypePath(
                base=_annotation_name(inner),
                layer=None,
                span=sp,
                layer_alias_used=None,
            ),
            right=TypePath(
                base="None",
                layer=None,
                span=sp,
                layer_alias_used=None,
            ),
            span=sp,
        )

    if _is_pipe_union_with_none(node):
        # _is_pipe_union_with_none ensures node is ast.BinOp.
        assert isinstance(node, ast.BinOp)
        inner = _extract_pipe_union_inner(node)
        # v0.3.5: ``None | None`` (and chains of None like
        # ``None | None | None``) collapse to type(None). The
        # extractor returns ``node.left`` which for ``None | None``
        # is itself None; pre-v0.3.5 the path produced
        # ``UnionType(None, None)``, a structurally degenerate
        # binary union that arrived at the right user-visible answer
        # incidentally. Mirror the v0.3.3 ``_is_all_none_union`` and
        # v0.3.4 ``Optional[None]`` discipline: bare TypePath("None")
        # so all three optional-spelling paths produce structurally
        # identical AST for the all-None case.
        if _is_none_literal(inner):
            return TypePath(
                base="None",
                layer=None,
                span=sp,
                layer_alias_used=None,
            )
        return UnionType(
            left=TypePath(
                base=_annotation_name(inner),
                layer=None,
                span=sp,
                layer_alias_used=None,
            ),
            right=TypePath(
                base="None",
                layer=None,
                span=sp,
                layer_alias_used=None,
            ),
            span=sp,
        )

    if _is_union_with_none(node):
        # _is_union_with_none ensures node is ast.Subscript.
        assert isinstance(node, ast.Subscript)
        inner = _extract_union_with_none_inner(node)
        return UnionType(
            left=TypePath(
                base=_annotation_name(inner),
                layer=None,
                span=sp,
                layer_alias_used=None,
            ),
            right=TypePath(
                base="None",
                layer=None,
                span=sp,
                layer_alias_used=None,
            ),
            span=sp,
        )

    # v0.3.3: degenerate ``Union[None, ...]`` (every arm is ``None``)
    # resolves to ``type(None)`` at Python runtime per the typing
    # module's semantics. Translate it as a bare ``TypePath(base="None")``
    # so a matching ``return None`` body does not fire a false-positive
    # ``return_none_mismatch``. ``_is_union_with_none`` deliberately
    # rejects this shape (the predicate is the contract
    # ``_extract_union_with_none_inner`` can satisfy, which is binary
    # ``Optional``-equivalence; degenerate Unions need their own
    # branch). Caught by the round-6 review of v0.3.2.
    if _is_all_none_union(node):
        return TypePath(
            base="None",
            layer=None,
            span=sp,
            layer_alias_used=None,
        )

    return TypePath(
        base=_annotation_name(node),
        layer=None,
        span=sp,
        layer_alias_used=None,
    )


def _is_optional(node: ast.expr) -> bool:
    """True iff ``node`` is ``Optional[X]``, ``typing.Optional[X]``,
    or ``t.Optional[X]`` (a common ``import typing as t`` alias).

    Older versions accepted any ``Attribute.Optional``, so an
    annotation like ``weird.lib.Optional[X]`` would be misclassified
    as ``typing.Optional[X]``. v0.3.0 requires the attribute's root
    to be a single ``Name`` whose id is ``typing`` or ``t``.
    """
    if not isinstance(node, ast.Subscript):
        return False
    if isinstance(node.value, ast.Name) and node.value.id == "Optional":
        return True
    if isinstance(node.value, ast.Attribute):
        attr = node.value
        if (
            attr.attr == "Optional"
            and isinstance(attr.value, ast.Name)
            and attr.value.id in ("typing", "t")
        ):
            return True
    return False


def _extract_optional_inner(node: ast.Subscript) -> ast.expr:
    """Extract ``X`` from ``Optional[X]``."""
    return node.slice


def _is_pipe_union_with_none(node: ast.expr) -> bool:
    """True iff ``node`` is ``X | None`` (PEP 604 form)."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        if isinstance(node.right, ast.Constant) and node.right.value is None:
            return True
        if isinstance(node.right, ast.Name) and node.right.id == "None":
            return True
    return False


def _extract_pipe_union_inner(node: ast.BinOp) -> ast.expr:
    """Extract ``X`` from ``X | None``."""
    return node.left


def _is_union_with_none(node: ast.expr) -> bool:
    """True iff ``node`` is ``Union[..., None]`` or
    ``typing.Union[..., None]`` (or the ``t.Union`` alias) where at
    least one arm is ``None`` AND at least one arm is non-None.

    v0.3.2 fix for Finding 1 of the round-5 review. Older code
    (pre-PEP 604) routinely uses ``Union[X, None]`` as the spelling
    for what newer code writes as ``Optional[X]`` or ``X | None``.
    mypy and pyright treat all three forms identically; v0.3.1's
    matcher only recognised the latter two, producing a false
    positive ``return_none_mismatch`` on the ``Union`` form.

    v0.3.3 boundary fix for the round-6 review (the IndexError
    crash on ``Union[None]``, ``Union[None, None]``, and
    ``Union[None, None, None]``). The predicate is the truthful
    contract that ``_extract_union_with_none_inner`` can satisfy:
    if every arm is None, there is no non-None inner type to
    extract. Degenerate ``Union[None, ...]`` shapes fall through to
    the normal type-translation path (which renders ``Union`` as a
    bare ``TypePath`` and treats ``None`` as a valid return) instead
    of raising an unstructured Python exception that violates the
    ``errors/marad.py`` structured-diagnosis contract.
    """
    if not isinstance(node, ast.Subscript):
        return False
    if not _is_union_head(node.value):
        return False
    elts = _slice_elements(node.slice)
    has_none = any(_is_none_literal(e) for e in elts)
    has_non_none = any(not _is_none_literal(e) for e in elts)
    return has_none and has_non_none


def _extract_union_with_none_inner(node: ast.Subscript) -> ast.expr:
    """Extract the non-None arms from ``Union[X, None]`` (returns
    ``X``) or from ``Union[X, Y, None]`` (returns a synthesized
    ``ast.BinOp(X | Y)``).

    Furqan's ``UnionType`` is binary, so a 3+ arm Python union has
    to collapse to a binary shape for the translator. The non-None
    arms collapse via PEP 604 ``|`` chaining; ``_allows_none`` only
    cares that one of the resulting two arms is ``None``.
    """
    elts = _slice_elements(node.slice)
    non_none = [e for e in elts if not _is_none_literal(e)]
    # Precondition (enforced by ``_is_union_with_none``): at least
    # one non-None arm. v0.3.3 added the upstream check after the
    # round-6 review caught the IndexError crash on ``Union[None]``,
    # ``Union[None, None]``, and ``Union[None, None, None]``. This
    # assertion is defense in depth so a future caller that skips
    # the predicate fails loudly with a contract message instead of
    # the cryptic ``IndexError: list index out of range``.
    assert non_none, (
        "_extract_union_with_none_inner called on a Union with no "
        "non-None arms; callers must check _is_union_with_none first"
    )
    if len(non_none) == 1:
        return non_none[0]
    # Synthesize ``X | Y | ...`` as a left-folded BinOp tree.
    folded: ast.expr = non_none[0]
    for arm in non_none[1:]:
        folded = ast.BinOp(left=folded, op=ast.BitOr(), right=arm)
    return folded


def _is_all_none_union(node: ast.expr) -> bool:
    """True iff ``node`` is a ``Union`` subscript whose arms are all
    the ``None`` literal: ``Union[None]``, ``Union[None, None]``,
    ``Union[None, None, None]``, etc.

    v0.3.3 boundary helper for the round-6 review. ``typing.Union``
    evaluates these forms to ``type(None)`` at runtime, so the
    semantically correct translation is a bare
    ``TypePath(base="None")`` rather than a binary ``UnionType``
    (which has no non-None arm to populate) or a free-form
    exception (which violates the structured-diagnosis contract).
    """
    if not isinstance(node, ast.Subscript):
        return False
    if not _is_union_head(node.value):
        return False
    elts = _slice_elements(node.slice)
    if not elts:
        return False
    return all(_is_none_literal(e) for e in elts)


def _is_union_head(node: ast.expr) -> bool:
    """True iff ``node`` is the head of a ``Union`` subscript:
    ``Union``, ``typing.Union``, or ``t.Union``."""
    if isinstance(node, ast.Name) and node.id == "Union":
        return True
    if (
        isinstance(node, ast.Attribute)
        and node.attr == "Union"
        and isinstance(node.value, ast.Name)
    ):
        return node.value.id in ("typing", "t")
    return False


def _slice_elements(slice_node: ast.expr) -> list[ast.expr]:
    """Return the comma-separated elements of a subscript slice."""
    if isinstance(slice_node, ast.Tuple):
        return list(slice_node.elts)
    return [slice_node]


def _slice_contains_none(slice_node: ast.expr) -> bool:
    return any(_is_none_literal(e) for e in _slice_elements(slice_node))


def _is_none_literal(node: ast.expr) -> bool:
    return (isinstance(node, ast.Constant) and node.value is None) or (
        isinstance(node, ast.Name) and node.id == "None"
    )


def _annotation_name(node: ast.expr) -> str:
    """Best-effort short rendering of an annotation expression.

    PEP 604 unions like ``int | str`` recurse into both arms and join
    with ``|``. Without this branch the BinOp falls through to
    ``"Unknown"`` and the diagnostic prose for return_none_mismatch
    suggests changing the type to ``Optional[Unknown]``, which is
    not actionable.

    v0.3.1: ``Attribute`` nodes render the full dotted path
    (``weird.lib.Optional`` rather than just ``Optional``). Without
    this, the diagnostic for a return-None inside a function annotated
    ``-> weird.lib.Optional[str]`` says ``declares -> Optional`` and
    suggests ``Optional[Optional]`` as the fix, which is incoherent.
    The substantive check (whether the annotation is
    ``typing.Optional`` for the matcher) is done elsewhere by
    ``_is_optional``; this function is for prose rendering only.
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        root = _annotation_name(node.value)
        return f"{root}.{node.attr}" if root != "Unknown" else node.attr
    if isinstance(node, ast.Constant):
        return str(node.value)
    if isinstance(node, ast.Subscript):
        return _annotation_name(node.value)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return f"{_annotation_name(node.left)} | {_annotation_name(node.right)}"
    return "Unknown"


# ---------------------------------------------------------------------------
# Body and expression translation
# ---------------------------------------------------------------------------


def _translate_body(
    body: list[ast.stmt],
    filename: str,
    exit_is_terminal: bool = False,
) -> list[ReturnStmt | IfStmt]:
    """Translate a Python statement list into Furqan ``ReturnStmt``
    and ``IfStmt`` nodes (the only statement shapes Furqan's AST has).

    Compound statements are translated structurally so the inner
    return statements remain visible to the checkers, but D24's
    all-paths-return analysis is not over-claimed:

    * ``for``, ``while``, ``async for`` -> wrapped in an ``IfStmt``
      with an opaque condition and an empty ``else_body``. D24 sees
      this as "may not run," which matches the runtime semantics
      (the iterable may be empty or the condition may be false).
    * ``with`` and ``async with`` -> body spliced into the parent
      statement list. The body always executes (modulo exceptions,
      which D24 explicitly does not model).
    * ``try`` -> body and ``finalbody`` are spliced (always run);
      the ``orelse`` clause is also spliced (runs when the body
      completes without exception); each ``except`` handler is
      wrapped as ``IfStmt(opaque, ..., ())`` since handlers may not
      run on the actual control-flow path.
    * ``match`` -> each case body is wrapped as ``IfStmt(opaque,
      ..., ())``. Phase 3+ may special-case an exhaustive ``case _:``
      arm to splice into the previous IfStmt's ``else_body`` so D24
      can recognise total matches; the conservative shape is fine
      for now (it under-claims completeness, never over-claims).

    * ``raise`` and statement-level ``sys.exit(...)``,
      ``os._exit(...)``, ``os.abort()`` -> when ``exit_is_terminal``
      is set, a ``ReturnStmt`` whose value is the ``__raise__``
      marker. An exit is a terminal path, not a fall-through, so D24
      must not report a missing return on it (v1.0.1; the same
      "propagation is an exit" reading the try-handler chain already
      uses). ``return_none`` only matches ``__none__``, so the marker
      never reads as a None return. ``exit_is_terminal`` is False for
      functions with no explicit ``return`` (R3 owns those).
      Not recognised (documented limits): bare ``exit()`` / ``quit()``
      (site builtins, absent under ``python -S``), ``assert False``
      (stripped under ``python -O``), aliased imports such as
      ``from sys import exit``, and user functions annotated
      ``NoReturn``.

    Anything else (assignments, other expression statements,
    ``import``, ``pass``, ``break``, ``continue``, ``global``,
    ``nonlocal``) is silently skipped: the checkers wired into the
    runner do not inspect these forms.
    """
    result: list[ReturnStmt | IfStmt] = []

    def _sub(stmts: list[ast.stmt]) -> list[ReturnStmt | IfStmt]:
        return _translate_body(stmts, filename, exit_is_terminal)

    for node in body:
        if exit_is_terminal and (isinstance(node, ast.Raise) or _is_exit_call(node)):
            sp = _span(filename, node.lineno, node.col_offset)
            result.append(ReturnStmt(value=IdentExpr(name="__raise__", span=sp), span=sp))
        elif isinstance(node, ast.Return):
            result.append(
                ReturnStmt(
                    value=_translate_expression(node.value, filename),
                    span=_span(filename, node.lineno, node.col_offset),
                )
            )
        elif isinstance(node, ast.If):
            result.append(
                IfStmt(
                    condition=_translate_expression(node.test, filename),
                    body=tuple(_sub(node.body)),
                    span=_span(filename, node.lineno, node.col_offset),
                    else_body=tuple(_sub(node.orelse)),
                )
            )
        elif isinstance(node, ast.For | ast.AsyncFor | ast.While):
            inner = _sub(node.body)
            # for/while-else clauses run when the loop terminates
            # without break. They are equally "may run" for our
            # purposes. Splice into the maybe-runs IfStmt body.
            inner.extend(_sub(node.orelse))
            if inner:
                result.append(_maybe_runs_if(inner, node, filename))
        elif isinstance(node, ast.With | ast.AsyncWith):
            result.extend(_sub(node.body))
        elif isinstance(node, ast.Try):
            # v0.3.5: model try/except control flow correctly.
            # Pre-v0.3.5 spliced ``try.body`` and ``orelse`` as
            # always-running, which made D24 silently certify
            # functions whose only return path was inside a try
            # block whose except handler fell through. The fix
            # closes the "Exception-driven fall-through" limitation
            # documented since v0.3.1.
            #
            # Encoding: a try statement has two coherent exit
            # families: the success path (try.body + orelse) which
            # runs when no exception is raised, and the handler
            # paths (one per except clause) which run when their
            # matched exception fires. To make D24 reach the right
            # answer when every explicit path returns (the
            # try-except-else-all-return shape mypy passes), we
            # encode this as a single ``IfStmt`` whose body is the
            # success path and whose ``else_body`` chains the
            # handlers. D24's all-paths-return predicate then sees
            # both halves and concludes coverage iff every branch
            # returns. The unmatched-exception case is deliberately
            # not modelled - it propagates, which is an exit not a
            # fall-through.
            #
            # finally always runs and is spliced unconditionally.
            success_body = tuple(_sub(node.body) + _sub(node.orelse))
            handler_chain = _build_try_handler_chain(node.handlers, filename, exit_is_terminal)
            if success_body or handler_chain:
                sp = _span(filename, node.lineno, node.col_offset)
                result.append(
                    IfStmt(
                        condition=IdentExpr(name="__opaque__", span=sp),
                        body=success_body,
                        span=sp,
                        else_body=handler_chain,
                    )
                )
            result.extend(_sub(node.finalbody))
        elif isinstance(node, ast.Match):
            for case in node.cases:
                inner = _sub(case.body)
                if inner:
                    result.append(_maybe_runs_if(inner, case, filename))
    return result


_EXIT_CALLS: frozenset[tuple[str, str]] = frozenset(
    {("sys", "exit"), ("os", "_exit"), ("os", "abort")}
)


def _is_exit_call(node: ast.stmt) -> bool:
    """True for a statement-level ``sys.exit(...)``, ``os._exit(...)``
    or ``os.abort()`` call written with the module-qualified name.
    Aliased imports and builtins ``exit()`` / ``quit()`` are not
    recognised (documented limit; see ``_translate_body``)."""
    if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)):
        return False
    func = node.value.func
    return (
        isinstance(func, ast.Attribute)
        and isinstance(func.value, ast.Name)
        and (func.value.id, func.attr) in _EXIT_CALLS
    )


def _own_body_has(node: ast.AST, kinds: tuple[type, ...]) -> bool:
    """True iff ``node``'s own body (not nested defs, classes or
    lambdas) contains a node of one of ``kinds``."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Lambda):
            continue
        if isinstance(child, kinds) or _own_body_has(child, kinds):
            return True
    return False


def _is_generator(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True iff the function is a generator (``yield`` or
    ``yield from`` in its own body). Generator expressions and
    comprehensions do not count: they create their own scope."""
    return _own_body_has(node, (ast.Yield, ast.YieldFrom))


def _is_none_annotation(node: ast.expr) -> bool:
    """True for a bare ``-> None`` annotation, including the string
    forward-reference form ``-> "None"``."""
    if isinstance(node, ast.Constant):
        return node.value is None or node.value == "None"
    return False


def _contains_return(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True iff the function's own body (not nested defs or classes)
    contains at least one ``return`` statement."""
    return _own_body_has(node, (ast.Return,))


def _maybe_runs_if(
    inner: list[ReturnStmt | IfStmt],
    source_node: ast.AST,
    filename: str,
) -> IfStmt:
    """Wrap ``inner`` in an ``IfStmt(opaque, inner, ())`` so D24
    treats the body as "may or may not execute" rather than as a
    guaranteed control-flow path."""
    line = getattr(source_node, "lineno", 0)
    col = getattr(source_node, "col_offset", 0)
    sp = _span(filename, line, col)
    return IfStmt(
        condition=IdentExpr(name="__opaque__", span=sp),
        body=tuple(inner),
        span=sp,
        else_body=(),
    )


def _build_try_handler_chain(
    handlers: list[ast.ExceptHandler],
    filename: str,
    exit_is_terminal: bool = False,
) -> tuple[IfStmt | ReturnStmt, ...]:
    """Build a right-folded ``IfStmt`` chain for a list of
    ``ast.ExceptHandler`` nodes, suitable for use as the
    ``else_body`` of a try-statement encoding.

    The last handler's body is spliced directly as the deepest
    leaf, NOT wrapped in another IfStmt. The reasoning: after all
    handlers have been considered, if none matched, the exception
    propagates - that is an exit, not a fall-through. D24's
    contract is fall-through detection; treating "no handler
    matches" as covered (because propagation exits the function)
    matches the project's stated decision not to model exception
    flow explicitly. Each non-last handler is wrapped as
    ``IfStmt(opaque, head_body, chain_for_rest)`` so that for D24
    to conclude all-paths-return on the exception family, every
    handler's body must independently all-paths-return.

    v0.3.5: replaces the pre-v0.3.5 list of independent maybe-runs
    IfStmts. The chain shape is what lets D24 conclude that
    ``try/except/else where every branch returns`` does in fact
    all-paths-return.
    """
    if not handlers:
        return ()
    last_body = tuple(_translate_body(handlers[-1].body, filename, exit_is_terminal))
    accum = last_body
    for handler in reversed(handlers[:-1]):
        h_body = tuple(_translate_body(handler.body, filename, exit_is_terminal))
        sp = _span(filename, handler.lineno, handler.col_offset)
        accum = (
            IfStmt(
                condition=IdentExpr(name="__opaque__", span=sp),
                body=h_body,
                span=sp,
                else_body=accum,
            ),
        )
    return accum


def _extract_calls(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    filename: str,
) -> list[CallRef]:
    """Extract calls from a function's DIRECT body only.

    Does not descend into nested function definitions (closures,
    inner functions). Does not collect calls from the enclosing
    function's decorator list, since those are evaluated at
    definition time, not invoked from inside the body.

    Lambdas are NOT treated as nested functions: calls inside a
    lambda body count as calls of the enclosing function.
    Rationale: lambdas are inline expressions, not separate scopes
    the user reasons about independently.

    Phase 2 fix for Phase 1 Gap 5.
    """
    calls: list[CallRef] = []
    narrowed = _narrowed_call_ids(node)

    def _walk(n: ast.AST, is_root: bool) -> None:
        # Stop at any nested FunctionDef / AsyncFunctionDef /
        # ClassDef. Their bodies are separate scopes and their
        # calls are attributed to the inner definition (or to
        # nothing, if the inner def is itself a method whose
        # methods get extracted at module level).
        if not is_root and isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            return
        if isinstance(n, ast.Call) and id(n) not in narrowed:
            name = _call_name(n)
            if name:
                calls.append(
                    CallRef(
                        path=(name,),
                        span=_span(filename, n.lineno, n.col_offset),
                    )
                )
        for child in ast.iter_child_nodes(n):
            # Skip the enclosing function's own decorators when
            # walking the root node.
            if (
                is_root
                and isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
                and hasattr(n, "decorator_list")
                and child in n.decorator_list
            ):
                continue
            _walk(child, is_root=False)

    _walk(node, is_root=True)
    return calls


# ---------------------------------------------------------------------------
# v1.0.1: call-site narrowing for D11 (status coverage)
# ---------------------------------------------------------------------------
#
# D11 reports a caller that receives ``X | None`` from a producer and
# declares a bare ``X``. That is correct when the None arm is silently
# dropped, and wrong when the caller handles it explicitly at the call
# site. The shapes below handle the None arm explicitly; their call is
# withheld from D11. Deliberately conservative: anything not listed
# here still reaches D11 (documented limits: ``assert x is not None``,
# which ``python -O`` strips; narrowing more than one statement away
# from the binding; and storing the Optional in a container).


# Equality and identity are defined for None on either side. Membership
# is not: ``x in None`` raises, and so does ``None in "abc"``. Ordering
# raises on None. Only the operators below narrow.
_NONE_SAFE_COMPARE = (ast.Eq, ast.NotEq, ast.Is, ast.IsNot)


def _narrowed_call_ids(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[int]:
    """Return ``id()`` of every ``ast.Call`` in ``fn``'s own body whose
    possible ``None`` result is explicitly handled at the call site:

    * ``call(...) or default``: the call is the left operand of ``or``
      and the last operand is a literal that cannot be None.
    * ``call(...) == value`` (also ``!=``, ``is``, ``is not``):
      comparisons that are defined for None and yield a bool. Ordering
      and membership (``in``, ``not in``) can raise on None and stay
      visible.
    * ``x = call(...)`` immediately followed by ``if x is None:`` or
      ``if not x:`` whose body ends the path or rebinds ``x`` to a
      literal that cannot be None. Ending the path means ``raise``,
      ``sys.exit``, or a ``return`` that does not read ``x``;
      ``continue`` / ``break`` count only when every read of ``x`` is
      in the rest of the same loop body.
    * ``x = call(...)`` immediately followed by ``if x is not None:``
      or ``if x:`` where every later read of ``x`` is inside that
      ``if`` body.
    * The walrus forms of the two guard shapes:
      ``if (x := call(...)) is None: <exit>`` and
      ``if (x := call(...)) is not None: ...``.
    """
    out: set[int] = set()
    loads = _name_loads(fn)
    unsafe = _exception_sensitive_ids(fn)
    blocked = _unguardable_names(fn)

    for n in _own_nodes(fn):
        if (
            isinstance(n, ast.BoolOp)
            and isinstance(n.op, ast.Or)
            and isinstance(n.values[0], ast.Call)
            and _non_none_expr(n.values[-1])
        ):
            out.add(id(n.values[0]))
        if isinstance(n, ast.Compare) and all(isinstance(op, _NONE_SAFE_COMPARE) for op in n.ops):
            for operand in (n.left, *n.comparators):
                if isinstance(operand, ast.Call):
                    out.add(id(operand))
        if isinstance(n, ast.If) and id(n) not in unsafe:
            walrus = _walrus_guard_call(n, loads, blocked)
            if walrus is not None:
                out.add(id(walrus))
        for block in _stmt_blocks(n):
            for i, stmt in enumerate(block[:-1]):
                bound = _bound_call(stmt)
                if bound is None:
                    continue
                var, call = bound
                if var in blocked:
                    continue  # read by a closure, or global / dynamic
                if id(block[i + 1]) in unsafe:
                    continue  # the guard's exit may be caught or overridden
                in_loop = isinstance(n, ast.For | ast.AsyncFor | ast.While) and block is n.body
                reads_stay_in_block = in_loop and all(
                    any(_inside(u, s) for s in block[i + 1 :]) for u in loads.get(var, [])
                )
                if _guards(block[i + 1], var, loads, loop_exit_ok=reads_stay_in_block):
                    out.add(id(call))
    return out


def _own_nodes(fn: ast.AST) -> list[ast.AST]:
    """Every node in ``fn``'s own body (not nested defs/classes/lambdas)."""
    out: list[ast.AST] = []

    def _walk(n: ast.AST) -> None:
        for child in ast.iter_child_nodes(n):
            if isinstance(
                child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Lambda
            ):
                continue
            out.append(child)
            _walk(child)

    out.append(fn)
    _walk(fn)
    return out


def _stmt_blocks(n: ast.AST) -> list[list[ast.stmt]]:
    blocks = []
    for field in ("body", "orelse", "finalbody"):
        value = getattr(n, field, None)
        if isinstance(value, list) and value and isinstance(value[0], ast.stmt):
            blocks.append(value)
    for handler in getattr(n, "handlers", []) or []:
        blocks.append(handler.body)
    for case in getattr(n, "cases", []) or []:
        blocks.append(case.body)
    return blocks


def _bound_call(stmt: ast.stmt) -> tuple[str, ast.Call] | None:
    """``x = call(...)`` or ``x: T = call(...)`` -> (``x``, call)."""
    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
        target, value = stmt.targets[0], stmt.value
    elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
        target, value = stmt.target, stmt.value
    else:
        return None
    if isinstance(target, ast.Name) and isinstance(value, ast.Call):
        return target.id, value
    return None


def _name_loads(fn: ast.AST) -> dict[str, list[ast.Name]]:
    """Every read of each name in ``fn``, nested lambdas and defs
    included: a closure that reads the name after the guard must
    count as a read outside the guarded region."""
    out: dict[str, list[ast.Name]] = {}
    for n in ast.walk(fn):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
            out.setdefault(n.id, []).append(n)
    return out


def _is_none_test(test: ast.expr, var: str, negated: bool) -> bool:
    """``x is None`` / ``not x`` (negated=False: the None branch) or
    ``x is not None`` / ``x`` (negated=True: the not-None branch)."""
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and _is_name(test.left, var):
        op, right = test.ops[0], test.comparators[0]
        is_none = isinstance(right, ast.Constant) and right.value is None
        return is_none and isinstance(op, ast.IsNot if negated else ast.Is)
    if negated:
        return _is_name(test, var)
    return (
        isinstance(test, ast.UnaryOp)
        and isinstance(test.op, ast.Not)
        and _is_name(test.operand, var)
    )


def _is_name(node: ast.AST, var: str) -> bool:
    return isinstance(node, ast.Name) and node.id == var


# Statements allowed before the exit or rebind in a None branch: they
# cannot transfer control out of the branch except by raising, so the
# exit or rebind that follows is reached on every non-raising path.
_STRAIGHT_LINE = (ast.Expr, ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Pass)


def _straight_prefix(stmts: list[ast.stmt], var: str) -> bool:
    """Every statement is simple (no branch, loop, ``try``, ``with``,
    ``return``, ``break`` or ``continue``) and none of them touches
    ``var``. v1.0.1 audit F-01: without this, ``if x is None:`` whose
    body is ``if early: return x`` followed by a raise or a rebind
    leaked the None through the nested return."""
    return all(isinstance(st, _STRAIGHT_LINE) and not _reads(st, var) for st in stmts)


def _ends_path(body: list[ast.stmt], var: str, loop_exit_ok: bool = False) -> bool:
    """The None branch leaves without leaking ``var``: a straight-line
    prefix that never touches ``var`` (``_straight_prefix``), then an
    exit as the last statement.

    ``return`` counts only when its value does not read ``var``
    (``if x is None: return x`` hands the None straight back).
    ``continue`` / ``break`` leave only the loop body, so they count
    only when every read of ``var`` is inside that loop body
    (``loop_exit_ok``)."""
    if not _straight_prefix(body[:-1], var):
        return False
    last = body[-1]
    if isinstance(last, ast.Return):
        return last.value is None or not _reads(last.value, var)
    if isinstance(last, ast.Continue | ast.Break):
        return loop_exit_ok
    return isinstance(last, ast.Raise) or _is_exit_call(last)


def _reads(node: ast.AST, var: str) -> bool:
    return any(_is_name(n, var) for n in ast.walk(node))


def _non_none_expr(node: ast.expr) -> bool:
    """Expressions that cannot evaluate to None: non-None literals,
    container displays and comprehensions, f-strings."""
    if isinstance(node, ast.Constant):
        return node.value is not None
    return isinstance(
        node,
        ast.List
        | ast.Tuple
        | ast.Dict
        | ast.Set
        | ast.ListComp
        | ast.SetComp
        | ast.DictComp
        | ast.JoinedStr,
    )


def _rebinds(body: list[ast.stmt], var: str) -> bool:
    """``var`` is rebound at the top level of the None branch to a
    value that cannot be None, and nothing in the branch binds it to
    anything else."""
    first = next((i for i, stmt in enumerate(body) if _bound_name(stmt) == var), None)
    if first is None or not _straight_prefix(body[:first], var):
        return False  # v1.0.1 audit F-01: the rebind must be reached on every path
    for n in ast.walk(ast.Module(body=body, type_ignores=[])):
        if not _binding_is_non_none(n, var):
            return False
    return True


def _binding_is_non_none(n: ast.AST, var: str) -> bool:
    """False when ``n`` binds ``var`` to something that may be None.

    Only a plain ``var = <non-None literal>`` (or annotated form)
    counts as safe. Every other way of binding the name (tuple or
    starred unpacking, ``for`` / ``with`` targets, walrus, augmented
    assignment, ``match`` captures, ``except ... as``, imports,
    ``global`` / ``nonlocal``, ``del``) is treated as possibly None.
    v1.0.1 verification round: tuple unpacking and ``match``
    captures had slipped through."""
    if isinstance(n, ast.Assign):
        if any(_is_name(t, var) for t in n.targets) and not _non_none_expr(n.value):
            return False
        return not any(_stores(t, var) for t in n.targets if not isinstance(t, ast.Name))
    if isinstance(n, ast.AnnAssign):
        if _is_name(n.target, var):
            return n.value is not None and _non_none_expr(n.value)
        return not _stores(n.target, var)
    if isinstance(n, ast.AugAssign | ast.NamedExpr):
        return not _is_name(n.target, var)
    if isinstance(n, ast.MatchAs | ast.MatchStar):
        return n.name != var
    if isinstance(n, ast.MatchMapping):
        return n.rest != var
    if isinstance(n, ast.ExceptHandler):
        return n.name != var
    if isinstance(n, ast.Import | ast.ImportFrom):
        return all((a.asname or a.name.split(".")[0]) != var for a in n.names)
    if isinstance(n, ast.Global | ast.Nonlocal):
        return var not in n.names
    if isinstance(n, ast.Delete):
        return not any(_stores(t, var) or _is_name(t, var) for t in n.targets)
    return not _binds_target(n, var)


def _stores(target: ast.AST, var: str) -> bool:
    """``target`` (an unpacking pattern) stores into ``var``."""
    return any(
        isinstance(x, ast.Name) and x.id == var and isinstance(x.ctx, ast.Store | ast.Del)
        for x in ast.walk(target)
    )


_DYNAMIC_SCOPE_CALLS = frozenset({"locals", "vars", "eval", "exec"})
_FRAME_ATTRS = frozenset({"_getframe", "currentframe", "f_locals", "f_back", "stack"})

# Scopes that read their free names later than they are created: a
# closure, a generator expression (its element expression runs on
# iteration) and, on Python 3.12+, a ``type`` alias (lazy value).
_LATE_SCOPES: tuple[type, ...] = (
    ast.Lambda,
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
    ast.GeneratorExp,
    *((ast.TypeAlias,) if hasattr(ast, "TypeAlias") else ()),
)


def _unguardable_names(fn: ast.AST) -> frozenset[str]:
    """Names a guard cannot vouch for.

    * Names read inside a nested ``lambda`` / ``def`` / ``class``,
      generator expression or ``type`` alias (``_LATE_SCOPES``): these
      read the variable when they run, not when they are created, so
      a later binding to None (the next loop pass, a later
      assignment) reaches the caller through them. v1.0.1
      verification rounds two and three.
    * Every name, when the function references ``locals`` / ``vars``
      / ``eval`` / ``exec`` (called or not) or a frame attribute such
      as ``sys._getframe`` / ``f_locals``.
    * Names declared ``global`` or ``nonlocal``: any call can rebind
      them after the guard."""
    names: set[str] = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Global | ast.Nonlocal):
            names.update(n.names)
        if (isinstance(n, ast.Name) and n.id in _DYNAMIC_SCOPE_CALLS) or (
            isinstance(n, ast.Attribute) and n.attr in _FRAME_ATTRS | _DYNAMIC_SCOPE_CALLS
        ):
            return _EVERY_NAME  # any reference, called or not, plus frame access
    for n in ast.walk(fn):
        if isinstance(n, _LATE_SCOPES) and n is not fn:
            names.update(
                x.id for x in ast.walk(n) if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Load)
            )
    return frozenset(names)


class _EveryName(frozenset):  # type: ignore[type-arg]
    def __contains__(self, item: object) -> bool:
        return True


_EVERY_NAME: frozenset[str] = _EveryName()


def _exception_sensitive_ids(fn: ast.AST) -> set[int]:
    """``id()`` of every node inside a ``try`` that has handlers or a
    ``finally``, or inside a ``with`` block. There, a ``raise`` or
    ``sys.exit`` in a None branch can be caught or suppressed and a
    ``finally`` can override the exit, so the guard does not prove the
    None is gone. v1.0.1 verification round: four such leaks."""
    out: set[int] = set()
    for n in _own_nodes(fn):
        sensitive = isinstance(n, ast.With | ast.AsyncWith) or (
            isinstance(n, ast.Try | getattr(ast, "TryStar", ast.Try))
            and bool(n.handlers or n.finalbody)
        )
        if sensitive:
            out.update(id(d) for d in ast.walk(n) if d is not n)
    return out


def _binds_target(n: ast.AST, var: str) -> bool:
    targets: list[ast.AST] = []
    if isinstance(n, ast.For | ast.AsyncFor):
        targets.append(n.target)
    elif isinstance(n, ast.With | ast.AsyncWith):
        targets.extend(i.optional_vars for i in n.items if i.optional_vars is not None)
    return any(_is_name(x, var) for t in targets for x in ast.walk(t))


def _bound_name(stmt: ast.stmt) -> str | None:
    if (
        isinstance(stmt, ast.Assign)
        and len(stmt.targets) == 1
        and isinstance(stmt.targets[0], ast.Name)
    ):
        return stmt.targets[0].id
    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
        return stmt.target.id
    return None


def _inside(node: ast.AST, region: ast.AST) -> bool:
    return any(node is sub for sub in ast.walk(region))


def _guards(
    nxt: ast.stmt,
    var: str,
    loads: dict[str, list[ast.Name]],
    loop_exit_ok: bool = False,
) -> bool:
    if not isinstance(nxt, ast.If):
        return False
    if _is_none_test(nxt.test, var, negated=False):
        return _ends_path(nxt.body, var, loop_exit_ok) or _rebinds(nxt.body, var)
    if _is_none_test(nxt.test, var, negated=True):
        uses = loads.get(var, [])
        return all(_inside(u, nxt.test) or any(_inside(u, s) for s in nxt.body) for u in uses)
    return False


def _walrus_guard_call(
    node: ast.If,
    loads: dict[str, list[ast.Name]],
    blocked: frozenset[str] = frozenset(),
) -> ast.Call | None:
    test = node.test
    target: ast.NamedExpr | None = None
    if (
        isinstance(test, ast.Compare)
        and len(test.ops) == 1
        and isinstance(test.left, ast.NamedExpr)
    ):
        target = test.left
        right = test.comparators[0]
        if not (isinstance(right, ast.Constant) and right.value is None):
            return None
        is_none_branch = isinstance(test.ops[0], ast.Is)
        if not (is_none_branch or isinstance(test.ops[0], ast.IsNot)):
            return None
    elif isinstance(test, ast.NamedExpr):
        target, is_none_branch = test, False
    else:
        return None
    if not (isinstance(target.target, ast.Name) and isinstance(target.value, ast.Call)):
        return None
    var = target.target.id
    if var in blocked:
        return None
    if is_none_branch:
        return target.value if _ends_path(node.body, var) else None
    uses = loads.get(var, [])
    if all(any(_inside(u, s) for s in node.body) for u in uses):
        return target.value
    return None


def _call_name(node: ast.Call) -> str | None:
    """Return the simple name of the callable at a call site, or
    ``None`` if it cannot be reduced to a bare identifier."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _translate_expression(
    node: ast.expr | None,
    filename: str,
) -> IdentExpr:
    """Collapse every Python expression to one of two opaque markers.

    ``__none__`` marks the literal ``None`` (so a future D22 pass can
    distinguish ``return None`` from ``return value``). ``__opaque__``
    marks every other expression. Phase 1 does no type inference;
    D22 (return-type match) will treat these as uncheckable, which is
    correct.

    KNOWN PHASE 1 GAP: D24 treats ``return None`` as a satisfied
    return path even when the declared return type is non-Optional.
    This is a type mismatch, not a missing return. Phase 2 with D22
    closes this gap.
    """
    sp_zero = _span(filename, 0, 0)
    if node is None:
        return IdentExpr(name="__none__", span=sp_zero)
    if isinstance(node, ast.Constant) and node.value is None:
        return IdentExpr(
            name="__none__",
            span=_span(filename, node.lineno, node.col_offset),
        )
    return IdentExpr(
        name="__opaque__",
        span=_span(filename, node.lineno, node.col_offset),
    )


def _span(filename: str, line: int, col: int) -> SourceSpan:
    return SourceSpan(file=filename, line=line, column=col)
