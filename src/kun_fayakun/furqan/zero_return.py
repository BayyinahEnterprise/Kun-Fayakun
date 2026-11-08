"""R3: ring-close check for declared producers (Python semantics).

A function that declares a non-``None`` return type but contains zero
``return`` statements anywhere in its body is reported as
``zero_return_path``. mypy reports the same case as "Missing return
statement"; this checker brings furqan-lint to parity for that class.

Skipped (does not fire R3):

- Functions annotated ``-> None``. The implicit ``None`` return is
  the declared type.
- Functions annotated ``-> Optional[T]``, ``-> T | None``, or any
  ``Union`` containing ``None`` (implicit ``None`` is a valid return
  for Optional). Annotation analysis delegates to
  ``adapter._is_optional``, ``adapter._is_pipe_union_with_none``,
  ``adapter._is_union_with_none``, and ``adapter._is_all_none_union``.
  These encode the v0.3.x degenerate-form fixes (Optional[None],
  Union[None, None], etc.) that took six audit rounds to harden;
  R3 does not re-derive them.
- Functions with no return annotation at all. R3 has no contract
  for an unannotated function.
- Functions whose body raises unconditionally (``raise`` is the
  terminal value, not a ``return``). Conservative: only the
  canonical "function body is exactly one Raise" or "all paths
  end in Raise" shapes are recognized.
- Functions whose body is the canonical infinite loop ``while True:``
  with no ``break`` (provably non-returning; reaching the end of
  the body is unreachable). Non-canonical loops (``while 1:``,
  ``itertools.count()``) are NOT recognized in v0.6.0.
- Generator functions (``yield`` / ``yield from`` in the body,
  v1.0.1). The annotation describes what is yielded; reaching the end
  of a generator ends iteration and is never a missing return.
- Functions decorated with any of the names in
  ``_SKIP_DECORATORS`` (e.g., ``@abstractmethod``, ``@overload``).
  As of v0.6.1, decorator resolution follows module-level
  ``import`` and ``from ... import ... as ...`` aliases via a
  symbol table built from the module's top-level imports. So
  ``from abc import abstractmethod as abstract`` then ``@abstract``
  is correctly recognized and skipped. Imports inside function or
  class bodies are not tracked (deliberate simplification).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from furqan_lint.adapter import (
    _is_all_none_union,
    _is_exit_call,
    _is_generator,
    _is_optional,
    _is_pipe_union_with_none,
    _is_union_with_none,
)

# Decorator skip-list. Names are resolved through a module-level
# alias map (see _build_decorator_alias_map) so aliased imports
# (``from abc import abstractmethod as abstract``) are recognized.
_SKIP_DECORATORS: frozenset[str] = frozenset(
    {
        "abstractmethod",
        "overload",
        "typing.overload",
        "abc.abstractmethod",
    }
)


@dataclass(frozen=True)
class ZeroReturnDiagnostic:
    """A function that declared a non-None return type but contains
    zero ``return`` statements (R3, ring-close)."""

    function_name: str
    lineno: int
    col_offset: int
    declared_return: str

    @property
    def diagnosis(self) -> str:
        return (
            f"function '{self.function_name}' declares "
            f"-> {self.declared_return} but contains no "
            f"`return` statement (R3, ring-close)."
        )


def check_zero_return(tree: ast.Module) -> list[ZeroReturnDiagnostic]:
    """Walk every top-level and nested function/method in ``tree`` and
    emit a diagnostic for each that satisfies the R3 firing condition.

    Methods of classes are walked. Lambdas are not (they cannot have
    a return-type annotation in Python syntax). Nested function
    definitions are walked independently of their enclosing function.

    Builds a module-level alias map from top-level ``import`` and
    ``from ... import ... [as ...]`` statements once per call so the
    decorator skip-list can resolve aliased imports.
    """
    aliases = _build_decorator_alias_map(tree)
    diagnostics: list[ZeroReturnDiagnostic] = []
    for fn in _iter_function_defs(tree):
        diagnostics.extend(_check_function(fn, aliases))
    return diagnostics


# ---------------------------------------------------------------------------
# Walking
# ---------------------------------------------------------------------------


def _iter_function_defs(
    tree: ast.AST,
) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    """Yield every ``FunctionDef`` and ``AsyncFunctionDef`` reachable
    from ``tree``, including methods of classes and inner functions."""
    out: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            out.append(node)
    return out


# ---------------------------------------------------------------------------
# Per-function check
# ---------------------------------------------------------------------------


def _check_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, str],
) -> list[ZeroReturnDiagnostic]:
    """Return a single-element list if ``node`` satisfies R3's
    firing condition, else an empty list.

    Returns a list (rather than ``ZeroReturnDiagnostic | None``) so
    that the caller can ``.extend(...)`` without a None-narrowing
    step that D11 status-coverage would flag as silently dropping
    the Incomplete arm.
    """
    # 1. No return-type annotation: skip.
    if node.returns is None:
        return []

    # 2. Annotation allows None (Optional/Union-with-None/None): skip.
    if _annotation_allows_none(node.returns):
        return []

    # 3. Decorator on the skip-list (with alias resolution): skip.
    if _has_skip_decorator(node, aliases):
        return []

    # 3b. Generator (v1.0.1): the annotation is the yield type, and
    #     the end of the body ends iteration. Not a producer.
    if _is_generator(node):
        return []

    # 4. Body is provably non-returning (raise-only or while True
    #    with no break): skip.
    if _body_is_non_returning(node.body):
        return []

    # 5. Has at least one return statement (excluding nested
    #    function/lambda bodies): not R3's case (D24 territory).
    if _has_any_return(node.body):
        return []

    # All checks passed - fire R3.
    return [
        ZeroReturnDiagnostic(
            function_name=node.name,
            lineno=node.lineno,
            col_offset=node.col_offset,
            declared_return=_render_annotation(node.returns),
        )
    ]


# ---------------------------------------------------------------------------
# Annotation analysis (delegates to adapter helpers)
# ---------------------------------------------------------------------------


def _annotation_allows_none(ann: ast.expr) -> bool:
    """True iff ``ann`` is a type annotation that includes ``None``.

    Delegates to the adapter helpers that encode the v0.3.x
    degenerate-form fixes. R3 does not re-derive them.
    """
    if _is_none_literal(ann):
        return True
    if _is_optional(ann):
        return True
    if _is_pipe_union_with_none(ann):
        return True
    if _is_union_with_none(ann):
        return True
    return bool(_is_all_none_union(ann))


def _is_none_literal(node: ast.expr) -> bool:
    """True iff ``node`` is the bare ``None`` literal."""
    if isinstance(node, ast.Constant) and node.value is None:
        return True
    return isinstance(node, ast.Name) and node.id == "None"


def _render_annotation(ann: ast.expr) -> str:
    """Best-effort rendering of an annotation for diagnostic prose.

    Falls back to ``ast.dump`` if ``ast.unparse`` is unavailable
    (Python < 3.9, but the project requires 3.10+ so unparse is
    always present).
    """
    try:
        return ast.unparse(ann)
    except AttributeError:  # pragma: no cover  - 3.10+ guaranteed
        return ast.dump(ann)


# ---------------------------------------------------------------------------
# Decorator skip-list
# ---------------------------------------------------------------------------


def _has_skip_decorator(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: dict[str, str],
) -> bool:
    """True iff any decorator on ``node`` matches a name in
    ``_SKIP_DECORATORS``, either directly or via the module's
    ``aliases`` map.

    Recognizes ``@abstractmethod``, ``@overload``,
    ``@typing.overload``, ``@abc.abstractmethod`` directly. Resolves
    aliased imports through ``aliases``: ``from abc import
    abstractmethod as abstract`` followed by ``@abstract`` matches.
    """
    return any(_decorator_matches_skip_list(dec, aliases) for dec in node.decorator_list)


def _decorator_matches_skip_list(dec: ast.expr, aliases: dict[str, str]) -> bool:
    """True iff the decorator reduces to a name in ``_SKIP_DECORATORS``,
    either directly or after resolution through ``aliases``.

    Recognizes:
    - Direct bare:    ``@abstractmethod``, ``@overload``.
    - Direct dotted:  ``@abc.abstractmethod``, ``@typing.overload``.
    - Called forms:   ``@abstractmethod()``, ``@functools.cache(...)``.
    - Aliased bare:   ``from abc import abstractmethod as abstract``
                      then ``@abstract`` resolves to
                      ``abc.abstractmethod`` via ``aliases``.
    - Aliased prefix: ``import abc as a`` then ``@a.abstractmethod``
                      resolves to ``abc.abstractmethod`` via
                      ``aliases``.

    Returns ``False`` for shapes that don't reduce to a dotted name
    (e.g., ``@(lambda f: f)``). Returns ``bool`` so the consumer-side
    discipline (D11) is honestly propagated.
    """
    target = dec.func if isinstance(dec, ast.Call) else dec

    if isinstance(target, ast.Name):
        # Bare: @abstract, @abstractmethod, etc.
        name = target.id
        if name in _SKIP_DECORATORS:
            return True
        return aliases.get(name) in _SKIP_DECORATORS

    if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
        # Dotted: @abc.abstractmethod, @a.abstractmethod, etc.
        prefix = target.value.id
        suffix = target.attr
        if f"{prefix}.{suffix}" in _SKIP_DECORATORS:
            return True
        resolved_prefix = aliases.get(prefix)
        if resolved_prefix is not None:
            return f"{resolved_prefix}.{suffix}" in _SKIP_DECORATORS
        return False

    return False


def _build_decorator_alias_map(tree: ast.Module) -> dict[str, str]:
    """Build a name -> resolved-name map from ``tree``'s top-level
    imports. Used by the decorator skip-list to recognize aliased
    imports.

    Mappings:
    - ``from X import Y`` -> ``{Y: "X.Y"}``
    - ``from X import Y as Z`` -> ``{Z: "X.Y"}``
    - ``import X`` -> ``{X: "X"}``
    - ``import X as Y`` -> ``{Y: "X"}``

    Resolution is module-level only. Imports inside function or
    class bodies are not tracked; decorators that need such imports
    are exotic enough to defer.
    """
    aliases: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for name in node.names:
                local = name.asname or name.name
                qualified = f"{module}.{name.name}" if module else name.name
                aliases[local] = qualified
        elif isinstance(node, ast.Import):
            for name in node.names:
                local = name.asname or name.name
                aliases[local] = name.name
    return aliases


# ---------------------------------------------------------------------------
# Non-returning body detection (raise-only, while True)
# ---------------------------------------------------------------------------


def _body_is_non_returning(body: list[ast.stmt]) -> bool:
    """True iff the body provably cannot finish normally.

    v1.0.2: replaces the two hard-coded v0.6.0 shapes (all paths end in
    ``raise``; the body is exactly one ``while True:`` without
    ``break``) with a small completion analysis, ``_can_complete``. The
    side-street map (``bench/sidestreets``) showed R3 reporting 564
    functions up to four statements that never fall through: bodies
    ending in ``sys.exit()``, an infinite ``while True`` after other
    statements, ``try`` / ``finally`` whose ``finally`` exits, and
    branches that raise on one side and exit on the other.

    Sound in the direction that matters: it answers "cannot complete"
    only when every path raises, calls a recognised exit
    (``sys.exit`` / ``os._exit`` / ``os.abort``, the same syntactic
    recognition as D24, with the same documented limits), or loops in
    ``while True`` with no ``break``. ``with`` (a context manager may
    suppress), ``for``, ``match``, and ``try`` handlers that might
    catch are treated as able to complete, so R3 keeps reporting
    those.
    """
    return bool(body) and not _can_complete(body)


def _can_complete(stmts: list[ast.stmt]) -> bool:
    """Can executing ``stmts`` in order reach the end of the block?"""
    return all(_stmt_can_complete(s) for s in stmts)


def _stmt_can_complete(s: ast.stmt) -> bool:
    if isinstance(s, ast.Raise | ast.Return | ast.Break | ast.Continue) or _is_exit_call(s):
        return False
    if isinstance(s, ast.If):
        return _can_complete(s.body) or _can_complete(s.orelse)
    if isinstance(s, ast.While):
        if _is_constant_true(s.test):
            return _contains_break(s.body)
        return True
    if isinstance(s, ast.Try) or (hasattr(ast, "TryStar") and isinstance(s, ast.TryStar)):
        if s.finalbody and not _can_complete(s.finalbody):
            return False
        body_done = _can_complete(s.body) and _can_complete(s.orelse)
        if body_done or not s.handlers:
            return body_done
        return True  # a handler may catch what the body raises
    return True  # with, for, match, assignments, expressions, ...


def _is_constant_true(node: ast.expr) -> bool:
    """True iff ``node`` is the literal ``True``. Does NOT recognize
    ``1``, ``"truthy"``, or any other truthy-but-not-True expression.
    """
    return isinstance(node, ast.Constant) and node.value is True


def _contains_break(body: list[ast.stmt]) -> bool:
    """True iff ``body`` (or any nested control-flow construct
    inside it) contains a ``Break``. Conservative: a ``Break`` inside
    a nested ``while`` or ``for`` loop is still counted, even though
    it would only break the inner loop. v0.6.0 prefers false-positive
    suppression over precise loop-scope tracking.
    """
    for node in body:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Break):
                return True
    return False


# ---------------------------------------------------------------------------
# Return-counting (excluding nested function/lambda bodies)
# ---------------------------------------------------------------------------


def _has_any_return(body: list[ast.stmt]) -> bool:
    """True iff the body contains any ``Return`` statement that
    belongs to the function being checked.

    Returns inside nested ``FunctionDef``, ``AsyncFunctionDef``, or
    ``Lambda`` bodies do NOT count - those are independent function
    scopes.
    """
    return any(_node_contains_own_return(node) for node in body)


def _node_contains_own_return(node: ast.AST) -> bool:
    """Recursive walker that returns True if ``node`` (or any of its
    nested children, EXCEPT inside another function/lambda body)
    contains a ``Return``.
    """
    if isinstance(node, ast.Return):
        return True
    # Stop descending into nested function/lambda scopes.
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
        return False
    return any(_node_contains_own_return(child) for child in ast.iter_child_nodes(node))
