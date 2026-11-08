"""Translate a tree-sitter-rust CST into a Furqan ``Module``.

The translator supports D24, D11, and R3 (R3 wired in the runner).
The translation is intentionally lossy: it preserves enough
control-flow shape and return-type structure for those two checkers
and discards everything else (lifetimes, trait objects' payloads,
expression values, generic parameter bounds, etc.).

Function discovery
==================

Walks the CST recursively to find every ``function_item`` node. This
covers four categories:

* Free functions at the source-file root.
* Methods inside ``impl_item`` blocks.
* Functions inside ``mod_item`` blocks.
* Functions nested inside another function's body.

Two adjacent CST node types are explicitly skipped per prompt
section 3.4:

* ``function_signature_item`` (trait method declarations with no body):
  D24/D11 do not apply to interface declarations.
* ``closure_expression``: the structural-honesty argument that
  motivates D24 is weaker for inline closures than for top-level
  functions; a future phase may revisit.

Return type translation
=======================

* ``Result<T, E>`` -> ``UnionType(TypePath(T), TypePath(E))``.
* ``Option<T>`` -> ``UnionType(TypePath(T), TypePath("None"))``.
* ``T`` (any other) -> ``TypePath(T)``.

The choice of ``TypePath("None")`` for Rust ``Option::None`` is a
IR-shape simplification (see ADR-001 reversibility note). Both
``Result`` and ``Option`` produce the ``UnionType``-with-some-arm
shape that D11's ``producer_predicate`` already fires on.

Body translation
================

Each function body is a tree-sitter ``block`` node. Children are
translated to Furqan ``IfStmt`` and ``ReturnStmt`` markers; all
other expressions and statements are left as opaque markers
(unattached). The translation rules:

* ``return X;`` -> ``ReturnStmt(opaque)``.
* ``if cond { body } else { else_body }`` ->
  ``IfStmt(opaque, [translated body], [translated else_body])``.
* ``if cond { body }`` (no else) ->
  ``IfStmt(opaque, [translated body], ())``.
* ``match X { arm => body, ... }`` -> wrapped as a chain of
  ``IfStmt(opaque, [arm body], else_body=...)`` so each arm
  contributes a possible-runs path.
* ``while``, ``loop``, ``for``, ``while_let`` -> wrapped as
  ``IfStmt(opaque, body=[], else_body=())`` (may run zero or N
  times).
* Tail expression with no trailing ``;`` -> synthesise a
  ``ReturnStmt(opaque)`` per validator finding R1.
* ``panic!()`` / ``todo!()`` / ``unimplemented!()`` macro
  invocation at tail position -> treated as opaque. The empty-body
  and panic-only-body cases are caught by the R3 zero-return checker
  (added in v0.7.3, which retired the
  ``empty_or_panic_only_body.rs`` documented limit); the translator
  itself does not need to recognise them as a special shape.

Async functions (``async fn``) translate identically to non-async;
the async-ness is irrelevant to D24/D11.

Errors
======

If ``tree.root_node.has_error`` is set, the translator raises
``RustParseError``. The CLI catches this and exits with code 2,
matching the Python adapter's behaviour for un-parseable source.
The detection mechanism is ``has_error`` (which catches both
``ERROR`` nodes and ``is_missing`` markers) rather than a manual
walk for ``type == 'ERROR'``, because the latter misses cases
like a missing closing brace.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

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

if TYPE_CHECKING:
    from tree_sitter import Node, Tree


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class RustParseError(Exception):
    """Raised when ``tree.root_node.has_error`` is set on the parsed
    Rust source. Carries the line number of the first ERROR or
    missing node found, so the CLI can render a useful message.
    """

    def __init__(self, path: Path, line: int, kind: str) -> None:
        super().__init__(f"Failed to parse {path}: {kind} at line {line}")
        self.path = path
        self.line = line
        self.kind = kind


class RustExtrasNotInstalled(ImportError):
    """Raised by ``parse_file`` when the ``[rust]`` extra is missing
    from the install (i.e., ``tree_sitter`` and/or
    ``tree_sitter_rust`` cannot be imported).

    Subclasses ``ImportError`` so callers that catch ``ImportError``
    broadly still work; the typed name lets the CLI distinguish a
    missing-extra case from an unrelated import bug.

    The exception message is the install hint itself, so the CLI
    can simply ``print(str(exc))`` to stderr.
    """


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Edition:
    """Ambient edition for a translated module. The translator does not
    branch on this; it exists so v0.7.x can add edition-conditional
    fixtures without restructuring the call sites.
    """

    name: str  # one of "2018", "2021", "2024"


def translate_tree(tree: Tree, source_bytes: bytes, path: Path, edition: str = "2021") -> Module:
    """Translate a parsed Rust ``Tree`` into a Furqan ``Module``.

    Raises ``RustParseError`` if ``tree.root_node.has_error`` is set
    (catches both ERROR nodes and missing-token markers).

    ``edition`` is recorded on the module via the ambient marker
    pattern but does not currently change translation behaviour.
    """
    _assert_parses_cleanly(tree, path)
    root = tree.root_node

    functions: list[FunctionDef] = []
    for fn_node in _iter_function_items(root):
        functions.append(_translate_function(fn_node, source_bytes, str(path)))

    module_name = path.stem
    span = _span(str(path), 1, 0)
    bismillah = BismillahBlock(
        name=module_name,
        authority=("rust_module",),
        serves=(("structural_honesty",),),
        scope=(module_name,),
        not_scope=(),
        span=span,
        alias_used="bismillah",
    )

    return Module(
        bismillah=bismillah,
        functions=tuple(functions),
        source_path=str(path),
        compound_types=(),
    )


def _assert_parses_cleanly(tree: Tree, path: Path) -> None:
    """Walk the tree once. If any ERROR or missing node is found,
    raise ``RustParseError`` naming the first occurrence.

    Structured as a single conditional block (no early return) so
    that D24 sees a uniform shape: either we walk the tree and
    raise, or we exit normally. The early-return-then-raise pattern
    can confuse D24's path-coverage walk into a Case P1 false
    positive.
    """
    if tree.root_node.has_error:
        for node in _walk(tree.root_node):
            if node.is_error or node.is_missing or node.type == "ERROR":
                line = node.start_point[0] + 1
                kind = "missing token" if node.is_missing else node.type
                raise RustParseError(path, line, kind)
        # has_error was set but no specific node surfaced; report generically.
        raise RustParseError(path, 0, "unspecified parse error")


# ---------------------------------------------------------------------------
# Function discovery
# ---------------------------------------------------------------------------


def _iter_function_items(root: Node) -> list[Node]:
    """Return every ``function_item`` reachable from ``root``,
    including methods inside impl/trait blocks (where applicable),
    functions inside mod blocks, and functions nested in other
    function bodies.

    Skipped: ``function_signature_item`` (no body, trait
    declarations) and ``closure_expression`` (per prompt 3.4).
    Trait method DEFINITIONS (where the trait provides a default
    body via ``function_item``) ARE walked, matching the rule that
    we check anything with a body.
    """
    return [node for node in _walk(root) if node.type == "function_item"]


def _walk(node: Node) -> list[Node]:
    """Depth-first walk returning ``node`` and all descendants.

    Returns a list rather than yielding so that R3 (zero-return)
    treats this as a function with a terminal return. Generator
    functions look like zero-return-paths to R3 v0.6.x; widening
    R3 to recognise generators is a v0.6.2 candidate but out of
    v0.7.0 scope.
    """
    result: list[Node] = [node]
    for child in node.children:
        result.extend(_walk(child))
    return result


# ---------------------------------------------------------------------------
# Per-function translation
# ---------------------------------------------------------------------------


def _translate_function(node: Node, source_bytes: bytes, filename: str) -> FunctionDef:
    """Translate one ``function_item`` to a ``FunctionDef``.

    Extracts: name, return type (if annotated), body statements,
    direct call references (for D11). Lifetimes, generic parameters,
    parameter types, and visibility modifiers are discarded; D24/D11
    do not need them.

    Calls are extracted as bare-name references; method calls
    ``self.foo(...)`` reduce to the method name ``foo`` matching the
    Python adapter convention. Cross-module calls are out of scope
    for v0.7.x (no symbol table).
    """
    name = _function_name(node) or "<anonymous>"
    span = _span(filename, node.start_point[0] + 1, node.start_point[1])
    rt_list = _function_return_type_or_empty(node, span)
    return_type: TypePath | UnionType | None = rt_list[0] if rt_list else None
    statements: tuple[Any, ...] = ()
    calls: tuple[Any, ...] = ()
    for body in _function_body_or_empty(node):
        statements = tuple(_translate_block(body, source_bytes, filename))
        calls = tuple(_extract_calls(body, span))
    return FunctionDef(
        name=name,
        calls=calls,
        span=span,
        params=(),
        return_type=return_type,
        accesses=(),
        statements=statements,
    )


def _extract_calls(body: Node, default_span: SourceSpan) -> list[CallRef]:
    """Walk ``body`` collecting every direct call. Returns one
    ``CallRef`` per call site, naming the callee. The Furqan D11
    checker resolves callee return types by looking up the name in
    the same Module's function table; cross-module calls are out of
    scope for v0.7.x.

    Skips nested function/closure bodies so that calls inside a
    closure or nested fn are attributed to that inner scope (when
    the inner is also walked at the top level) rather than to the
    enclosing function.
    """
    calls: list[CallRef] = []
    for node in _walk_skipping_nested(body):
        if node.type == "call_expression":
            callee = _call_callee_name(node)
            if callee:
                span = _span(
                    default_span.file,
                    node.start_point[0] + 1,
                    node.start_point[1],
                )
                calls.append(CallRef(path=(callee,), span=span))
    return calls


_NESTED_SKIP_TYPES: frozenset[str] = frozenset(
    {
        "function_item",
        "closure_expression",
        "impl_item",
        "trait_item",
        "mod_item",
    }
)


def _walk_skipping_nested(root: Node) -> list[Node]:
    """Depth-first walk that does NOT descend into nested function
    bodies, closures, or impl/trait/mod blocks. Used by call
    extraction so calls inside an inner function are not mis-
    attributed to the outer one.

    Returns a list (not a generator) for R3 compatibility; see
    ``_walk`` for the rationale.
    """
    result: list[Node] = [root]
    for child in root.children:
        if child.type in _NESTED_SKIP_TYPES:
            continue
        result.extend(_walk_skipping_nested(child))
    return result


def _call_callee_name(call: Node) -> str:
    """Extract the bare callee name from a ``call_expression``,
    or the empty string if no name can be reduced.

    Recognised function-position shapes:
    - ``foo(...)``                      -> ``"foo"``
    - ``self.foo(...)``                 -> ``"foo"`` (method call)
    - ``module::foo(...)``              -> ``"foo"`` (scoped path)
    - ``Ok(...)``, ``Some(...)``       -> the constructor name (the
      module-table lookup will simply miss for built-in enum
      constructors and D11 ignores those).
    - ``foo::<T>(...)``                 -> ``"foo"`` (turbofish stripped)

    Returns ``""`` for shapes we cannot reduce to a single name
    (e.g., higher-order calls like ``(f)(x)``); the caller filters
    empty strings out before constructing CallRefs. ``str`` rather
    than ``str | None`` keeps the consumer-side D11 discipline
    honest.
    """
    func: Node | None = None
    for i, child in enumerate(call.children):
        if call.field_name_for_child(i) == "function":
            func = child
            break
    if func is None:
        return ""
    if func.type == "identifier":
        return _text(func).decode()
    if func.type == "field_expression":
        # method call: receiver.method(...)
        for i, child in enumerate(func.children):
            if func.field_name_for_child(i) == "field":
                return _text(child).decode()
    if func.type == "scoped_identifier":
        # path: a::b::c(...) -> "c"
        for i, child in enumerate(func.children):
            if func.field_name_for_child(i) == "name":
                return _text(child).decode()
    if func.type == "generic_function":
        # turbofish: f::<T>(...) -> walk into the inner identifier
        for child in func.children:
            if child.type == "identifier":
                return _text(child).decode()
            if child.type == "scoped_identifier":
                for i, c in enumerate(child.children):
                    if child.field_name_for_child(i) == "name":
                        return _text(c).decode()
    return ""


def _function_name(node: Node) -> str:
    """Return the ``identifier`` field child's text as a string,
    or the empty string if none is found.

    Returns ``str`` rather than ``str | None`` so that callers do
    not need to propagate the Optional through D11 status-coverage
    checks. An anonymous function (no identifier) is rare enough
    that the empty-string sentinel is acceptable; the caller uses
    ``"<anonymous>"`` for display purposes.
    """
    for i, child in enumerate(node.children):
        if node.field_name_for_child(i) == "name":
            return _text(child).decode()
    return ""


def _function_return_type_or_empty(node: Node, span: SourceSpan) -> list[TypePath | UnionType]:
    """Return a single-element list containing the function's
    translated return type, or an empty list if there is no
    annotation (in Rust the implicit ``-> ()`` case).

    Returns ``list`` for the same D11-honesty reason as
    ``_function_body_or_empty``.
    """
    for i, child in enumerate(node.children):
        if node.field_name_for_child(i) == "return_type":
            return [_translate_type(child, span)]
    return []


def _translate_type(node: Node, span: SourceSpan) -> TypePath | UnionType:
    """Translate a Rust type-tree node to a Furqan ``TypePath`` or
    ``UnionType``. Recognised shapes:

    * ``Result<T, E>`` -> ``UnionType(TypePath(T), TypePath(E))``.
    * ``Option<T>`` -> ``UnionType(TypePath(T), TypePath("None"))``.
    * Any other type (primitive, reference, generic, scoped path,
      trait object) -> ``TypePath(rendered_text)``.
    """
    if node.type == "generic_type":
        head = _generic_head(node)
        args = _generic_arguments(node)
        if head == "Result" and len(args) >= 1:
            left = _translate_type(args[0], span)
            right = (
                _translate_type(args[1], span)
                if len(args) >= 2
                else TypePath(base="<unknown>", layer=None, span=span)
            )
            return UnionType(
                left=_as_typepath(left),
                right=_as_typepath(right),
                span=span,
            )
        if head == "Option" and len(args) >= 1:
            inner = _translate_type(args[0], span)
            return UnionType(
                left=_as_typepath(inner),
                right=TypePath(base="None", layer=None, span=span),
                span=span,
            )
    return TypePath(base=_text(node).decode(), layer=None, span=span)


def _generic_head(node: Node) -> str:
    """Return the head identifier of a ``generic_type`` (e.g.,
    ``Result`` from ``Result<i32, Error>``).
    """
    for child in node.children:
        if child.type in ("type_identifier", "scoped_type_identifier"):
            return _text(child).decode().split("::")[-1]
    return ""


def _generic_arguments(node: Node) -> list[Node]:
    """Return the type-argument children of a ``generic_type`` node
    (the contents of the ``<...>`` brackets).
    """
    args: list[Node] = []
    for child in node.children:
        if child.type == "type_arguments":
            for arg in child.named_children:
                if arg.type not in ("comment", "block_comment", "line_comment"):
                    args.append(arg)
    return args


def _as_typepath(t: TypePath | UnionType) -> TypePath:
    """Coerce a translated type to a ``TypePath`` for use as an arm
    of a ``UnionType``. Nested unions are flattened by taking the
    left arm; this is an IR-shape simplification (Rust does not have
    syntactic ``A | B`` types yet outside trait bounds, so the
    nested case is exotic).
    """
    if isinstance(t, TypePath):
        return t
    return t.left


def _function_body_or_empty(node: Node) -> list[Node]:
    """Return a list containing the function's ``body`` block, or
    an empty list if the function is bodiless (signature-only).
    The walker skips signature-only functions at discovery time so the
    empty case is a defensive guard.

    Returns ``list[Node]`` (length 0 or 1) rather than
    ``Node | None`` so that the caller can iterate without a
    None-narrowing step that D11 would flag.
    """
    for i, child in enumerate(node.children):
        if node.field_name_for_child(i) == "body":
            return [child]
    return []


# ---------------------------------------------------------------------------
# Body translation
# ---------------------------------------------------------------------------


def _translate_block(block: Node, source_bytes: bytes, filename: str) -> list[Any]:
    """Translate a Rust ``block`` node to a list of Furqan
    statements. The list contains ``IfStmt`` markers (for control
    flow), ``ReturnStmt`` markers (explicit and synthesised), and
    nothing for opaque expressions.

    Tail-expression detection (validator R1): the last non-comment
    named child is the tail expression iff its source byte range
    does NOT end in ``;``. Comments are skipped explicitly so a
    trailing ``//`` line comment does not get mis-classified as an
    implicit-return tail expression. The check is positional and
    works across tree-sitter-rust minor versions because both 0.23
    and 0.24 share the convention that tail expressions are
    unwrapped at block end.
    """
    statements: list[Any] = []
    children = [c for c in block.named_children if c.type not in ("line_comment", "block_comment")]
    for index, child in enumerate(children):
        is_last = index == len(children) - 1
        translated = _translate_statement(
            child,
            is_tail=is_last,
            source_bytes=source_bytes,
            filename=filename,
        )
        statements.extend(translated)
    return statements


def _translate_statement(
    node: Node, *, is_tail: bool, source_bytes: bytes, filename: str
) -> list[Any]:
    """Translate one block-level Rust node to zero or more Furqan
    statements. Recursive; ``IfStmt`` and ``match_expression`` walk
    into their bodies.
    """
    span = _span(filename, node.start_point[0] + 1, node.start_point[1])
    text = _text(node)

    # Explicit return statement (``return X;`` is wrapped as
    # ``expression_statement`` whose inner is ``return_expression``).
    if node.type == "expression_statement":
        for inner in _named_first_or_empty(node):
            if inner.type == "return_expression":
                return [ReturnStmt(value=_opaque(span), span=span)]
            if inner.type == "if_expression":
                return _translate_if(inner, source_bytes, filename, span)
            if inner.type == "match_expression":
                return _translate_match(inner, source_bytes, filename, span)
            if inner.type in (
                "while_expression",
                "loop_expression",
                "for_expression",
                "while_let_expression",
            ):
                return _translate_loop(inner, source_bytes, filename, span)
        # Tail position: an expression_statement that does NOT end
        # in ';' is an implicit return (R1). The text of the node
        # always reflects the source bytes faithfully.
        if is_tail and not text.endswith(b";"):
            return [ReturnStmt(value=_opaque(span), span=span)]
        return []

    # Bare control-flow at tail position (no expression_statement wrap).
    if node.type == "if_expression":
        if_stmts = _translate_if(node, source_bytes, filename, span)
        if is_tail and not text.endswith(b";"):
            if_stmts.append(ReturnStmt(value=_opaque(span), span=span))
        return if_stmts
    if node.type == "match_expression":
        match_stmts = _translate_match(node, source_bytes, filename, span)
        if is_tail and not text.endswith(b";"):
            match_stmts.append(ReturnStmt(value=_opaque(span), span=span))
        return match_stmts
    if node.type in (
        "while_expression",
        "loop_expression",
        "for_expression",
        "while_let_expression",
    ):
        loop_stmts = _translate_loop(node, source_bytes, filename, span)
        if is_tail and not text.endswith(b";"):
            loop_stmts.append(ReturnStmt(value=_opaque(span), span=span))
        return loop_stmts

    # Items inside function bodies (let, const, nested fn, etc.) do
    # NOT count as terminal values. Skip; D24 will fire if there's
    # nothing terminal.
    if node.type in (
        "let_declaration",
        "const_item",
        "static_item",
        "type_item",
        "use_declaration",
        "function_item",
        "struct_item",
        "enum_item",
        "trait_item",
        "impl_item",
        "mod_item",
    ):
        return []

    # Anything else at tail position without ';' is an implicit-
    # return tail expression (R1). This includes integer_literal,
    # binary_expression, call_expression, scoped_identifier (for
    # ``Some(_)`` etc.), and so on.
    if is_tail and not text.endswith(b";"):
        return [ReturnStmt(value=_opaque(span), span=span)]
    return []


def _translate_if(node: Node, source_bytes: bytes, filename: str, span: SourceSpan) -> list[Any]:
    """Translate an ``if_expression`` to a single ``IfStmt`` whose
    body and ``else_body`` are recursively translated.
    """
    body_node = None
    else_node = None
    for i, child in enumerate(node.children):
        fname = node.field_name_for_child(i)
        if fname == "consequence":
            body_node = child
        elif fname == "alternative":
            # else body may itself be a block OR an else_clause that
            # wraps a block / chained if. Drill once.
            if child.type == "else_clause":
                inner_list = _named_first_or_empty(child)
                else_node = inner_list[0] if inner_list else None
            else:
                else_node = child
    body_stmts = (
        tuple(_translate_block(body_node, source_bytes, filename)) if body_node is not None else ()
    )
    if else_node is None:
        else_stmts: tuple[Any, ...] = ()
    elif else_node.type == "if_expression":
        # Chained `else if` becomes a nested IfStmt in the else_body.
        else_stmts = tuple(_translate_if(else_node, source_bytes, filename, span))
    elif else_node.type == "block":
        else_stmts = tuple(_translate_block(else_node, source_bytes, filename))
    else:
        else_stmts = ()
    return [
        IfStmt(
            condition=_opaque(span),
            body=body_stmts,
            span=span,
            else_body=else_stmts,
        )
    ]


def _translate_match(node: Node, source_bytes: bytes, filename: str, span: SourceSpan) -> list[Any]:
    """Translate a ``match_expression`` into a chain of nested
    ``IfStmt`` markers, one per arm. Each arm becomes an IfStmt
    whose body is the translated arm body and whose else_body is
    the rest of the chain. The last arm's else_body is empty.

    This mirrors how the Python adapter wraps ``match`` statements
    so D24's path-coverage walk treats each arm as a possible-runs
    path that must produce a value.
    """
    arms: list[Node] = []
    for child in node.children:
        if child.type == "match_block":
            for arm in child.named_children:
                if arm.type == "match_arm":
                    arms.append(arm)
    return _arms_to_if_chain(arms, source_bytes, filename, span)


def _arms_to_if_chain(
    arms: list[Node], source_bytes: bytes, filename: str, span: SourceSpan
) -> list[Any]:
    """Recursive helper for ``_translate_match``.

    Rust matches are guaranteed exhaustive by the compiler. Linting
    well-formed Rust source means we can rely on this: the LAST
    arm's body IS reached on every path that the preceding arms did
    not catch. So we emit the last arm's body directly as the
    deepest else of the chain rather than wrapping it as another
    IfStmt with an empty else_body. Without this, a match like
    ``match r { Ok(n) => n, Err(_) => panic!() }`` would produce a
    chain whose deepest else_body is empty and D24 would fire
    spuriously.

    A guard (``if cond``) on the last arm makes it conditional, in
    which case we DO wrap as IfStmt with empty else_body and let
    D24 fire (the guard might be false on some inputs, exposing a
    real fall-through path the Rust compiler would also flag).
    """
    if not arms:
        return []
    head, *rest = arms
    if not rest and not _arm_has_guard(head):
        return list(_translate_arm_body(head, source_bytes, filename, span))
    body_stmts = tuple(_translate_arm_body(head, source_bytes, filename, span))
    else_stmts = tuple(_arms_to_if_chain(rest, source_bytes, filename, span))
    return [
        IfStmt(
            condition=_opaque(span),
            body=body_stmts,
            span=span,
            else_body=else_stmts,
        )
    ]


def _arm_has_guard(arm: Node) -> bool:
    """True iff the match arm has a ``if cond`` guard. Guarded arms
    are conditional even when they appear last, so they cannot be
    treated as catch-alls.
    """
    return any(arm.field_name_for_child(i) == "guard" for i in range(len(arm.children)))


def _translate_arm_body(
    arm: Node, source_bytes: bytes, filename: str, span: SourceSpan
) -> list[Any]:
    """Translate a match arm's right-hand-side into Furqan
    statements. Used by both the chain builder and the wildcard
    short-circuit.
    """
    for body_node in _arm_body_or_empty(arm):
        if body_node.type == "block":
            return list(_translate_block(body_node, source_bytes, filename))
        if body_node.type == "return_expression":
            return [ReturnStmt(value=_opaque(span), span=span)]
        if not _text(body_node).endswith(b";"):
            # Bare expression in arm body is an implicit return for the arm.
            return [ReturnStmt(value=_opaque(span), span=span)]
    return []


def _arm_body_or_empty(arm: Node) -> list[Node]:
    """Return a single-element list containing the ``value`` field
    of a ``match_arm`` (the right-hand side of ``=>``), or an empty
    list if no value field is present.

    List wrapping for the D11-honesty pattern shared with the other
    Optional-returning lookups.
    """
    for i, child in enumerate(arm.children):
        if arm.field_name_for_child(i) == "value":
            return [child]
    return []


def _translate_loop(node: Node, source_bytes: bytes, filename: str, span: SourceSpan) -> list[Any]:
    """Wrap a Rust loop expression as an ``IfStmt`` with an empty
    body and empty else_body, marking it as 'may run zero or N
    times'. The Python adapter does the same for ``for``/``while``/
    ``with``/``try``/``match``; this is the consistent pattern.

    A future phase might walk the loop body for conservative
    analysis, but the current implementation treats the whole loop as opaque.
    """
    return [
        IfStmt(
            condition=_opaque(span),
            body=(),
            span=span,
            else_body=(),
        )
    ]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _opaque(span: SourceSpan) -> IdentExpr:
    """Return a placeholder ``IdentExpr`` used for expressions whose
    value we do not need to preserve. D24 and D11 only inspect
    structure, not values.
    """
    return IdentExpr(name="__opaque__", span=span)


def _text(node: Node) -> bytes:
    """Return ``node.text`` asserting it is not None.

    tree-sitter types ``Node.text`` as ``bytes | None`` because the
    underlying tree may have been freed; in our pipeline the tree
    is held alive by the caller for the full duration of
    translation, so the bytes are always present. The assertion
    converts the strict-mypy union narrowing into a runtime check.
    """
    text: bytes | None = node.text
    assert text is not None, f"node.text was None for {node.type}"
    return text


def _named_first_or_empty(node: Node) -> list[Node]:
    """Return a single-element list containing the first named
    child, or an empty list if there is none.

    Wraps the optional in a list for the D11-honesty pattern.
    """
    children = node.named_children
    return [children[0]] if children else []


def _span(filename: str, line: int, col: int) -> SourceSpan:
    """Construct a Furqan ``SourceSpan`` for a Rust position."""
    return SourceSpan(file=filename, line=line, column=col)


# Keep ``cast`` referenced so ``ruff`` does not flag the import as
# unused; it is reserved for narrowing the tree-sitter ``Node | None``
# returns in future translator extensions.
_ = cast
