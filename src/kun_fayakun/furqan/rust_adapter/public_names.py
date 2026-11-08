"""Public-name extraction for Rust source files.

Used by the additive-only diff path (CLI ``furqan-lint diff
old.rs new.rs``). Mirrors
``furqan_lint.go_adapter.public_names.extract_public_names`` in
shape -- returns a frozenset of names exposed by a single file
-- but reads from a tree-sitter CST walk over the Rust grammar
rather than from a JSON binary's emit field.

Implementation uses ``parse_source`` from
``furqan_lint.rust_adapter.parser`` (the existing tree-sitter
direct-bindings entry point); does NOT use
``tree_sitter_languages`` (NOT a project dependency).

Visibility scope (locked decision 2): ``pub`` only. Crate-
private items (``pub(crate)``, ``pub(super)``,
``pub(in path::...)``) are not part of the external API surface
and are skipped.

Item kinds (locked decision 3): ``function_item``,
``struct_item``, ``enum_item``, ``const_item``, ``static_item``,
``type_item``, ``mod_item``. ``trait_item`` is out of scope for
v0.8.2 (a future phase may add it once a concrete consumer
needs trait-name diffing).

Method names are NOT collected here. The Rust adapter walks
only top-level items; methods inside ``impl Type { ... }``
blocks are intentionally omitted in v0.8.3 (registered as
documented limit ``impl_methods_omitted.rs`` and a v0.8.4
candidate for change). This is asymmetric with Go: as of
v0.8.2, goast emits qualified method names like
``Counter.Foo`` (shipped in v0.8.2); the Rust counterpart is
not yet implemented. See
``tests/fixtures/rust/documented_limits/impl_methods_omitted.rs``.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass


# Tree-sitter Rust grammar node types that represent top-level
# items eligible for ``pub`` visibility. trait_item omitted per
# locked decision 3.
_PUB_ITEM_TYPES: frozenset[str] = frozenset(
    {
        "function_item",
        "struct_item",
        "enum_item",
        "const_item",
        "static_item",
        "type_item",
        "mod_item",
    }
)

# Tree-sitter Rust grammar node types whose decoded text is the
# declared name of an item. ``identifier`` covers
# function/const/static/mod; ``type_identifier`` covers
# struct/enum/type alias.
_NAME_NODE_TYPES: frozenset[str] = frozenset({"identifier", "type_identifier"})


def extract_public_names(path: Path | str) -> frozenset[str]:
    """Return the ``pub`` item names declared in a Rust source file.

    Walks the tree-sitter CST root's children; for each child
    whose type is in :data:`_PUB_ITEM_TYPES`, checks the
    visibility modifier and (if unrestricted ``pub``) extracts
    the item's name node text.

    Raises :class:`furqan_lint.rust_adapter.RustExtrasNotInstalled`
    if the ``[rust]`` extra is not installed (the CLI converts
    to exit code 1 plus the install hint).

    Raises :class:`furqan_lint.rust_adapter.RustParseError` if
    the source contains a syntax error or missing tokens (the
    CLI converts to exit code 2 plus a PARSE ERROR diagnostic
    on stdout). The check is delegated to the translator's
    ``_assert_parses_cleanly`` so the diff path uses the same
    parse-error definition as the lint path. Added in v0.8.3
    to close the round-21 HIGH finding: prior to this gate,
    a malformed ``.rs`` file silently parsed to an empty
    public-name set, producing a false MARAD on every name
    that existed in the well-formed file (or a false PASS
    when both sides were broken).
    """
    # Probe the [rust] extras at the entry point so a missing-
    # extras case raises RustExtrasNotInstalled (caught by the
    # CLI's _check_rust_additive helper as a typed exception)
    # rather than letting ModuleNotFoundError propagate up from
    # deep inside parser._get_parser. Same pattern as
    # rust_adapter.parse_file (added in v0.7.0.1 fix (a)).
    try:
        import tree_sitter  # noqa: F401  - presence probe only
        import tree_sitter_rust  # noqa: F401  - presence probe only
    except ImportError as e:
        from furqan_lint.rust_adapter import RustExtrasNotInstalled

        raise RustExtrasNotInstalled(
            "Rust support not installed. Run: pip install furqan-lint[rust]"
        ) from e
    from furqan_lint.rust_adapter.parser import parse_source
    from furqan_lint.rust_adapter.translator import _assert_parses_cleanly

    source_path = Path(path)
    tree = parse_source(source_path.read_bytes())
    _assert_parses_cleanly(tree, source_path)
    names: set[str] = set()
    for child in tree.root_node.children:
        if child.type not in _PUB_ITEM_TYPES:
            continue
        if not _has_unrestricted_pub(child):
            continue
        name_list = _item_name_or_empty(child)
        names.update(name_list)
    return frozenset(names)


def _has_unrestricted_pub(node: Any) -> bool:
    """Return True iff ``node`` has a ``visibility_modifier``
    child whose decoded text is exactly ``b"pub"`` (no
    ``pub(crate)``, ``pub(super)``, or ``pub(in ...)``
    qualifier).
    """
    for child in node.children:
        if child.type == "visibility_modifier":
            return bool(child.text == b"pub")
    return False


def _item_name_or_empty(node: Any) -> list[str]:
    """Return a single-element list containing the decoded
    name of an item ``node``, or an empty list if no name node
    is found (defensive; in practice every well-formed item
    node has one).

    The list shape (vs. ``str | None``) keeps the optional out
    of the function signature so D11 does not see a may-fail
    producer (the absence-of-name-node is a structural
    distinction, not a may-fail status). The caller does
    ``names.update(_item_name_or_empty(child))`` to recover the
    optional at the assignment boundary, matching the Rust and
    Go translators\' ``..._or_empty`` shape.
    """
    for child in node.children:
        if child.type in _NAME_NODE_TYPES:
            return [str(child.text.decode())]
    return []
