"""Tree-sitter parser bootstrap for the Rust adapter.

Wraps the tree-sitter-rust grammar in a lazily-initialised Parser
singleton. The Language handle is constructed once per process and
reused; tree-sitter's Python bindings are thread-safe for parsing
(each ``Parser.parse(...)`` call is independent), so the singleton
imposes no concurrency penalty.

The module imports tree_sitter and tree_sitter_rust at function-call
time, not at import time, so that the broader furqan_lint package
remains importable on installs without the ``[rust]`` extra. See
``furqan_lint.rust_adapter.__init__`` for the lazy-import gate.
"""

from __future__ import annotations

from functools import cache
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from tree_sitter import Tree


@cache
def _get_parser() -> Any:
    """Return a memoised ``tree_sitter.Parser`` configured for Rust.

    Memoised via ``functools.cache``: initialises on first call,
    subsequent calls return the same instance. Imports tree_sitter
    and tree_sitter_rust at call time; if either is missing,
    ``ImportError`` propagates and the CLI's lazy-import gate
    converts it to a user-facing install hint.
    """
    import tree_sitter
    import tree_sitter_rust

    language = tree_sitter.Language(tree_sitter_rust.language())
    return tree_sitter.Parser(language)


def parse_source(source: bytes) -> Tree:
    """Parse a Rust source byte-string and return a tree-sitter Tree.

    The caller is responsible for ``has_error`` checking; this
    function never raises on a parse error (tree-sitter recovers
    locally and returns a partial tree). The translator's
    ``_assert_parses_cleanly`` is the gate that refuses partial
    parses and exits with code 2.
    """
    parser = _get_parser()
    tree: Tree = parser.parse(source)
    return tree


def parse_file(path: Path) -> Tree:
    """Read a file and parse it. Convenience wrapper around
    ``parse_source`` for the common path-based call.
    """
    return parse_source(path.read_bytes())
