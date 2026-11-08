"""Rust adapter: parse .rs files into a Furqan ``Module`` for D24 + D11.

Opt-in via the ``[rust]`` extra:

    pip install furqan-lint[rust]

The package is importable without the extra (the CLI does not import
this module unless asked to lint a ``.rs`` file), so the
Python-only install path remains unaffected. tree-sitter is imported
lazily inside ``parse_file``; importing this package alone does not
trigger a ``tree_sitter`` import.

If ``parse_file`` is called and tree-sitter is missing, it raises
``RustExtrasNotInstalled`` (a subclass of ``ImportError``) with the
install hint as its message. The CLI catches this typed exception
and prints a calm one-line install hint instead of dumping a Python
traceback. v0.7.0.1 fix: in v0.7.0 the missing-extras case
crashed with a raw ModuleNotFoundError traceback because the
deferred import inside ``parser._get_parser`` was not wrapped.

Public surface
==============

* ``parse_file(path)`` -> ``Module``: parse a Rust source file and
  return the translated Furqan ``Module``.
* ``extract_public_names(path)`` -> ``frozenset[str]``: return
  the ``pub`` item names declared in ``path``. Used by the
  additive-only diff path
  (``furqan-lint diff old.rs new.rs``). Added in v0.8.2.
* ``RustParseError``: raised when the Rust source contains a syntax
  error or missing tokens; the CLI converts this to exit code 2.
* ``RustExtrasNotInstalled``: raised when the ``[rust]`` extra is
  missing from the install. CLI converts to exit code 1 plus the
  install hint.

Everything else (the parser singleton, the translator internals,
the edition resolver) is intentionally not exported. v0.7.x and
later can expand the surface using the ``__all__``-snapshot
additive-only discipline pinned by
``tests/test_rust_public_surface_additive.py``.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from furqan.parser.ast_nodes import Module

from furqan_lint.rust_adapter.translator import (
    RustExtrasNotInstalled,
    RustParseError,
)

__all__ = (
    "RustExtrasNotInstalled",
    "RustParseError",
    "extract_public_names",
    "parse_file",
)


def parse_file(path: Path) -> Module:
    """Parse ``path`` as Rust source and return a Furqan ``Module``.

    Probes the ``tree_sitter`` and ``tree_sitter_rust`` imports
    at the entry point of this function. If either is missing,
    raises ``RustExtrasNotInstalled`` (a subclass of ``ImportError``)
    with the install hint as its message. The CLI catches this typed
    exception and prints a one-line install hint without a Python
    traceback.

    Raises ``RustParseError`` if the source contains a syntax error
    (recoverable parse errors and missing tokens are both caught
    via ``tree.root_node.has_error``).
    """
    # Fix (a) for v0.7.0.1: probe the extras imports here so the
    # call site (not just the package import) trips on missing
    # extras. Without this, the ImportError fires deep inside
    # parser._get_parser and surfaces as a raw traceback to the
    # user, violating prompt section 3.3 ("Do not crash with
    # ModuleNotFoundError").
    try:
        import tree_sitter  # noqa: F401  - presence probe only
        import tree_sitter_rust  # noqa: F401  - presence probe only
    except ImportError as e:
        raise RustExtrasNotInstalled(
            "Rust support not installed. Run: pip install furqan-lint[rust]"
        ) from e

    from furqan_lint.rust_adapter.edition import edition_for
    from furqan_lint.rust_adapter.parser import parse_file as _parse_file
    from furqan_lint.rust_adapter.translator import translate_tree

    tree = _parse_file(path)
    edition = edition_for(path)
    return translate_tree(tree, path.read_bytes(), path, edition=edition)


def extract_public_names(path: Path | str) -> frozenset[str]:
    """Return ``pub`` item names declared in ``path``.

    Lazy-imports
    ``furqan_lint.rust_adapter.public_names.extract_public_names``
    so this package's import path does not require tree-sitter to
    be present (the missing-extras case is handled inside the
    helper, which raises :class:`RustExtrasNotInstalled` with the
    install hint).
    """
    from furqan_lint.rust_adapter.public_names import (
        extract_public_names as _extract,
    )

    if isinstance(path, Path):
        return _extract(path)
    return _extract(Path(str(path)))
