"""Public-name extraction for Go source files.

Used by the additive-only diff path (CLI ``furqan-lint diff
old.go new.go``). Mirrors ``furqan_lint.additive._extract_public_names``
in shape -- returns a frozenset of names exposed by a single
file -- but reads from the goast binary's ``public_names`` JSON
field rather than from a Python AST walk.

Symmetric with ``rust_adapter.public_names.extract_public_names``
(shipped in v0.8.2). Both extractors feed
``additive.compare_name_sets``. The v0.8.3 Rust adapter omits
impl-block methods (documented limit
``impl_methods_omitted.rs``); Go's goast emits qualified
``Type.Method`` names for 6 receiver shapes since v0.8.2.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def extract_public_names(path: Path | str) -> frozenset[str]:
    """Extract uppercase-initial Go identifiers from ``path``.

    The goast binary emits ``public_names`` as an ordered list of
    every identifier whose first rune is uppercase, regardless of
    declaration kind: top-level functions, type names, var/const
    names, AND method names. As of v0.8.2, method names are
    emitted with receiver-type qualification (``Counter.Foo``,
    ``Logger.Foo``); v0.8.1's bare-name false-negative (where
    distinct ``Foo`` methods on different receivers collapsed
    into one ``Foo`` entry, masking the removal of one of them)
    was retired in v0.8.2 by the goast change in
    ``cmd/goast/main.go``\'s ``receiverTypeName`` helper.

    Returns a frozenset so the caller can pass it directly to
    :func:`furqan_lint.additive.compare_name_sets` without
    additional conversion.

    Raises whatever the underlying ``parse_file`` raises:
    :class:`furqan_lint.go_adapter.GoExtrasNotInstalled` when the
    bundled goast binary is absent (and no
    ``FURQAN_LINT_GOAST_BIN`` env override is set), or
    :class:`furqan_lint.go_adapter.GoParseError` when goast
    cannot parse the source file (the CLI maps both to user-
    facing exit codes).
    """
    from furqan_lint.go_adapter import parse_file

    data: dict[str, Any] = parse_file(path)
    return frozenset(data.get("public_names", []))
