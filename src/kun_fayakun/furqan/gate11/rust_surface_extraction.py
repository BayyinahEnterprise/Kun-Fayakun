"""Phase G11.1 (as-Saffat): Rust public-surface extraction for CASM v1.0.

Extracts the public surface of a Rust source file into the
shape expected by the CASM v1.0 manifest schema's
``public_surface.names`` field. Each entry is a dict with
``name``, ``kind``, and ``signature_fingerprint``.

The extractor walks the tree-sitter-rust CST top-level items
and emits an ASCII-sorted list of public-surface entries. The
extraction method registered in the manifest is
``tree-sitter.rust-public-surface@v1.0`` per Phase G11.A
Invariant 5.

Disease-model framing (per amended_2 audit F4): this module
PINS the current furqan-lint Rust adapter's
``extract_public_names`` semantics as documented limits in
the Sigstore-CASM substrate. It does NOT change the adapter's
behaviour. The choices below (impl-block methods omitted,
``pub(crate)`` / ``pub(super)`` excluded, items inside non-
``pub`` modules excluded) match the existing adapter so the
two views of "public" stay in sync.

Item kinds emitted in ``public_surface.names`` per amended_4
T03:

- ``function``: top-level ``pub fn``
- ``struct``: top-level ``pub struct``
- ``enum``: top-level ``pub enum``
- ``trait``: top-level ``pub trait`` (NOT in legacy
  extract_public_names; added by Phase G11.1 because traits
  are part of the externally-visible API surface)
- ``type_alias``: top-level ``pub type``
- ``constant``: top-level ``pub const`` and ``pub static``
- ``alias``: top-level ``pub use ...`` re-exports

The kind names come from the prompt's per-kind canonical-form
table in T03; the canonicalization itself lives in
``rust_signature_canonicalization``.

Dynamic ``pub use *`` glob re-exports are surfaced as a
``CASM-V-INDETERMINATE`` sentinel name (caller is expected to
treat the manifest as indeterminate per Phase G11.A
Invariant 6 step 8) rather than silently producing a false-pass.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass


class RustGate11ExtrasNotInstalled(ImportError):
    """Raised when [gate11-rust] extras are absent at extract time.

    The CLI converts to exit code 1 with the install hint
    ``pip install furqan-lint[gate11-rust]``.
    """


class DynamicRustSurfaceError(Exception):
    """Raised when the .rs file's public surface cannot be
    statically determined (e.g., glob ``pub use *`` re-export).

    Step 8 of the verification flow surfaces this as
    ``CASM-V-INDETERMINATE`` rather than a false pass; see
    Phase G11.A Invariant 6.
    """


# Tree-sitter-rust grammar node types -> CASM v1.0 kind strings.
_KIND_MAP: dict[str, str] = {
    "function_item": "function",
    "struct_item": "struct",
    "enum_item": "enum",
    "trait_item": "trait",
    "type_item": "type_alias",
    "const_item": "constant",
    "static_item": "constant",
    "use_declaration": "alias",
}

# Name-node types in tree-sitter-rust grammar.
_NAME_NODE_TYPES: frozenset[str] = frozenset({"identifier", "type_identifier"})


def extract_public_surface_rust(path: Path | str) -> list[dict[str, str]]:
    """Return the ASCII-sorted public-surface list for a Rust file.

    Each entry is a dict with keys ``name``, ``kind``, and
    ``signature_fingerprint`` (the latter computed via
    :mod:`furqan_lint.gate11.rust_signature_canonicalization`).

    Raises :class:`RustGate11ExtrasNotInstalled` if the
    ``[gate11-rust]`` extra is not installed.

    Raises :class:`DynamicRustSurfaceError` if the file
    contains a glob re-export (``pub use ...::*``) that cannot
    be statically resolved.
    """
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_rust  # noqa: F401
    except ImportError as e:
        raise RustGate11ExtrasNotInstalled(
            "Rust Gate 11 support not installed. Run: " "pip install furqan-lint[gate11-rust]"
        ) from e

    from furqan_lint.gate11.rust_signature_canonicalization import (
        signature_fingerprint_rust,
    )
    from furqan_lint.rust_adapter.parser import parse_source
    from furqan_lint.rust_adapter.translator import _assert_parses_cleanly

    source_path = Path(path)
    source_bytes = source_path.read_bytes()
    tree = parse_source(source_bytes)
    _assert_parses_cleanly(tree, source_path)

    entries: list[dict[str, str]] = []
    for child in tree.root_node.children:
        if child.type not in _KIND_MAP:
            continue
        if not _has_unrestricted_pub(child):
            continue
        kind = _KIND_MAP[child.type]
        for name in _extract_names(child, kind, source_bytes):
            fingerprint = signature_fingerprint_rust(child, name, kind, source_bytes)
            entries.append(
                {
                    "name": name,
                    "kind": kind,
                    "signature_fingerprint": fingerprint,
                }
            )

    entries.sort(key=lambda e: e["name"])
    return entries


def _has_unrestricted_pub(node: Any) -> bool:
    """Return True iff ``node`` has a ``visibility_modifier`` whose
    decoded text is exactly ``b"pub"`` (no ``pub(crate)`` etc.).
    """
    for child in node.children:
        if child.type == "visibility_modifier":
            return bool(child.text == b"pub")
    return False


def _extract_names(node: Any, kind: str, source_bytes: bytes) -> list[str]:
    """Return the declared name(s) for an item node.

    Most item kinds have a single name. ``use_declaration``
    can declare multiple names (``pub use foo::{a, b, c}``);
    ``pub use foo::*`` raises :class:`DynamicRustSurfaceError`.
    """
    if kind == "alias":
        return _extract_use_names(node, source_bytes)
    for child in node.children:
        if child.type in _NAME_NODE_TYPES:
            return [str(child.text.decode())]
    return []


def _extract_use_names(node: Any, source_bytes: bytes) -> list[str]:
    """Extract the names exposed by a ``pub use`` re-export.

    Glob re-exports (``pub use foo::*``) cannot be statically
    resolved; they raise :class:`DynamicRustSurfaceError` so the
    verifier can mark the manifest indeterminate per Phase
    G11.A Invariant 6.
    """
    text = node.text.decode("utf-8", errors="replace")
    if "::*" in text or text.endswith("*;"):
        raise DynamicRustSurfaceError(
            "pub use glob re-export cannot be statically resolved; "
            "Phase G11.1 surface extraction surfaces "
            "CASM-V-INDETERMINATE for this module"
        )
    # Collect all leaf identifiers under the use_declaration.
    # The last identifier in any path is the re-exported name
    # unless an "as" alias is present (in which case the alias
    # is the name).
    names: list[str] = []
    _collect_use_leaf_names(node, names)
    return names


def _collect_use_leaf_names(node: Any, out: list[str]) -> None:
    """Walk a use_declaration tree and collect re-exported names.

    Names emerge from:
    - ``use_as_clause``: the alias identifier wins
    - ``scoped_use_list``: each item in the list contributes
    - bare ``scoped_identifier``: the final identifier is the name
    """
    nt = node.type
    if nt == "use_as_clause":
        # The alias ID is the last identifier child.
        for child in reversed(list(node.children)):
            if child.type in _NAME_NODE_TYPES:
                out.append(str(child.text.decode()))
                return
        return
    if nt == "scoped_use_list":
        # Recurse into the list's items.
        for child in node.children:
            _collect_use_leaf_names(child, out)
        return
    if nt == "use_list":
        for child in node.children:
            _collect_use_leaf_names(child, out)
        return
    if nt == "scoped_identifier":
        # Take the last identifier in the path.
        last_name = None
        for child in node.children:
            if child.type in _NAME_NODE_TYPES:
                last_name = str(child.text.decode())
        if last_name is not None:
            out.append(last_name)
        return
    if nt in _NAME_NODE_TYPES:
        out.append(str(node.text.decode()))
        return
    # Otherwise recurse.
    for child in node.children:
        _collect_use_leaf_names(child, out)
