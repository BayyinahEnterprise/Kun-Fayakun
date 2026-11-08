"""Public-surface extraction for CASM v1.0 manifests.

Returns ``public_surface.names`` entries (each a dict with name +
kind + signature_fingerprint) sourced from a Python module's AST.
The function honors ``__all__`` semantics by delegating to the
existing additive-only checker's ``_extract_public_names``: when
``__all__`` is statically declared, only those names appear;
otherwise every top-level function, class, plain assignment, or
PEP 526 annotated assignment whose name does not start with an
underscore appears.

A ``DynamicAllError`` (from the existing additive-only checker)
propagates through this function. The CLI (T09) treats the
surfaced ``DynamicAllError`` as INDETERMINATE (exit 2) per the
nine-step verification flow, not as CASM-V-050/051.

Class methods of nested classes are tracked as `Outer.Inner.method`
inside the class signature dict (Phase G11.0 prompt T04). Locally
defined classes inside functions are omitted, consistent with
the documented limit at v0.3.x.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from furqan_lint.additive import DynamicAllError, _extract_public_names
from furqan_lint.gate11.signature_canonicalization import (
    class_signature_dict,
    constant_signature_dict,
    function_signature_dict,
    signature_fingerprint,
)


def extract_public_surface(path: Path | str) -> list[dict[str, Any]]:
    """Return the manifest's ``public_surface.names`` entry list.

    Each entry has ``name``, ``kind``, and
    ``signature_fingerprint``. Entries are ASCII-sorted by
    ``name``.

    Raises ``DynamicAllError`` (from
    ``furqan_lint.additive``) if ``__all__`` is dynamic. The
    Gate 11 CLI handles this exception as INDETERMINATE.
    """
    p = Path(path)
    source = p.read_text(encoding="utf-8")
    public_names = _extract_public_names(source)
    tree = ast.parse(source, filename=str(p))
    entries: list[dict[str, Any]] = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            if node.name in public_names:
                sig = function_signature_dict(node)
                entries.append(
                    {
                        "name": node.name,
                        "kind": "function",
                        "signature_fingerprint": signature_fingerprint(sig),
                    }
                )
        elif isinstance(node, ast.ClassDef):
            if node.name in public_names:
                sig = class_signature_dict(node)
                entries.append(
                    {
                        "name": node.name,
                        "kind": "class",
                        "signature_fingerprint": signature_fingerprint(sig),
                    }
                )
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id in public_names:
                sig = constant_signature_dict(node.target.id, node.annotation)
                entries.append(
                    {
                        "name": node.target.id,
                        "kind": "constant",
                        "signature_fingerprint": signature_fingerprint(sig),
                    }
                )
        elif isinstance(node, ast.Assign):
            # Plain assignments (no annotation) are emitted as
            # constants with annotation "None"; this matches the
            # additive-only checker's treatment of them as public
            # names.
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in public_names:
                    sig = constant_signature_dict(target.id, None)
                    entries.append(
                        {
                            "name": target.id,
                            "kind": "constant",
                            "signature_fingerprint": signature_fingerprint(sig),
                        }
                    )
                elif isinstance(target, ast.Tuple):
                    for elt in target.elts:
                        if isinstance(elt, ast.Name) and elt.id in public_names:
                            sig = constant_signature_dict(elt.id, None)
                            entries.append(
                                {
                                    "name": elt.id,
                                    "kind": "constant",
                                    "signature_fingerprint": signature_fingerprint(sig),
                                }
                            )
    # Some __all__ entries may be exported via re-import or runtime
    # binding rather than top-level definition; the existing
    # additive-only checker treats those as set members but we have
    # no AST node to fingerprint. Emit them with kind=constant +
    # annotation="None" so the manifest still commits to their
    # presence.
    seen = {e["name"] for e in entries}
    for missing in sorted(public_names - seen):
        sig = constant_signature_dict(missing, None)
        entries.append(
            {
                "name": missing,
                "kind": "constant",
                "signature_fingerprint": signature_fingerprint(sig),
            }
        )
    entries.sort(key=lambda e: e["name"])
    return entries


__all__ = (
    "DynamicAllError",
    "extract_public_surface",
)
