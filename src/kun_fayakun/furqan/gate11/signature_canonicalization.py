"""Per-name signature fingerprinting for CASM v1.0.

Each public name in a manifest carries a ``signature_fingerprint``
that is the SHA-256 of an RFC 8785 canonical JSON dict whose
shape depends on the kind:

* function: name, kind="function", parameters list (each with
  name + canonical annotation + default_present), return_annotation,
  is_async.
* class: name, kind="class", bases (canonicalized), method_names
  (ASCII-sorted public methods).
* constant: name, kind="constant", annotation (canonical type
  string).

Canonical type strings normalize:

* whitespace (single space; no newlines)
* PEP 604 unions: ``int | str`` and ``str | int`` both
  canonicalize to ``"int | str"``.
* Optionals: ``Optional[X]``, ``X | None``, ``Union[X, None]``,
  and ``Union[None, X]`` all canonicalize to ``"X | None"``.
* string-quoted forward references unwrap to their inner type.

Canonicalization failures (malformed annotation, unparseable
forward reference) record the original text and emit a
CASM-V-003 ADVISORY in the extraction log.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CanonicalizationAdvisory:
    """One CASM-V-003 ADVISORY surfaced during canonicalization.

    The Verifier (T08) and the surface extractor (T05) collect
    these without raising; the manifest is still emitted with the
    original text recorded so verification can complete.
    """

    name: str
    original: str
    reason: str


def _canonical_type_string(node: ast.AST | None) -> str:
    """Normalize an AST annotation to a canonical type string.

    Returns ``"None"`` when the input is None (no annotation).
    Returns the AST's ``ast.unparse`` form on canonicalization
    failure so the manifest still commits to something stable.
    """
    if node is None:
        return "None"
    # First, unwrap string-quoted forward references.
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        try:
            inner = ast.parse(node.value, mode="eval").body
            return _canonical_type_string(inner)
        except SyntaxError:
            return node.value
    # Optional[X] -> X | None
    if isinstance(node, ast.Subscript):
        sub_value = _node_name(node.value)
        if sub_value in {"Optional", "typing.Optional"}:
            inner_str = _canonical_type_string(node.slice)
            return _format_union([inner_str, "None"])
        if sub_value in {"Union", "typing.Union"}:
            union_members: list[ast.AST] = _flatten_tuple(node.slice)
            inner_strings = [_canonical_type_string(m) for m in union_members]
            # Phase G11.0.1 T03: flatten inner unions so
            # Union[Optional[T], List[U]] (== Union[T | None, List[U]])
            # canonicalizes with None positioned consistently per
            # _format_union's None-at-end convention. Without this,
            # the pre-v0.11.2 implementation produced
            # "List[U] | T | None" (alphabetical of two members,
            # "T | None" treated as a single opaque string) where
            # the canonical form should be "List[U] | T | None"
            # (alphabetical of three members; None at end).
            flattened: list[str] = []
            for s in inner_strings:
                if " | " in s:
                    flattened.extend(part.strip() for part in s.split(" | "))
                else:
                    flattened.append(s)
            return _format_union(flattened)
        # Generic subscript like List[int] or Dict[K, V] --
        # normalize to "List[<canonical>]" or "Dict[<canonical>, <canonical>]".
        # Phase G11.0.1 (at-Tawbah) T03 / audit H-4 propagation
        # defense: a multi-argument generic's slice is an
        # ast.Tuple whose elements MUST recurse element-wise.
        # The pre-v0.11.2 implementation fell through to
        # ast.unparse(node.slice) for tuple slices, producing
        # "Dict[(str, int)]" instead of "Dict[str, int]" -- the
        # exact tuple-stringification failure mode that the
        # Rust verifier's amended_4 T03 rules 6 + 7 already
        # defend against. Cross-language symmetry is restored
        # in v0.11.2 by handling the Tuple slice case here.
        if isinstance(node.slice, ast.Tuple):
            inner_parts = [_canonical_type_string(elem) for elem in node.slice.elts]
            return f"{sub_value}[{', '.join(inner_parts)}]"
        slice_str = _canonical_type_string(node.slice)
        return f"{sub_value}[{slice_str}]"
    # X | Y union via PEP 604
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left = _canonical_type_string(node.left)
        right = _canonical_type_string(node.right)
        # Recursively flatten nested unions to a flat list.
        binop_members: list[str] = []
        for s in (left, right):
            if " | " in s:
                binop_members.extend(part.strip() for part in s.split(" | "))
            else:
                binop_members.append(s)
        return _format_union(binop_members)
    if isinstance(node, ast.Tuple):
        # Tuple in annotation context (e.g., inside Union[X, Y])
        # is a list of types; the caller (Subscript path) handles
        # this. Falling here means a literal tuple annotation
        # which is uncommon; render via unparse.
        return ast.unparse(node)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _node_name(node)
    if isinstance(node, ast.Constant):
        if node.value is None:
            return "None"
        return repr(node.value)
    # Fallback: the safest deterministic stringification.
    try:
        return ast.unparse(node)
    except Exception:
        return "<unparseable>"


def _node_name(node: ast.AST | None) -> str:
    """Return a string name for a Name or Attribute node, or ``""``."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _node_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _flatten_tuple(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, ast.Tuple):
        return list(node.elts)
    return [node]


def _format_union(members: list[str]) -> str:
    """Sort union members alphabetically; collapse Optional sentinel.

    Per the spec: ``Optional[X]`` and ``X | None`` both produce
    ``"X | None"``. We sort the non-None members alphabetically
    and append ``None`` at the end if present (so the canonical
    form for Optional is consistent regardless of input source).
    """
    seen: set[str] = set()
    deduped: list[str] = []
    for m in members:
        if m not in seen:
            seen.add(m)
            deduped.append(m)
    has_none = "None" in deduped
    others = sorted(s for s in deduped if s != "None")
    if has_none:
        # If the only members are X and None, render as "X | None"
        # canonical Optional form. For multi-member unions with None,
        # keep None at the end after sorting the rest.
        return " | ".join([*others, "None"])
    return " | ".join(sorted(deduped))


def function_signature_dict(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> dict[str, Any]:
    """Build the signature dict for a function or async-function.

    Per spec: name, kind, parameters list (in source order),
    return_annotation, is_async.
    """
    parameters: list[dict[str, Any]] = []
    args = node.args
    # Combine posonly + args + vararg + kwonly + kwarg in source order.
    # The defaults are right-aligned across posonly+args; kw_defaults
    # align 1:1 with kwonly args.
    pos_args = list(args.posonlyargs) + list(args.args)
    n_defaults = len(args.defaults)
    # Among pos_args, the last n_defaults have defaults present.
    for i, a in enumerate(pos_args):
        default_present = i >= len(pos_args) - n_defaults
        parameters.append(
            {
                "name": a.arg,
                "annotation": _canonical_type_string(a.annotation),
                "default_present": bool(default_present),
            }
        )
    if args.vararg is not None:
        parameters.append(
            {
                "name": "*" + args.vararg.arg,
                "annotation": _canonical_type_string(args.vararg.annotation),
                "default_present": False,
            }
        )
    for a, d in zip(args.kwonlyargs, args.kw_defaults, strict=False):
        parameters.append(
            {
                "name": a.arg,
                "annotation": _canonical_type_string(a.annotation),
                "default_present": d is not None,
            }
        )
    if args.kwarg is not None:
        parameters.append(
            {
                "name": "**" + args.kwarg.arg,
                "annotation": _canonical_type_string(args.kwarg.annotation),
                "default_present": False,
            }
        )
    return {
        "name": node.name,
        "kind": "function",
        "parameters": parameters,
        "return_annotation": _canonical_type_string(node.returns),
        "is_async": isinstance(node, ast.AsyncFunctionDef),
    }


def class_signature_dict(node: ast.ClassDef) -> dict[str, Any]:
    """Build the signature dict for a class.

    Per spec: name, kind, bases (canonicalized), method_names
    (ASCII-sorted public methods).

    Method signatures are NOT included in v1.0; only the names.
    """
    bases = [_canonical_type_string(b) for b in node.bases]
    methods: list[str] = []
    for stmt in node.body:
        if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef) and not stmt.name.startswith(
            "_"
        ):
            methods.append(stmt.name)
    methods.sort()
    return {
        "name": node.name,
        "kind": "class",
        "bases": bases,
        "method_names": methods,
    }


def constant_signature_dict(name: str, annotation: ast.AST | None) -> dict[str, Any]:
    """Build the signature dict for a top-level annotated assignment.

    Per spec: name, kind, annotation. The constant value is NOT
    included; CASM v1.0 commits to existence and type, not value.
    """
    return {
        "name": name,
        "kind": "constant",
        "annotation": _canonical_type_string(annotation),
    }


def signature_fingerprint(sig_dict: dict[str, Any]) -> str:
    """Return SHA-256 of the RFC 8785 canonical bytes of ``sig_dict``."""
    import rfc8785

    canonical = rfc8785.dumps(sig_dict)
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


__all__ = (
    "CanonicalizationAdvisory",
    "class_signature_dict",
    "constant_signature_dict",
    "function_signature_dict",
    "signature_fingerprint",
)
