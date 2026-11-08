"""Phase G11.1 (as-Saffat): canonical signatures for Rust public surface.

Computes per-name canonical signatures for the CASM v1.0
manifest's ``public_surface.names`` field. Each signature dict
is RFC 8785 (JCS) canonicalized and SHA-256 hashed into the
``signature_fingerprint`` value.

Per-kind canonical forms (from amended_4 T03):

- ``function``: name + parameters + return_type + is_unsafe
  + is_async
- ``struct``: name + fields (each with name, type, is_pub)
- ``enum``: name + variants
- ``trait``: name + method_names
- ``type_alias``: name + target_type
- ``constant``: name + type + is_static
- ``alias``: name + target_path

Canonical type strings (from amended_4 T03 rules 1-7):

  1. Whitespace collapsed
  2. Lifetimes stripped (consistent with existing translator
     behaviour; documented as ``lifetime_stripped_from_signature``
     limit)
  3. Generic parameters preserved in canonical form
  4. Trait objects retain ``dyn`` keyword; bounds beyond the
     first identifier stripped
  5. Reference types preserve ``&`` and ``&mut``; lifetimes dropped
  6. Nested generics MUST recurse element-wise -- this rule is
     the substrate-side defense against the audit H-4 failure
     mode (Phase G11.0 v0.10.0's Python implementation fell
     through to ``ast.unparse(node.slice)`` for multi-argument
     generics, producing tuple-stringification artifacts)
  7. Multi-argument generic parameters MUST be iterated as AST
     nodes, NOT stringified as a single opaque tuple

The canonicalizer iterates tree-sitter-rust AST nodes
explicitly. There is no ``ast.unparse``-equivalent fallthrough.

Disease-model framing (per amended_2 audit F4): this module
PINS the current furqan-lint Rust adapter's signature-extraction
choices (lifetime stripping, trait-object literal-text signing,
generic parameter preservation with bounds elided after ``:``)
as documented limits in the Sigstore-CASM substrate. Improving
these is a v1.5 horizon item.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass


def signature_fingerprint_rust(node: Any, name: str, kind: str, source_bytes: bytes) -> str:
    """Compute the canonical signature fingerprint for a public item.

    Returns ``"sha256:<hex64>"``.

    Args:
        node: the tree-sitter-rust node for the item.
        name: the item's name (already extracted by the surface
            extractor).
        kind: one of ``"function"``, ``"struct"``, ``"enum"``,
            ``"trait"``, ``"type_alias"``, ``"constant"``,
            ``"alias"``.
        source_bytes: the raw module source bytes (used for
            slicing tree-sitter offsets when needed).
    """
    if kind == "function":
        sig = _function_signature_dict(node, name, source_bytes)
    elif kind == "struct":
        sig = _struct_signature_dict(node, name, source_bytes)
    elif kind == "enum":
        sig = _enum_signature_dict(node, name, source_bytes)
    elif kind == "trait":
        sig = _trait_signature_dict(node, name, source_bytes)
    elif kind == "type_alias":
        sig = _type_alias_signature_dict(node, name, source_bytes)
    elif kind == "constant":
        sig = _constant_signature_dict(node, name, source_bytes)
    elif kind == "alias":
        sig = _alias_signature_dict(node, name, source_bytes)
    else:
        raise ValueError(f"unknown kind: {kind!r}")

    import rfc8785

    canonical = rfc8785.dumps(sig)
    digest = hashlib.sha256(canonical).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------
# Per-kind signature dict builders
# ---------------------------------------------------------------


def _function_signature_dict(node: Any, name: str, src: bytes) -> dict[str, Any]:
    parameters: list[dict[str, str]] = []
    return_type: str | None = None
    is_unsafe = False
    is_async = False

    for child in node.children:
        ct = child.type
        text = child.text.decode("utf-8", errors="replace")
        if ct == "function_modifiers":
            if "unsafe" in text:
                is_unsafe = True
            if "async" in text:
                is_async = True
        elif ct == "parameters":
            parameters = _extract_function_parameters(child)
        elif ct == "return_type":
            # The return_type node wraps the actual type node.
            return_type = _canonical_return_type(child)

    return {
        "name": name,
        "kind": "function",
        "parameters": parameters,
        "return_type": return_type,
        "is_unsafe": is_unsafe,
        "is_async": is_async,
    }


def _extract_function_parameters(
    parameters_node: Any,
) -> list[dict[str, str]]:
    """Extract ``parameters`` children -> list of {name, type}."""
    result: list[dict[str, str]] = []
    for child in parameters_node.children:
        if child.type != "parameter":
            continue
        param_name = ""
        param_type = ""
        # The parameter node's grammar: pattern : type
        # Walk children: first identifier is name, after `:` is type
        seen_colon = False
        for sub in child.children:
            sub_type = sub.type
            sub_text = sub.text.decode("utf-8", errors="replace")
            if not seen_colon and sub_type in (
                "identifier",
                "self_parameter",
                "_pattern",
            ):
                param_name = sub_text
            elif sub_text == ":":
                seen_colon = True
            elif seen_colon:
                param_type = _canonical_type_from_node(sub)
                break
        # Default fallback if grammar variant differs.
        if not param_name:
            for sub in child.children:
                if sub.type == "identifier":
                    param_name = sub.text.decode("utf-8", errors="replace")
                    break
        if not param_type:
            text = child.text.decode("utf-8", errors="replace")
            if ":" in text:
                _, _, after = text.partition(":")
                param_type = _canonical_type_string_from_text(after)
        result.append({"name": param_name, "type": param_type})
    return result


def _canonical_return_type(return_type_node: Any) -> str | None:
    """Extract the canonical return type from a ``return_type`` node.

    The grammar shape is ``-> <type>``. Returns None for the
    unit return (``()`` implicit).
    """
    # Walk children; the last non-arrow child is the type.
    for child in return_type_node.children:
        if child.type in ("->", "arrow"):
            continue
        canonical = _canonical_type_from_node(child)
        if canonical:
            return canonical
    # Fallback: parse from raw text.
    text = return_type_node.text.decode("utf-8", errors="replace")
    if "->" in text:
        _, _, after = text.partition("->")
        return _canonical_type_string_from_text(after)
    return None


def _struct_signature_dict(node: Any, name: str, src: bytes) -> dict[str, Any]:
    fields: list[dict[str, Any]] = []
    for child in node.children:
        if child.type == "field_declaration_list":
            for fd in child.children:
                if fd.type == "field_declaration":
                    fields.append(_extract_field(fd))
        elif child.type == "ordered_field_declaration_list":
            # Tuple struct: pub struct X(pub T);
            idx = 0
            for fd in child.children:
                if fd.type in ("(", ")", ","):
                    continue
                fields.append(
                    {
                        "name": str(idx),
                        "type": _canonical_type_from_node(fd),
                        "is_pub": _has_unrestricted_pub_inline(fd),
                    }
                )
                idx += 1
    return {
        "name": name,
        "kind": "struct",
        "fields": fields,
    }


def _extract_field(fd: Any) -> dict[str, Any]:
    field_name = ""
    field_type = ""
    is_pub = False
    seen_colon = False
    for sub in fd.children:
        st = sub.type
        text = sub.text.decode("utf-8", errors="replace")
        if st == "visibility_modifier":
            is_pub = bool(sub.text == b"pub")
        elif not seen_colon and st in (
            "field_identifier",
            "identifier",
        ):
            field_name = text
        elif text == ":":
            seen_colon = True
        elif seen_colon and not field_type:
            field_type = _canonical_type_from_node(sub)
    return {
        "name": field_name,
        "type": field_type,
        "is_pub": is_pub,
    }


def _has_unrestricted_pub_inline(node: Any) -> bool:
    for child in node.children:
        if child.type == "visibility_modifier" and child.text == b"pub":
            return True
    return False


def _enum_signature_dict(node: Any, name: str, src: bytes) -> dict[str, Any]:
    variants: list[str] = []
    for child in node.children:
        if child.type == "enum_variant_list":
            for v in child.children:
                if v.type == "enum_variant":
                    for sub in v.children:
                        if sub.type in (
                            "identifier",
                            "type_identifier",
                        ):
                            variants.append(sub.text.decode("utf-8", errors="replace"))
                            break
    return {
        "name": name,
        "kind": "enum",
        "variants": variants,
    }


def _trait_signature_dict(node: Any, name: str, src: bytes) -> dict[str, Any]:
    method_names: list[str] = []
    for child in node.children:
        if child.type == "declaration_list":
            for d in child.children:
                if d.type in ("function_signature_item", "function_item"):
                    for sub in d.children:
                        if sub.type == "identifier":
                            method_names.append(sub.text.decode("utf-8", errors="replace"))
                            break
    method_names.sort()
    return {
        "name": name,
        "kind": "trait",
        "method_names": method_names,
    }


def _type_alias_signature_dict(node: Any, name: str, src: bytes) -> dict[str, Any]:
    target_type = ""
    seen_eq = False
    for child in node.children:
        text = child.text.decode("utf-8", errors="replace")
        if text == "=":
            seen_eq = True
            continue
        if seen_eq and child.type not in (";",):
            target_type = _canonical_type_from_node(child)
            break
    return {
        "name": name,
        "kind": "type_alias",
        "target_type": target_type,
    }


def _constant_signature_dict(node: Any, name: str, src: bytes) -> dict[str, Any]:
    is_static = node.type == "static_item"
    type_str = ""
    seen_colon = False
    for child in node.children:
        text = child.text.decode("utf-8", errors="replace")
        if text == ":":
            seen_colon = True
            continue
        if seen_colon and not type_str and text not in ("=", ";"):
            type_str = _canonical_type_from_node(child)
            break
    return {
        "name": name,
        "kind": "constant",
        "type": type_str,
        "is_static": is_static,
    }


def _alias_signature_dict(node: Any, name: str, src: bytes) -> dict[str, Any]:
    text = node.text.decode("utf-8", errors="replace")
    # Strip "pub use " prefix and trailing ";"
    text = text.strip().removeprefix("pub use ").rstrip(";").strip()
    # If there's an "as <alias>" clause for this name, use the path.
    target_path = text
    return {
        "name": name,
        "kind": "alias",
        "target_path": target_path,
    }


# ---------------------------------------------------------------
# Canonical type-string construction (rules 1-7 from T03)
# ---------------------------------------------------------------


def _canonical_type_from_node(node: Any) -> str:  # noqa: PLR0915
    """Build the canonical type string from a tree-sitter type node.

    This is the H-4 propagation defense: we walk the AST and
    recurse element-wise on nested generic types. We do NOT
    fall through to a stringification of multi-argument generic
    parameter nodes.
    """
    nt = node.type

    # Primitive / leaf types
    if nt in ("primitive_type", "type_identifier", "identifier"):
        return _strip_whitespace(node.text.decode("utf-8", errors="replace"))

    if nt in ("scoped_type_identifier", "scoped_identifier"):
        # e.g. std::io::Error
        return _strip_whitespace(node.text.decode("utf-8", errors="replace"))

    if nt == "unit_type":
        return "()"

    if nt == "tuple_type":
        inner: list[str] = []
        for child in node.children:
            if child.type in ("(", ")", ","):
                continue
            inner.append(_canonical_type_from_node(child))
        return "(" + ", ".join(inner) + ")"

    if nt in ("array_type", "slice_type"):
        # [T] or [T; N]
        inner_parts: list[str] = []
        for child in node.children:
            ct = child.type
            text = child.text.decode("utf-8", errors="replace")
            if ct in ("[", "]", ";"):
                continue
            if ct in (
                "primitive_type",
                "type_identifier",
                "scoped_type_identifier",
                "generic_type",
                "reference_type",
                "tuple_type",
                "array_type",
                "slice_type",
                "dynamic_type",
                "pointer_type",
            ):
                inner_parts.append(_canonical_type_from_node(child))
            else:
                # length expression (e.g., integer literal)
                inner_parts.append(_strip_whitespace(text))
        if len(inner_parts) == 1:
            return f"[{inner_parts[0]}]"
        return "[" + "; ".join(inner_parts) + "]"

    if nt == "reference_type":
        # &<lifetime>?<mut>?<inner>
        is_mut = False
        inner_type = ""
        for child in node.children:
            ct = child.type
            text = child.text.decode("utf-8", errors="replace")
            if ct == "lifetime":
                # Rule 5: drop lifetimes
                continue
            if ct == "mutable_specifier" or text == "mut":
                is_mut = True
                continue
            if text == "&":
                continue
            inner_type = _canonical_type_from_node(child)
        prefix = "&mut " if is_mut else "&"
        return prefix + inner_type

    if nt == "pointer_type":
        # *const T or *mut T
        text = node.text.decode("utf-8", errors="replace")
        return _canonical_type_string_from_text(text)

    if nt == "generic_type":
        # Foo<A, B, C> -- this is the H-4 critical path. The
        # type_arguments node is iterable; we recurse element-
        # wise into each argument.
        outer_name = ""
        inner_args: list[str] = []
        for child in node.children:
            ct = child.type
            if ct in ("type_identifier", "scoped_type_identifier"):
                outer_name = _strip_whitespace(child.text.decode("utf-8", errors="replace"))
            elif ct == "type_arguments":
                # H-4 rule 7: iterate arguments as nodes.
                for arg in child.children:
                    at = arg.type
                    if at in ("<", ">", ","):
                        continue
                    if at == "lifetime":
                        # Rule 2: lifetimes stripped at every
                        # nesting level, including as a direct
                        # generic argument.
                        continue
                    # H-4 rule 6: recurse into each argument.
                    inner_args.append(_canonical_type_from_node(arg))
        return f"{outer_name}<{', '.join(inner_args)}>"

    if nt == "dynamic_type":
        # Box<dyn Trait + 'a + Send> -> "dyn Trait" (rule 4)
        # Find the first trait identifier; drop bounds beyond
        # the first identifier and any lifetimes.
        parts: list[str] = []
        kept_first = False
        for child in node.children:
            ct = child.type
            text = child.text.decode("utf-8", errors="replace")
            if text in ("dyn",):
                parts.append("dyn")
                continue
            if ct == "lifetime":
                continue
            if ct == "trait_bounds":
                # Walk inner: take only first non-lifetime trait
                for tb in child.children:
                    tbt = tb.type
                    if tbt in ("+",):
                        continue
                    if tbt == "lifetime":
                        continue
                    if not kept_first:
                        parts.append(_canonical_type_from_node(tb))
                        kept_first = True
                continue
            if ct in (
                "type_identifier",
                "scoped_type_identifier",
                "generic_type",
            ):
                if not kept_first:
                    parts.append(_canonical_type_from_node(child))
                    kept_first = True
                continue
            if text == "+":
                continue
        return " ".join(parts) if parts else "dyn"

    if nt == "function_type":
        # fn(A) -> B
        text = node.text.decode("utf-8", errors="replace")
        return _canonical_type_string_from_text(text)

    if nt == "lifetime":
        # Rule 2: lifetimes stripped. Should only reach here when
        # called incorrectly; return empty so caller filters it.
        return ""

    # Fallback for nodes we don't have an explicit handler for:
    # use the source text but apply rules 1 (whitespace collapse)
    # + 2 (lifetime strip via regex).
    text = node.text.decode("utf-8", errors="replace")
    return _canonical_type_string_from_text(text)


def _canonical_type_string_from_text(text: str) -> str:
    """Apply rules 1, 2 to a raw type text.

    Reserved for fallthrough cases where the AST handler is not
    yet specialized for a given node type. Rule 6 (nested-
    generic recursion) is NOT applied here; this helper is only
    correct for primitive / non-generic types. Generic types
    MUST be handled in :func:`_canonical_type_from_node`.
    """
    import re

    text = text.strip()
    # Rule 2: strip lifetimes ('a, 'static, etc).
    text = re.sub(r"'[a-zA-Z_][a-zA-Z0-9_]*\b", "", text)
    text = re.sub(r"\bfor<[^>]*>\s*", "", text)
    # Rule 1: collapse whitespace.
    text = re.sub(r"\s+", " ", text).strip()
    # Strip leading "+ " left over from bound stripping.
    text = re.sub(r"^\+\s*", "", text).strip()
    # Strip orphan "+ " sequences left after lifetime drop.
    text = re.sub(r"\s*\+\s*(?=,|>|$)", "", text)
    text = re.sub(r"\s*,\s*", ", ", text)
    return text


def _strip_whitespace(text: str) -> str:
    import re

    return re.sub(r"\s+", " ", text).strip()
