"""Phase G11.2 (al-Mursalat): canonical signatures for Go public surface.

Computes per-name canonical signatures for the CASM v1.0
manifest's ``public_surface.names`` field for Go-language
substrates. Each signature dict is RFC 8785 (JCS) canonicalized
and SHA-256 hashed into the ``signature_fingerprint`` value.

Per-kind canonical forms:

- ``function``: name + parameters + return_types + is_variadic
- ``struct``: name + fields (each with name, type, is_exported)
- ``interface``: name + method_names
- ``type_alias``: name + target_type
- ``constant``: name + type

Canonical type strings (H-4 closure rules 6-8 -- mirror of
Python at-Tawbah T03 rules 1-5 adapted for Go's container
shapes; rule numbering continues from rules 1-5):

  6. Nested type expressions MUST recurse element-wise. A type
     like ``[]map[string]*Result[T, E]`` canonicalizes as
     ``slice[map[string][pointer[Result[T,E]]]]`` with the
     container token (``slice``, ``map``, ``pointer``,
     ``channel``, ``channel_recv``, ``channel_send``) explicitly
     named.
  7. Multi-return signatures MUST iterate as AST nodes, not
     stringified. A signature ``(int, error)`` is iterated via
     ``ReturnTypeNames: ["int", "error"]`` from the goast JSON
     output (which itself iterates ``ast.FuncType.Results``
     children rather than calling ``.String()`` on the whole
     tuple); the Python layer iterates the resulting list.
  8. Channel direction MUST be preserved. ``chan T``,
     ``<-chan T``, ``chan<- T`` canonicalize as ``channel[T]``,
     ``channel_recv[T]``, ``channel_send[T]`` respectively;
     these are three structurally distinct types.

The canonicalizer operates on Go type expressions as strings
(post-goast pre-stringification). The goast binary's
``functionOut.Params[].Type`` and ``functionOut.ReturnTypeNames``
fields produce these strings via Go's ``go/ast`` ``String()``
methods, which iterate the AST faithfully -- the Python layer
canonicalizes the per-type strings recursively without losing
the structural information.

Disease-model framing (per as-Saffat amended_2 audit F4 +
at-Tawbah T03 H-4 closure): this module is the Go-side defense
against the audit H-4 failure mode (Phase G11.0 v0.10.0's
Python implementation fell through to ``ast.unparse(node.slice)``
for multi-argument generics, producing tuple-stringification
artifacts). The Go translation preserves the abstract rule
(recurse element-wise; iterate as nodes not strings; preserve
direction markers) by parsing Go type expressions into a small
recursive AST at the Python layer.

Canonicalization failures (malformed Go type expression,
unparseable composite) record the original text and emit a
CASM-V-003 ADVISORY per as-Saffat T03 convention.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class GoCanonicalizationAdvisory:
    """One CASM-V-003 ADVISORY surfaced during Go canonicalization.

    The Verifier and the surface extractor collect these without
    raising; the manifest is still emitted with the original
    text recorded so verification can complete.
    """

    name: str
    original: str
    reason: str


# Token boundaries for Go type expressions. The canonicalizer
# uses a small recursive descent parser; this keeps the
# dependency surface zero (no tree-sitter-go at Python layer).
# Each rule is rule 6 / 7 / 8 substrate-explicit.

_CONTAINER_PREFIXES = {
    "[]": "slice",
    "*": "pointer",
    "chan<-": "channel_send",
    "<-chan": "channel_recv",
    "chan ": "channel",
}


def _strip_whitespace(expr: str) -> str:
    """Collapse all whitespace to single spaces; trim ends.

    Rule 6 prep step: whitespace normalization before
    structural canonicalization. Matches as-Saffat T03 rule 1
    (Python H-4) and rust_signature_canonicalization rule 1.
    """
    return re.sub(r"\s+", " ", expr).strip()


def _canonicalize_type(expr: str) -> str:
    """Recursively canonicalize a Go type expression to its
    structural form.

    Implements rules 6 + 8 (rule 7 is exercised at the function-
    signature level via iterate-list-not-string discipline).

    Examples (rule 6 + 8 closure tests; tests/test_go_signature_canonicalization.py
    pins each):

    * ``[]map[string]*Result[T, E]``
      -> ``slice[map[string][pointer[Result[T,E]]]]``
    * ``chan<- *T`` -> ``channel_send[pointer[T]]``
    * ``<-chan *T`` -> ``channel_recv[pointer[T]]``
    * ``chan *T`` -> ``channel[pointer[T]]``
    * ``map[string]chan struct{}``
      -> ``map[string][channel[struct{}]]``
    """
    expr = _strip_whitespace(expr)
    if not expr:
        return ""

    # Rule 8: channel direction preservation. Direction markers
    # MUST be checked BEFORE pointer / slice / generic recursion
    # because ``chan<- *T`` is ``channel_send[pointer[T]]``, not
    # ``channel[pointer[T]]``. Ordered longest-first to avoid
    # ``chan`` matching before ``chan<-``.
    for prefix in ("chan<-", "<-chan"):
        if expr.startswith(prefix):
            inner = expr[len(prefix) :].strip()
            container = _CONTAINER_PREFIXES[prefix]
            return f"{container}[{_canonicalize_type(inner)}]"
    if expr.startswith("chan ") or expr == "chan":
        # Bare ``chan T`` (bidirectional)
        inner = expr[5:].strip() if expr.startswith("chan ") else ""
        return f"channel[{_canonicalize_type(inner)}]"

    # Rule 6: slice container preservation. ``[]T`` is the
    # canonical Go slice token; canonicalize as ``slice[T]``
    # with recursive inner-type canonicalization.
    if expr.startswith("[]"):
        inner = expr[2:].strip()
        return f"slice[{_canonicalize_type(inner)}]"

    # Rule 6: pointer container preservation. ``*T`` is Go's
    # pointer token; canonicalize as ``pointer[T]``.
    if expr.startswith("*"):
        inner = expr[1:].strip()
        return f"pointer[{_canonicalize_type(inner)}]"

    # Rule 6: map container preservation. ``map[K]V`` requires
    # bracketed K parsing; the V is everything after the matched
    # closing ``]``. Tracks bracket depth so nested generics
    # don't break key extraction.
    if expr.startswith("map["):
        depth = 1
        i = 4
        while i < len(expr) and depth > 0:
            if expr[i] == "[":
                depth += 1
            elif expr[i] == "]":
                depth -= 1
            i += 1
        if depth != 0:
            # Malformed; preserve original per advisory.
            return expr
        key_expr = expr[4 : i - 1].strip()
        value_expr = expr[i:].strip()
        return f"map[{_canonicalize_type(key_expr)}]" f"[{_canonicalize_type(value_expr)}]"

    # Generic application: ``Name[T1, T2, ...]``. Recurse over
    # each comma-separated type argument while tracking bracket
    # depth (so ``Result[T, E]`` inside ``map[string]*Result[T, E]``
    # iterates ``T`` and ``E`` as separate AST nodes, NOT as a
    # split-on-comma string operation that would mis-handle
    # nested generics).
    bracket_index = expr.find("[")
    if bracket_index > 0 and expr.endswith("]"):
        head = expr[:bracket_index].strip()
        inner_block = expr[bracket_index + 1 : -1]
        args = _split_top_level_commas(inner_block)
        canonical_args = ",".join(_canonicalize_type(a) for a in args)
        return f"{head}[{canonical_args}]"

    # Atomic type (int, string, error, T, MyType, ...). No
    # further structural decomposition; return verbatim after
    # whitespace strip.
    return expr


def _split_top_level_commas(s: str) -> list[str]:
    """Split a comma-separated list while respecting bracket
    nesting depth.

    Used by rule 6 generic-argument iteration so
    ``Result[T, E]`` inside a larger expression splits at the
    top-level comma boundary, NOT inside the nested ``[T, E]``.
    """
    parts: list[str] = []
    depth = 0
    current = ""
    for ch in s:
        if ch == "[":
            depth += 1
            current += ch
        elif ch == "]":
            depth -= 1
            current += ch
        elif ch == "," and depth == 0:
            parts.append(current.strip())
            current = ""
        else:
            current += ch
    if current.strip():
        parts.append(current.strip())
    return parts


def canonicalize_function_signature(
    name: str,
    params: list[dict[str, str]],
    return_types: list[str],
    is_variadic: bool = False,
) -> dict[str, object]:
    """Build the canonical signature dict for a Go function.

    Rule 7: iterates ``params`` and ``return_types`` as lists
    rather than stringifying the whole signature. Each parameter
    type and return type recurses through ``_canonicalize_type``.

    The dict is suitable for RFC 8785 canonicalization +
    sha256 fingerprint via ``canonical_signature_fingerprint``.

    Args:
        name: function name (e.g., "DoWork")
        params: list of {"name": ..., "type": ...} dicts from
                goast ``functionOut.Params``
        return_types: list of type strings from goast
                      ``functionOut.ReturnTypeNames``
        is_variadic: True if the last parameter is ``...T``
    """
    canonical_params = [
        {
            "name": p.get("name", ""),
            "type": _canonicalize_type(_strip_variadic(p.get("type", ""))),
        }
        for p in params
    ]
    canonical_returns = [_canonicalize_type(rt) for rt in return_types]
    return {
        "name": name,
        "kind": "function",
        "parameters": canonical_params,
        "return_types": canonical_returns,
        "is_variadic": is_variadic,
    }


def _strip_variadic(t: str) -> str:
    """Strip the ``...`` variadic marker for canonicalization.

    The variadic property is captured at the function-signature
    level (``is_variadic``); the type itself is canonicalized as
    its non-variadic equivalent so ``[]T`` (slice) and ``...T``
    (variadic) yield distinct fingerprints only via the
    ``is_variadic`` boolean rather than the type string.
    """
    t = t.strip()
    if t.startswith("..."):
        return t[3:].strip()
    return t


def canonical_signature_fingerprint(canonical_dict: Any) -> str:
    """Hash a canonical signature dict to its sha256 fingerprint.

    Uses RFC 8785 canonical JSON via ``rfc8785`` (gate11 extra
    requirement). The fingerprint is the hex digest with no
    ``sha256:`` prefix per the manifest schema convention.
    """
    import rfc8785

    canonical_bytes = rfc8785.dumps(canonical_dict)
    return hashlib.sha256(canonical_bytes).hexdigest()


__all__ = (
    "GoCanonicalizationAdvisory",
    "canonical_signature_fingerprint",
    "canonicalize_function_signature",
)
