"""Phase G11.3 (an-Naziat): canonical signatures for ONNX graph surface.

Computes per-graph canonical signatures for the CASM v1.0
manifest's ``module_identity.onnx`` ``OnnxIdentitySection``. The
canonical bytes (RFC 8785 / JCS) are SHA-256 hashed into the
``signature_fingerprint`` value at the graph-surface layer.

ONNX gate11 canonicalization is **graph-shape**, not
**type-shape**. The four substrates of the canonical mushaf
chain differ honestly at the canonicalization layer:

* Python (Phase G11.0): type-shape per at-Tawbah T03 rules 1-5
  (function / class / constant; nested generics; recursive type
  expressions; RFC 8785 JCS)
* Rust (Phase G11.1): type-shape per as-Saffat rules 1-5
  Rust-adapted (struct / enum / trait; nested generics;
  lifetime canonicalization)
* Go (Phase G11.2): type-shape per al-Mursalat T03 rules 6-8
  (nested type expressions; multi-return signatures; channel
  direction preservation)
* ONNX (Phase G11.3): **graph-shape** per an-Naziat T03 rules
  9-12 (this module). The substrate is binary protobuf
  (ModelProto), not source code; the public surface is graph
  inputs/outputs, not named function/struct signatures; the
  canonical form preserves ValueInfo entries sorted by name
  plus opset_imports / ir_version metadata.

The rule numbering 9-12 continues the cross-substrate H-4
closure rule numbering: rules 1-5 covered Python (at-Tawbah
T03 H-4 closure), rules 6-8 covered Go (al-Mursalat T03
adaptation for container shapes), rules 9-12 cover ONNX-specific
extensions. The numbering continuation makes the H-4 closure
mechanically traceable rule-by-rule across the mushaf chain.

Canonicalization rules (rules 9-12):

  9.  **ValueInfo entries MUST be sorted by name before
      serialization.** ONNX proto declaration order is
      non-canonical: graph optimization passes can re-order
      ``graph.input`` / ``graph.output`` entries without
      changing mathematical behavior. Sort by ``name``
      lexicographically before building the canonical string.
      (Closes the cross-substrate H-4 equivalent at the
      ONNX-graph layer; failure mode #1 of §5.1 step 4.)

  10. **Symbolic dimensions MUST be preserved as strings;
      concrete dimensions MUST be preserved as integers.** Do
      NOT call ``dim.dim_value`` on a ``dim_param``-typed dim;
      check ``dim.HasField('dim_param')`` first. Symbolic dims
      serialize as their ``dim_param`` name (a string);
      concrete dims serialize as their ``dim_value`` (an int).
      Symbolic-vs-concrete drift between manifest and substrate
      ModelProto raises ``CASM-V-071`` at verification time
      (failure mode #3 of §5.1 step 4).

  11. **opset_imports MUST be sorted by domain then by version
      descending.** Multiple opset_imports for the same domain
      are unusual; if they occur, the highest version is the
      binding one for verification semantics. Sorting
      ``(domain, -version)`` keeps the canonical string
      deterministic. Mismatch between manifest opset_imports
      and substrate ModelProto opset_imports raises
      ``CASM-V-070`` at verification time.

  12. **ir_version MUST be included as an integer.** ONNX's
      ``ModelProto.ir_version`` is a proto int field; the
      canonical string preserves its type as an integer (not
      a string). This is load-bearing because ir_version
      participates in opset-policy compatibility checks at
      runtime.

Disease-model framing (per as-Saffat amended_2 audit F4 +
at-Tawbah T03 H-4 closure + al-Mursalat T03 Go adaptation):
this module is the ONNX-side defense against the audit H-4
failure mode (Phase G11.0 v0.10.0's Python implementation fell
through to ``ast.unparse(node.slice)`` for multi-argument
generics, producing tuple-stringification artifacts). The ONNX
translation preserves the abstract rule (recurse element-wise;
preserve type-tags faithfully; sort deterministically) at the
graph-shape layer rather than the type-shape layer.

Canonicalization failures (malformed OnnxIdentitySection;
unknown dtype; non-iterable shape) raise ``CasmSchemaError``
with ``CASM-V-001`` rather than returning a sentinel string;
the strict-mode failure surfaces immediately at the
canonicalization site rather than at the downstream verifier
step that consumes the canonical bytes.

D24 discipline: helpers use single-trailing-return shape
(raise on miss, return on hit) so the path-coverage analysis
sees terminal coverage across all branches.
"""

from __future__ import annotations

from typing import Any

from furqan_lint.gate11.manifest_schema import (
    CasmSchemaError,
    OnnxIdentitySection,
    ValueInfoSummary,
)


def _canonicalize_value_info(vi: ValueInfoSummary) -> dict[str, Any]:
    """Canonicalize one ValueInfoSummary entry.

    Per rule 10: symbolic dims as strings, concrete dims as
    integers. Per rule 9 (caller's responsibility): the list
    of ValueInfoSummary entries is sorted by name BEFORE this
    helper is invoked.
    """
    if not isinstance(vi.name, str) or not vi.name:
        raise CasmSchemaError(
            "CASM-V-001",
            f"ValueInfoSummary.name must be a non-empty string; got {vi.name!r}",
        )
    if not isinstance(vi.dtype, str) or not vi.dtype:
        raise CasmSchemaError(
            "CASM-V-001",
            f"ValueInfoSummary.dtype must be a non-empty string; got {vi.dtype!r}",
        )
    shape_canonical: list[int | str] = []
    for d in vi.shape:
        if isinstance(d, bool):
            # bool is subclass of int in Python; reject explicitly.
            raise CasmSchemaError(
                "CASM-V-001",
                f"ValueInfoSummary.shape element must be int or str; got bool {d!r}",
            )
        if isinstance(d, int):
            shape_canonical.append(d)
        elif isinstance(d, str):
            if not d:
                raise CasmSchemaError(
                    "CASM-V-001",
                    "ValueInfoSummary.shape symbolic dim_param must be a non-empty string",
                )
            shape_canonical.append(d)
        else:
            raise CasmSchemaError(
                "CASM-V-001",
                "ValueInfoSummary.shape element must be int (concrete "
                f"dim_value) or str (symbolic dim_param); got {type(d).__name__}",
            )
    return {
        "name": vi.name,
        "dtype": vi.dtype,
        "shape": shape_canonical,
    }


def _canonicalize_opset_imports(
    opset_imports: tuple[tuple[str, int], ...],
) -> list[dict[str, Any]]:
    """Canonicalize opset_imports per rule 11.

    Sort by domain ascending, then by version descending. The
    descending-version order makes the highest-version entry
    appear first for any given domain -- which is the binding
    entry for verification semantics.
    """
    if not isinstance(opset_imports, tuple):
        raise CasmSchemaError(
            "CASM-V-001",
            "opset_imports must be a tuple of (domain, version) pairs",
        )
    canonical: list[dict[str, Any]] = []
    for pair in opset_imports:
        if not isinstance(pair, tuple) or len(pair) != 2:
            raise CasmSchemaError(
                "CASM-V-001",
                f"opset_imports entry must be a (domain, version) tuple; got {pair!r}",
            )
        domain, version = pair
        if not isinstance(domain, str):
            raise CasmSchemaError(
                "CASM-V-001",
                f"opset_imports domain must be a string; got {type(domain).__name__}",
            )
        if not isinstance(version, int) or isinstance(version, bool):
            raise CasmSchemaError(
                "CASM-V-001",
                f"opset_imports version must be an int; got {type(version).__name__}",
            )
        canonical.append({"domain": domain, "version": version})
    # Sort: domain ascending, version descending (per rule 11).
    canonical.sort(key=lambda d: (d["domain"], -d["version"]))
    return canonical


def canonicalize(section: OnnxIdentitySection) -> dict[str, Any]:
    """Canonicalize an ``OnnxIdentitySection`` into a dict.

    Returns a dict whose RFC 8785 / JCS serialization is the
    graph-shape canonical string. Apply
    :func:`rfc8785.dumps` (or equivalent JCS implementation)
    on the returned dict to produce the canonical bytes that
    feed into the manifest's signature surface.

    Implements rules 9-12:

    * Rule 9: ValueInfo entries sorted by name (inputs and
      outputs sorted independently).
    * Rule 10: symbolic dims preserved as strings, concrete
      dims preserved as ints; handled per-entry in
      :func:`_canonicalize_value_info`.
    * Rule 11: opset_imports sorted by domain ascending, version
      descending; handled in
      :func:`_canonicalize_opset_imports`.
    * Rule 12: ir_version preserved as integer (not string).
    """
    if not isinstance(section, OnnxIdentitySection):
        raise CasmSchemaError(
            "CASM-V-001",
            f"canonicalize expects OnnxIdentitySection; got {type(section).__name__}",
        )
    if not isinstance(section.ir_version, int) or isinstance(section.ir_version, bool):
        raise CasmSchemaError(
            "CASM-V-001",
            f"OnnxIdentitySection.ir_version must be an int; "
            f"got {type(section.ir_version).__name__}",
        )

    # Rule 9: sort ValueInfo entries by name before serialization.
    inputs_sorted = sorted(section.inputs, key=lambda vi: vi.name)
    outputs_sorted = sorted(section.outputs, key=lambda vi: vi.name)

    return {
        # Rule 11: opset_imports canonical order.
        "opset_imports": _canonicalize_opset_imports(section.opset_imports),
        # Rule 12: ir_version as integer (not string).
        "ir_version": section.ir_version,
        # Rule 9 + 10: ValueInfo entries sorted by name; shapes
        # preserve symbolic/concrete distinction faithfully.
        "inputs": [_canonicalize_value_info(vi) for vi in inputs_sorted],
        "outputs": [_canonicalize_value_info(vi) for vi in outputs_sorted],
    }


def canonicalize_bytes(section: OnnxIdentitySection) -> bytes:
    """Canonicalize an OnnxIdentitySection to RFC 8785 bytes.

    Wraps :func:`canonicalize` with the JCS serialization. The
    returned bytes are deterministic for any two semantically-
    equivalent OnnxIdentitySection inputs (regardless of input
    ValueInfo declaration order or opset_imports declaration
    order).
    """
    import rfc8785

    return rfc8785.dumps(canonicalize(section))


__all__ = (
    "canonicalize",
    "canonicalize_bytes",
)
