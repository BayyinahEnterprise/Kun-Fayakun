"""Public-name extraction for ONNX additive-only diff.

Public names for an ONNX model are exactly its ``graph.input`` and
``graph.output`` ValueInfo entries with their shapes. Per Decision
5 / round-24 finding m2, intermediates (``graph.value_info``) and
initializers (``graph.initializer``) are explicitly out of scope.
Including them would create false positives on every model
retraining (initializer tensor shapes / names change as a routine
matter; they are not part of the model's external interface).

Format
======

Each name is rendered as ``"input:NAME:SHAPE"`` or
``"output:NAME:SHAPE"``, where SHAPE is the dim list rendered as:

* ``int dim_value``  -> the integer literal (e.g. ``4``)
* ``str dim_param``  -> ``?NAME`` (e.g. ``?batch``)
* unset / dynamic    -> ``?``
* dims joined by ``x``; empty shape rendered as ``()``

This format ensures a shape change on the same name registers as
removal-plus-addition (MARAD) under the additive-only invariant,
matching the contract for Python ``__all__``, Rust ``pub`` items,
and Go exported identifiers.

Symmetric with rust_adapter.public_names.extract_public_names
and go_adapter.public_names.extract_public_names. Both feed
furqan_lint.additive.compare_name_sets.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def _shape_str(type_proto: Any) -> str:
    """Render an ONNX TypeProto's dim list as a printable shape.

    Examples:
        ``[1, 4]``           -> ``"1x4"``
        ``[?batch, 4]``      -> ``"?batchx4"``
        ``[?]`` (dynamic)    -> ``"?"``
        ``[]`` (scalar)      -> ``"()"``
        non-tensor type      -> ``"()"``
    """
    tt = getattr(type_proto, "tensor_type", None)
    if tt is None or not type_proto.HasField("tensor_type"):
        return "()"
    dims = list(tt.shape.dim)
    if not dims:
        return "()"
    parts: list[str] = []
    for d in dims:
        if d.HasField("dim_value"):
            parts.append(str(int(d.dim_value)))
        elif d.HasField("dim_param"):
            parts.append(f"?{d.dim_param}")
        else:
            parts.append("?")
    return "x".join(parts)


def extract_public_names(path: Path | str) -> frozenset[str]:
    """Extract input/output ValueInfo identifiers for the model
    at ``path``.

    Returns a frozenset of strings shaped:

    * ``"input:NAME:SHAPE"``  for each ``graph.input`` entry
    * ``"output:NAME:SHAPE"`` for each ``graph.output`` entry

    Raises :class:`furqan_lint.onnx_adapter.OnnxExtrasNotInstalled`
    if the ``[onnx]`` extra is missing.

    Raises :class:`furqan_lint.onnx_adapter.OnnxParseError` if
    the protobuf at ``path`` cannot be loaded.
    """
    from furqan_lint.onnx_adapter import parse_model

    model = parse_model(path)
    names: set[str] = set()
    for inp in model.graph.input:
        names.add(f"input:{inp.name}:{_shape_str(inp.type)}")
    for out in model.graph.output:
        names.add(f"output:{out.name}:{_shape_str(out.type)}")
    return frozenset(names)
