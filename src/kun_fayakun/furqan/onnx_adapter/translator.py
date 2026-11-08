"""Translate an ONNX ModelProto into the OnnxModule dataclass.

The OnnxModule is the IR consumed by the ONNX checker pipeline
(D24-onnx all-paths-emit and opset-compliance). It does NOT
convert ONNX into the existing Furqan ``Module`` IR (FunctionDef,
ReturnStmt, etc.) because the substrates are structurally
different: ONNX nodes are not functions, edges are not return
statements, and ValueInfo is not a type signature.

Per the v0.9.0 prompt's Framing note (round-24 finding C1
closure), the ONNX adapter ships a parallel diagnostic family
inspired by the Furqan structural-honesty primitives, not new
instances of the existing checker pipeline operating on a
unified IR. The OnnxModule is the substrate of that parallel
family.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ValueInfoSummary:
    """A summary of an ONNX ValueInfoProto entry.

    ``shape`` is a tuple where each element is either an ``int``
    (when ONNX's ``dim_value`` is set) or a ``str`` (when ONNX's
    ``dim_param`` is set). An empty/dynamic dim is represented
    as the empty string ``""``.
    """

    name: str
    shape: tuple[int | str, ...]
    elem_type: int


@dataclass(frozen=True)
class NodeSummary:
    """A summary of an ONNX NodeProto entry.

    ``domain`` is the ``""`` (empty) string for the default ONNX
    domain; non-empty for custom domains (e.g. ``"com.microsoft"``).
    """

    op_type: str
    name: str
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    domain: str


@dataclass(frozen=True)
class BranchSummary:
    """A summary of a control-flow node (``If`` or ``Where``).

    Each entry of ``branches`` is the tuple of NodeSummary entries
    for one branch subgraph (``then_branch`` / ``else_branch`` for
    ``If``; the broadcast-selection inputs for ``Where``).
    """

    node_name: str
    op_type: str
    branches: tuple[tuple[NodeSummary, ...], ...]


@dataclass(frozen=True)
class OnnxModule:
    """The OnnxModule IR consumed by the ONNX checker pipeline.

    ``opset_version`` is the version of the default-domain opset
    declared in the model's ``opset_import`` list. Custom-domain
    opset versions are stored on each NodeSummary's ``domain``
    field at lookup time, but the OnnxModule itself records only
    the default-domain version (most ONNX models use only the
    default domain).
    """

    inputs: tuple[ValueInfoSummary, ...]
    outputs: tuple[ValueInfoSummary, ...]
    nodes: tuple[NodeSummary, ...]
    opset_version: int
    ir_version: int
    branches: tuple[BranchSummary, ...]


def _shape_from_type_proto(type_proto: Any) -> tuple[int | str, ...]:
    """Extract the dim list from an ONNX ``TypeProto``.

    Returns a tuple where each element is either ``int`` (for
    ``dim_value``) or ``str`` (for ``dim_param``), or ``""`` for
    an empty/dynamic dim. Returns the empty tuple for non-tensor
    types (sequence, map, optional, sparse) which v0.9.0 does
    not introspect further.
    """
    tt = getattr(type_proto, "tensor_type", None)
    if tt is None or not type_proto.HasField("tensor_type"):
        return ()
    shape = tt.shape
    out: list[int | str] = []
    for dim in shape.dim:
        if dim.HasField("dim_value"):
            out.append(int(dim.dim_value))
        elif dim.HasField("dim_param"):
            out.append(str(dim.dim_param))
        else:
            out.append("")
    return tuple(out)


def _value_info_to_summary(vi: Any) -> ValueInfoSummary:
    elem_type = 0
    tt = getattr(vi.type, "tensor_type", None)
    if tt is not None and vi.type.HasField("tensor_type"):
        elem_type = int(tt.elem_type)
    return ValueInfoSummary(
        name=str(vi.name),
        shape=_shape_from_type_proto(vi.type),
        elem_type=elem_type,
    )


def _node_to_summary(node: Any) -> NodeSummary:
    return NodeSummary(
        op_type=str(node.op_type),
        name=str(node.name),
        inputs=tuple(str(i) for i in node.input),
        outputs=tuple(str(o) for o in node.output),
        domain=str(node.domain),
    )


def _collect_branches(node: Any) -> BranchSummary | None:
    """Return a BranchSummary for ``If`` / ``Where`` nodes; else None.

    For ``If`` (which carries ``then_branch`` and ``else_branch``
    GraphProto attributes), each entry is the tuple of nodes in
    that subgraph.

    For ``Where`` (which has no subgraphs, just three tensor
    inputs that pick element-wise between two parallel dataflow
    paths), the ``branches`` field is the empty tuple of tuples.
    The node is still recorded so the D24-onnx walker can decide
    whether both selection-input dataflow paths reach a declared
    output.
    """
    op_type = str(node.op_type)
    if op_type not in ("If", "Where"):
        return None
    branches: list[tuple[NodeSummary, ...]] = []
    if op_type == "If":
        for attr in node.attribute:
            if attr.name in ("then_branch", "else_branch") and attr.HasField("g"):
                sub_nodes = tuple(_node_to_summary(n) for n in attr.g.node)
                branches.append(sub_nodes)
    return BranchSummary(
        node_name=str(node.name),
        op_type=op_type,
        branches=tuple(branches),
    )


def to_onnx_module(model_proto: Any) -> OnnxModule:
    """Translate a ``ModelProto`` to an :class:`OnnxModule`.

    The translation is total over well-formed ``ModelProto``
    instances. It does not run ONNX semantic-validity checks;
    semantic validity is the job of the ONNX checker pipeline.
    """
    graph = model_proto.graph
    inputs = tuple(_value_info_to_summary(vi) for vi in graph.input)
    outputs = tuple(_value_info_to_summary(vi) for vi in graph.output)
    nodes = tuple(_node_to_summary(n) for n in graph.node)
    branches: list[BranchSummary] = []
    for n in graph.node:
        b = _collect_branches(n)
        if b is not None:
            branches.append(b)
    # Default-domain opset version: the entry with empty-string
    # ``domain`` (some models use the literal "ai.onnx" alias for
    # the default domain too; treat both as default).
    opset_version = 0
    for opset_id in model_proto.opset_import:
        if str(opset_id.domain) in ("", "ai.onnx"):
            opset_version = int(opset_id.version)
            break
    return OnnxModule(
        inputs=inputs,
        outputs=outputs,
        nodes=nodes,
        opset_version=opset_version,
        ir_version=int(model_proto.ir_version),
        branches=tuple(branches),
    )
