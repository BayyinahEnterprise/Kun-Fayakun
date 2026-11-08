"""D11-onnx: shape-coverage on ONNX edges via strict-mode shape inference.

Catches ``onnx.shape_inference.InferenceError`` raised by
``infer_shapes(model_proto, strict_mode=True, check_type=True)``
and parses the per-op diagnostic into structural-honesty findings.

Two failure-mode categories share the ``ShapeCoverageDiagnostic``
dataclass and are distinguished by the ``category`` field:

* ``"shape_mismatch"`` (v0.9.1) - declared edge shape disagrees
  with the op's computed shape (Decision 1 of v0.9.1 prompt).
* ``"type_mismatch"`` (v0.9.2) - the op does not accept the input
  element type at the declared opset version (Decision 1 of
  v0.9.2 prompt; Gap 1 closure from the v0.9.1 post-release
  NeuroGolf evaluation).
* ``"unparseable"`` - the ONNX message format does not match
  either of the two known per-op patterns; the checker emits a
  single generic finding so the user still sees the issue.

The two flags ``strict_mode=True`` and ``check_type=True`` are
paired in v0.9.2+ per Standing Rule of the v0.9.2 prompt; no path
in this module uses one without the other. Together they cover
shape-inference disagreement and operator-type-restriction
checking without requiring a custom predicate.

The checker is the third member of the ONNX checker family
(after D24-onnx all-paths-emit and opset-compliance). Per
Decision 5 of the v0.9.1 prompt, no translator extension is
needed: the inference call operates on ``ModelProto`` directly,
not on the OnnxModule IR.

Empirical message formats (onnx 1.14 through 1.21):

    Shape-mismatch (v0.9.1, preserved):
        ... (op_type:Concat): [ShapeInferenceError] Inferred
        shape and existing shape differ ...

    Type-mismatch (v0.9.2, new under check_type=True):
        ... (op_type:Equal): A typestr: T, has unsupported type:
        tensor(float)

The two patterns differ in whether a ``[KIND]`` bracketed prefix
appears between ``):`` and the body. The shape-mismatch regex
matches the v0.9.1 shape; the type-mismatch regex matches the
v0.9.2 shape. The dispatcher tries shape-mismatch first per
Decision 3 of the v0.9.2 prompt: shape-mismatch is preferred when
both could match because its ``error_kind`` is explicit, while
the type-mismatch path synthesizes ``"TypeInferenceError"`` from
the absence of a bracketed kind tag.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ShapeCoverageDiagnostic:
    """A D11-onnx finding from strict-mode + type-check inference.

    ``op_type`` and ``error_kind`` come from the per-op part of
    the ONNX error message. ``message`` is the human-readable
    body. ``diagnosis`` and ``minimal_fix`` are the
    structural-honesty user-facing prose, formatted differently
    per ``category``. ``category`` is the v0.9.2 sub-type
    discriminator: ``"shape_mismatch"``, ``"type_mismatch"``, or
    ``"unparseable"``.

    The ``category`` field is required (no default) per the
    v0.9.2 prompt's round-30 fail-fast / round-32 MED-1
    discipline: a future construction site that forgets to set
    ``category`` would silently mislabel ``type_mismatch`` as
    ``shape_mismatch`` if a default were in place; the required-
    field shape makes that failure mode a ``TypeError`` at
    construction time. The dataclass extension is additive for
    consumers (existing fields unchanged) and breaking for
    constructors (the only construction site is
    ``check_shape_coverage`` in this same file, updated in the
    same v0.9.2 commit).
    """

    op_type: str
    error_kind: str
    message: str
    diagnosis: str
    minimal_fix: str
    category: str


# Shape-mismatch format (v0.9.1, preserved):
#   (op_type:Concat): [ShapeInferenceError] Inferred shape and ...
#   (op_type:Concat, node name: concat_c): [ShapeInferenceError] ...
# ONNX includes the node name when one is set; the regex captures
# the op_type only and discards the optional ", node name: ..."
# suffix so downstream code sees a clean op name like "Concat".
_SHAPE_MISMATCH_RE = re.compile(
    r"\(op_type:(?P<op>[^,)]+)(?:,[^)]*)?\):\s*" r"\[(?P<kind>[^\]]+)\]\s*(?P<body>[^\n]+)"
)

# Type-mismatch format (v0.9.2, new under check_type=True). Two
# empirical body shapes observed against onnx 1.14-1.21:
#   (op_type:Equal): A typestr: T, has unsupported type: tensor(float)
#   (op_type:Reshape, node name: ...): shape typestr: tensor(int64), has unsupported type: tensor(float)
# The first form anchors on the schema typestr name (capital
# letter parameter, e.g., 'A', 'B', 'T'). The second form anchors
# on a named input ('shape', 'condition', etc.). Both share the
# literal ' typestr: ' substring with 'has unsupported type:'
# later in the body. The regex captures the general
# '<token> typestr:' shape so both variants route to
# category=type_mismatch rather than falling through to the
# unparseable-fallback. Distinguished from shape-mismatch by the
# absence of a bracketed [KIND] prefix between '):' and the body.
_TYPE_MISMATCH_RE = re.compile(
    r"\(op_type:(?P<op>[^,)]+)(?:,[^)]*)?\):\s+" r"(?P<body>\S+ typestr:[^\n]+)"
)


def _classify_per_op_finding(text: str) -> tuple[str, str, str, str] | None:
    """Classify a per-op ONNX error fragment.

    Returns ``(op_type, error_kind, body, category)`` or ``None``
    if neither known pattern matches at the start of ``text``.

    Tries the shape-mismatch regex first (preferred when both
    could match because its ``error_kind`` is explicit); falls
    back to the type-mismatch regex if the bracketed kind tag is
    absent. The fixed ordering is the spec for future-onnx-version
    stability per Standing Rule of the v0.9.2 prompt.
    """
    m = _SHAPE_MISMATCH_RE.match(text)
    if m:
        return (
            m.group("op"),
            m.group("kind"),
            m.group("body").strip(),
            "shape_mismatch",
        )
    m = _TYPE_MISMATCH_RE.match(text)
    if m:
        return (
            m.group("op"),
            "TypeInferenceError",
            m.group("body").strip(),
            "type_mismatch",
        )
    return None


def _format_for_category(op: str, body: str, category: str) -> tuple[str, str]:
    """Return ``(diagnosis, minimal_fix)`` prose for ``category``.

    The two sub-types have different semantics: shape-mismatch
    means the declared shape disagrees with the computed shape;
    type-mismatch means the op does not accept the input type at
    the declared opset. Same fix prose for both would be
    misleading; the v0.9.2 split per Decision 2 of the v0.9.2
    prompt distinguishes them at the user-visible layer.
    """
    if category == "shape_mismatch":
        return (
            (
                f"Op '{op}' fails strict-mode shape inference: "
                f"{body}. A declared edge shape disagrees with "
                f"the op's computed shape."
            ),
            (
                f"Correct the declared shape on the edge connected "
                f"to '{op}', or insert a Reshape node if the "
                f"disagreement is intentional."
            ),
        )
    if category == "type_mismatch":
        return (
            (
                f"Op '{op}' fails type-compliance check: {body}. "
                f"This operator does not accept the input element "
                f"type at the declared opset version."
            ),
            (
                "Either: (a) cast the input to a type the op "
                "accepts at this opset (e.g., wrap with Cast); "
                "(b) raise the model's opset_import to a version "
                "where this op accepts the current input type; or "
                "(c) replace the op with one that natively accepts "
                "the type (e.g., Equal-on-float at opset 10 -> "
                "upgrade to opset 11 where float types are "
                "supported)."
            ),
        )
    raise ValueError(f"Unknown category: {category}")  # defensive; unreachable


# Master regex anchoring on the (op_type:NAME): marker. Each match's
# start position becomes the input to ``_classify_per_op_finding``,
# which decides whether the rest of the line shape-matches or
# type-matches. Using a master scan plus per-match classification
# (rather than two parallel finditer scans) preserves the document
# order of findings, which matters for diagnostic stability.
_OP_TYPE_MARKER = re.compile(r"\(op_type:[^)]+\):")


def check_shape_coverage(model_proto: Any) -> Iterator[ShapeCoverageDiagnostic]:
    """Run strict-mode + type-check shape inference; yield one
    :class:`ShapeCoverageDiagnostic` per per-op mismatch.

    Both flags are paired (Standing Rule of the v0.9.2 prompt):

    * ``strict_mode=True`` - declared-vs-inferred shape rule
      (v0.9.1 / Decision 1 of v0.9.1 prompt)
    * ``check_type=True`` - operator-type-restriction rule
      (v0.9.2 / Decision 1 of v0.9.2 prompt; Gap 1 closure)

    Raises :class:`furqan_lint.onnx_adapter.OnnxExtrasNotInstalled`
    if the ``[onnx]`` extra is missing.

    Silent-passes (preserved from v0.9.1; Decision 5 of v0.9.2
    prompt) on:

    * dim_param shapes (symbolic dims like ``"batch"``)
    * empty dim_value (dynamic shapes)
    * broadcast-compatible op inputs

    These behaviors are inherent to strict_mode itself and
    unaffected by ``check_type=True``.
    """
    try:
        import onnx.shape_inference
    except ImportError as e:
        from furqan_lint.onnx_adapter import OnnxExtrasNotInstalled

        raise OnnxExtrasNotInstalled(
            "ONNX support not installed. Run: pip install furqan-lint[onnx]"
        ) from e

    try:
        onnx.shape_inference.infer_shapes(model_proto, strict_mode=True, check_type=True)
    except onnx.shape_inference.InferenceError as e:
        msg = str(e)
        # Locate every (op_type:NAME): marker in the message and
        # classify what follows. Document order is preserved.
        marker_starts = [m.start() for m in _OP_TYPE_MARKER.finditer(msg)]
        any_emitted = False
        for start in marker_starts:
            tail = msg[start:]
            parsed = _classify_per_op_finding(tail)
            if parsed is None:
                continue
            op, kind, body, category = parsed
            diagnosis, minimal_fix = _format_for_category(op, body, category)
            yield ShapeCoverageDiagnostic(
                op_type=op,
                error_kind=kind,
                message=body,
                diagnosis=diagnosis,
                minimal_fix=minimal_fix,
                category=category,
            )
            any_emitted = True

        if not any_emitted:
            # Unparseable format. Emit one generic finding so the
            # user still learns of the issue even though the
            # parser cannot extract per-op detail.
            yield ShapeCoverageDiagnostic(
                op_type="<unknown>",
                error_kind="<unknown>",
                message=msg,
                diagnosis=(f"Strict-mode shape inference failed: {msg}"),
                minimal_fix=(
                    "Correct the declared shapes / types to match op "
                    "semantics, or insert a Cast / Reshape node if the "
                    "disagreement is intentional."
                ),
                category="unparseable",
            )
