"""Score-validity advisory check via ``onnx_tool.model_profile``.

Closes Gap 2 (MEDIUM) per Decision 9 of v0.9.2 and round-32
NeuroGolf leverage analysis. Wraps ``onnx_tool.model_profile()``
in stdout-capture and exception-trapping; if profiling fails on
a model that ``onnx.checker`` would accept, the failure is a
deployment-side surface gap (operator missing schema-default
handling in the profiler) rather than a structural fault in
the model itself. Fires as ADVISORY, not MARAD: the model is
structurally valid; only the profiler's coverage is incomplete.

Per Decision 3 of v0.9.4 prompt: ADVISORY findings exit 0;
MARAD findings exit 1. The CLI distinguishes via the
``severity`` field on the diagnostic.

Convention dependency: ``onnx_tool.model_profile`` writes a
profile table to stdout on success (~420 bytes for a Relu
model). Decision 2 wraps the call in
``contextlib.redirect_stdout(io.StringIO())`` so successful
profiles produce no CLI output and only failure surfaces a
diagnostic.

Op-type extraction (Decision 4 / S1): walk the exception
traceback for the deepest frame whose ``f_locals.get("self")``
has an ``op_type`` string attribute; fall back to
``"<unknown>"`` if no match. Heuristic; graceful fallback.
"""

from __future__ import annotations

import contextlib
import io
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ScoreValidityDiagnostic:
    """A score-validity advisory finding from
    ``onnx_tool.model_profile``.

    All fields are required (frozen dataclass; round-30 fail-fast
    discipline). ``severity`` is always ``"ADVISORY"`` in v0.9.4;
    the field exists for symmetry with future severity splits
    (e.g., a strict-mode advisory that promotes to MARAD).
    """

    op_type: str
    exception_class: str
    exception_message: str
    severity: str
    diagnosis: str
    minimal_fix: str


def _extract_op_type_from_traceback(exc: BaseException) -> str:
    """Walk the exception traceback for an op_type heuristic.

    Returns the first string ``op_type`` attribute found on a
    ``self`` local of any frame in the traceback chain, or
    ``"<unknown>"`` if no match. The heuristic is fragile across
    onnx_tool versions; the fallback ensures the diagnostic
    still surfaces useful prose even when extraction fails.
    """
    tb = exc.__traceback__
    while tb is not None:
        frame_self = tb.tb_frame.f_locals.get("self")
        if frame_self is not None:
            op_type = getattr(frame_self, "op_type", None)
            if isinstance(op_type, str) and op_type:
                return op_type
            # Some onnx_tool internal types use "name" + "op_type"
            # split; check both.
            name = getattr(frame_self, "name", None)
            if isinstance(name, str) and name and not name.startswith("/") and op_type is None:
                # Heuristic: "/" prefix means a tensor name, not an op
                return name
        tb = tb.tb_next
    return "<unknown>"


def check_score_validity(
    model_proto: Any, model_path: Path | str
) -> Iterator[ScoreValidityDiagnostic]:
    """Run ``onnx_tool.model_profile`` against ``model_path``;
    yield one ADVISORY diagnostic if the profiler raises.

    Silent-passes (returns without yielding) when:

    1. ``onnx_tool`` is not importable (the ``[onnx-profile]``
       extra is not installed, Decision 6 condition (a)).
    2. ``onnx_tool.model_profile(str(model_path))`` returns
       successfully (the model profiles cleanly).

    Stdout from the profiler is captured via
    ``contextlib.redirect_stdout`` so successful profiles
    produce no CLI noise; only the failure surfaces a
    diagnostic. ``model_proto`` is unused at the v0.9.4
    layer (the profiler reads from disk via path) but stays
    in the signature for symmetry with the other ONNX
    checkers and to anchor a future in-memory API.
    """
    try:
        import onnx_tool
    except ImportError:
        return  # Decision 6 (a): silent-pass

    p = Path(model_path)
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            onnx_tool.model_profile(str(p))
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        op_type = _extract_op_type_from_traceback(exc)
        exc_class = type(exc).__name__
        exc_message = str(exc)

        diagnosis = (
            f"onnx_tool.model_profile() failed on op '{op_type}': "
            f"{exc_class}: {exc_message}. The model is structurally "
            f"valid ONNX; the profiler's coverage of this operator "
            f"shape is incomplete."
        )
        if op_type != "<unknown>":
            minimal_fix = (
                f"Set the relevant attributes explicitly on your "
                f"'{op_type}' node (the ONNX schema permits omitting "
                f"some defaults, but onnx_tool's profiler does not "
                f"always handle them). For TopK, set the 'axis' "
                f"attribute. For Reshape, ensure the shape input is "
                f"int64. For Squeeze, set 'axes' explicitly."
            )
        else:
            minimal_fix = (
                "Set node attributes explicitly to avoid relying "
                "on onnx_tool's coverage of schema defaults. "
                "Common gaps: TopK without 'axis', Reshape with "
                "non-int64 shape input, Squeeze without 'axes'."
            )

        yield ScoreValidityDiagnostic(
            op_type=op_type,
            exception_class=exc_class,
            exception_message=exc_message,
            severity="ADVISORY",
            diagnosis=diagnosis,
            minimal_fix=minimal_fix,
        )
