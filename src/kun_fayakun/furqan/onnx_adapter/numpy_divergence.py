"""numpy-vs-ONNX divergence detection (D11-onnx + 1, v0.9.3).

The fourth ONNX checker. Loads a discoverable numpy reference
function alongside each .onnx file, runs both the numpy
reference and the ONNX model on a probe grid extracted from
the corresponding ARC-AGI task file, and fires when the
outputs disagree.

Closes Gap 4 (HIGH competition lever) per the round-32
NeuroGolf leverage analysis: every NeuroGolf primitive has a
numpy reference (it is how the operator verifies before
building); the substrate-vs-surface gap is structurally where
bugs hide (cont48, cont42 task284 first build, cont44 task313
prefix-sum direction). Lifting that gap into the lint pipeline
is the dominant-failure-mode catch.

Convention dependency (Decision 9 of v0.9.3 prompt; documented
as the new four-place limit ``numpy_divergence_neurogolf_convention``):
the check is opt-in by reference presence. It silent-passes
when the ``[onnx-runtime]`` extra is not installed, when no
sibling ``_build.py`` is discoverable, or when no sibling
``.json`` task file is discoverable. Generic ONNX users with
no NeuroGolf-shaped sidecars see no behavior change.

Tolerance modes (Decision 4 of v0.9.3 prompt):

* Cell-exact via ``np.array_equal`` if the ONNX output dtype
  is integer OR rank >= 4 with channel dimension matching a
  known one-hot width (default ``(10,)`` for ARC-AGI).
* ``np.allclose(rtol=1e-5, atol=1e-7)`` otherwise.

Multi-probe tasks emit one finding per diverging probe. The
input-shape adaptation strategy is "add leading axes until
the input rank matches the ONNX expected rank" (NeuroGolf
models commonly expect (1, 1, H, W) but ARC-AGI grids are
stored as [[...]] rank-2).
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Known one-hot encoding widths for the cell-exact tolerance mode.
# ARC-AGI uses 10 channels (one per cell color). Future NeuroGolf
# models with different one-hot widths would extend this tuple.
_KNOWN_ONE_HOT_WIDTHS: tuple[int, ...] = (10,)


@dataclass(frozen=True)
class NumpyDivergenceDiagnostic:
    """A numpy-vs-ONNX divergence finding for one probe grid.

    All fields are required (frozen dataclass; round-30 fail-fast
    discipline). The summary fields carry enough metadata to
    reconstruct the cell-exact vs tolerance mode and the concrete
    diff without parsing the diagnosis prose.
    """

    model_path: str
    reference_path: str
    task_path: str
    probe_index: int
    numpy_output_summary: str
    onnx_output_summary: str
    divergence_summary: str
    diagnosis: str
    minimal_fix: str


def _summary(arr: Any) -> str:
    """Compact one-line summary of a numpy array."""
    import numpy as np

    a = np.asarray(arr)
    if a.size == 0:
        return f"shape={a.shape} dtype={a.dtype} (empty)"
    try:
        s = float(a.sum())
    except (TypeError, ValueError):
        s = float("nan")
    return f"shape={a.shape} dtype={a.dtype} sum={s}"


def _is_one_hot_output(output_array: Any) -> bool:
    """Return True if the output looks like a known one-hot encoding."""
    import numpy as np

    a = np.asarray(output_array)
    if np.issubdtype(a.dtype, np.integer):
        return True
    return a.ndim >= 4 and a.shape[1] in _KNOWN_ONE_HOT_WIDTHS


def _adapt_input_shape(input_array: Any, expected_ndim: int) -> Any:
    """Add leading axes until ``input_array.ndim`` reaches ``expected_ndim``.

    NeuroGolf models commonly expect ``(1, 1, H, W)``; ARC-AGI
    grids are stored as ``[[...]]`` rank-2. The simplest
    reasonable approach is to add leading axes; Co-work
    documents this in the v0.9.3 CHANGELOG.
    """
    import numpy as np

    a = np.asarray(input_array)
    while a.ndim < expected_ndim:
        a = a[np.newaxis, ...]
    return a


def _compare_outputs(numpy_out: Any, onnx_out: Any) -> tuple[bool, str]:
    """Return (agree, summary) using cell-exact or tolerance mode."""
    import numpy as np

    np_arr = np.asarray(numpy_out)
    onnx_arr = np.asarray(onnx_out)
    if np_arr.shape != onnx_arr.shape:
        return False, (f"shape disagreement: numpy={np_arr.shape} vs " f"onnx={onnx_arr.shape}")
    if _is_one_hot_output(onnx_arr):
        agree = bool(np.array_equal(np_arr, onnx_arr))
        if agree:
            return True, "cell-exact (one-hot detected): identical"
        diff = np.asarray(np_arr != onnx_arr)
        n_differ = int(diff.sum())
        return False, (f"cell-exact (one-hot detected); {n_differ} cells differ")
    agree = bool(np.allclose(np_arr, onnx_arr, rtol=1e-5, atol=1e-7))
    if agree:
        return True, ("np.allclose(rtol=1e-5, atol=1e-7): within tolerance")
    diff = np.abs(np_arr.astype(float) - onnx_arr.astype(float))
    return False, (f"np.allclose(rtol=1e-5, atol=1e-7); max abs diff = " f"{float(diff.max()):.3e}")


def _make_runtime_diag(
    model_path: Path,
    reference_path: Path,
    task_path: Path,
    probe_index: int,
    side: str,
    exc: Exception,
) -> NumpyDivergenceDiagnostic:
    """Construct a diagnostic for a runtime failure on one side."""
    if side == "numpy":
        diagnosis = (
            f"numpy_reference raised on probe {probe_index}: "
            f"{type(exc).__name__}: {exc}. The reference contract "
            f"is broken for this input."
        )
        minimal_fix = (
            "Inspect the reference function and ensure it accepts "
            "the probe-grid shape. The input is the raw nested "
            "list from train[i]['input'] in the ARC-AGI task file."
        )
    else:
        diagnosis = (
            f"ONNX inference raised on probe {probe_index}: "
            f"{type(exc).__name__}: {exc}. The model has a "
            f"runtime issue that lint-time graph checks did not "
            f"surface."
        )
        minimal_fix = (
            "Inspect the model's expected input shape / dtype. "
            "Common causes: input rank mismatch, missing batch "
            "dimension, dtype mismatch with the declared input "
            "ValueInfo."
        )
    return NumpyDivergenceDiagnostic(
        model_path=str(model_path),
        reference_path=str(reference_path),
        task_path=str(task_path),
        probe_index=probe_index,
        numpy_output_summary="<not produced: numpy_reference raised>"
        if side == "numpy"
        else "<computed but onnx side raised>",
        onnx_output_summary="<not produced: onnx side raised>"
        if side == "onnx"
        else "<computed but numpy side raised>",
        divergence_summary=f"runtime error on {side} side",
        diagnosis=diagnosis,
        minimal_fix=minimal_fix,
    )


def check_numpy_divergence(  # noqa: PLR0915
    model_proto: Any, model_path: Path | str
) -> Iterator[NumpyDivergenceDiagnostic]:
    """Run the numpy-vs-ONNX divergence check.

    Silent-passes (returns without yielding) when:

    1. ``onnxruntime`` or ``numpy`` is not importable
       (the ``[onnx-runtime]`` extra is not installed).
    2. No sibling ``<basename>_build.py`` with a callable
       ``numpy_reference`` is discoverable.
    3. No sibling ``<basename>.json`` ARC-AGI task file is
       discoverable.

    Otherwise: for each probe grid in the discovered task file,
    runs ``numpy_reference(grid)`` and ONNX inference on the
    same input. Yields one ``NumpyDivergenceDiagnostic`` per
    diverging probe (or per side that raises an exception).
    """
    try:
        import numpy as np
        import onnxruntime as ort
    except ImportError:
        return  # silent-pass per Decision 6 (a)

    from furqan_lint.onnx_adapter.numpy_reference import (
        discover_numpy_reference,
    )
    from furqan_lint.onnx_adapter.probe_grid import discover_probe_grids

    p = Path(model_path)
    reference = discover_numpy_reference(p)
    if reference is None:
        return  # silent-pass per Decision 6 (b)
    grids = discover_probe_grids(p)
    if grids is None:
        return  # silent-pass per Decision 6 (c)

    reference_path = p.parent / f"{p.stem}_build.py"
    primary_task = p.parent / f"{p.stem}.json"
    task_path = (
        primary_task if primary_task.is_file() else (p.parent.parent / "tasks" / f"{p.stem}.json")
    )

    # Build an InferenceSession from the in-memory ModelProto's bytes;
    # the session reads SerializeToString rather than re-loading the
    # file (avoids an extra disk read and keeps the call site honest
    # about what model is being run).
    try:
        session = ort.InferenceSession(model_proto.SerializeToString())
    except Exception as e:
        # Cannot create a session at all; emit one runtime-error
        # diagnostic anchored at probe 0 so the user sees the issue.
        yield _make_runtime_diag(p, reference_path, task_path, 0, "onnx", e)
        return

    onnx_input_names = [i.name for i in session.get_inputs()]
    if not onnx_input_names:
        return  # malformed model has no inputs; silent-pass
    primary_input_name = onnx_input_names[0]
    primary_input_meta = session.get_inputs()[0]
    expected_ndim = len(primary_input_meta.shape) if primary_input_meta.shape is not None else 4
    onnx_input_dtype = _ort_dtype_to_numpy(primary_input_meta.type)

    for i, grid in enumerate(grids):
        # Run numpy reference. On exception, emit runtime-error
        # diagnostic; do not abort other probes.
        try:
            numpy_out = reference(grid)
        except Exception as exc:
            yield _make_runtime_diag(p, reference_path, task_path, i, "numpy", exc)
            continue

        # Run ONNX model. Adapt input shape to expected rank.
        try:
            input_array = np.asarray(grid)
            if onnx_input_dtype is not None:
                input_array = input_array.astype(onnx_input_dtype)
            input_array = _adapt_input_shape(input_array, expected_ndim)
            onnx_outs = session.run(None, {primary_input_name: input_array})
            onnx_out = onnx_outs[0]
        except Exception as exc:
            yield _make_runtime_diag(p, reference_path, task_path, i, "onnx", exc)
            continue

        # Compare. The numpy_out may need shape adaptation too if
        # the reference returns a different rank than the ONNX
        # output. Add leading axes until the ranks match.
        np_arr = np.asarray(numpy_out)
        onnx_arr = np.asarray(onnx_out)
        while np_arr.ndim < onnx_arr.ndim:
            np_arr = np_arr[np.newaxis, ...]
        while onnx_arr.ndim < np_arr.ndim:
            onnx_arr = onnx_arr[np.newaxis, ...]

        agree, summary = _compare_outputs(np_arr, onnx_arr)
        if agree:
            continue

        diagnosis = (
            f"Probe {i}: numpy reference and ONNX model disagree. "
            f"{summary}. The substrate-vs-surface gap is the "
            f"dominant NeuroGolf failure mode: the build script's "
            f"intent (numpy reference) and the exported graph "
            f"(ONNX) do not compute the same function on this "
            f"input."
        )
        minimal_fix = (
            "Either: (a) re-derive the ONNX graph from the numpy "
            "reference (the reference is the canonical specification); "
            "(b) update the numpy reference to match the graph's "
            "actual semantics; or (c) inspect the disagreement "
            "(differing cells / max abs diff) to identify which "
            "operator in the graph differs from the reference."
        )
        yield NumpyDivergenceDiagnostic(
            model_path=str(p),
            reference_path=str(reference_path),
            task_path=str(task_path),
            probe_index=i,
            numpy_output_summary=_summary(np_arr),
            onnx_output_summary=_summary(onnx_arr),
            divergence_summary=summary,
            diagnosis=diagnosis,
            minimal_fix=minimal_fix,
        )


def _ort_dtype_to_numpy(ort_type: str) -> Any:
    """Map an onnxruntime type string to a numpy dtype, or None.

    Used to coerce the input grid to the ONNX model's expected
    dtype before inference. Only handles the common cases; falls
    back to numpy's auto-inference for anything unrecognized
    (returns None; caller passes the array through).
    """
    import numpy as np

    table = {
        "tensor(float)": np.float32,
        "tensor(double)": np.float64,
        "tensor(int64)": np.int64,
        "tensor(int32)": np.int32,
        "tensor(int8)": np.int8,
        "tensor(uint8)": np.uint8,
        "tensor(bool)": np.bool_,
    }
    return table.get(ort_type)
