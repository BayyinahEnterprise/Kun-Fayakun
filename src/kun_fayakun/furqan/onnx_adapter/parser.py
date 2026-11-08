"""Parse ONNX model files into ModelProto.

Uses the ``onnx`` Python package's protobuf loader. No
``onnxruntime`` dependency: lint-time checks operate on the
graph structure, not on inference. Does not call
``onnx.checker.check_model()``; semantic validity is the job
of furqan-lint's own checkers (D24-onnx, opset-compliance),
which are the authoritative source per Decision 1 of the
v0.9.0 prompt.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def parse_model(path: Path | str) -> Any:
    """Load an ONNX model and return the ``ModelProto``.

    Raises :class:`furqan_lint.onnx_adapter.OnnxExtrasNotInstalled`
    if the ``onnx`` package is not available.

    Raises :class:`furqan_lint.onnx_adapter.OnnxParseError` if
    the protobuf at ``path`` cannot be loaded.
    """
    from furqan_lint.onnx_adapter import (
        OnnxExtrasNotInstalled,
        OnnxParseError,
    )

    try:
        import onnx
    except ImportError as e:
        raise OnnxExtrasNotInstalled(
            "ONNX support not installed. Run: pip install furqan-lint[onnx]"
        ) from e

    p = Path(path)
    try:
        return onnx.load(str(p))
    except Exception as e:
        raise OnnxParseError(str(p), str(e)) from e
