"""ONNX adapter: parse .onnx model files into an OnnxModule for
D24-onnx (all-paths-emit) and opset-compliance.

Opt-in via the ``[onnx]`` extra:

    pip install furqan-lint[onnx]

Symmetric with ``rust_adapter`` and ``go_adapter``: the package is
importable without the extra (the CLI does not import this module
unless asked to lint a ``.onnx`` file), so the Python-only install
path remains unaffected. The ``onnx`` Python package is imported
lazily inside ``parse_model``; importing this package alone does
not trigger an ``onnx`` import.

If ``parse_model`` is called and ``onnx`` is missing, it raises
``OnnxExtrasNotInstalled`` (a subclass of ``ImportError``) with
the install hint as its message. The CLI catches this typed
exception and prints a calm one-line install hint instead of
dumping a Python traceback, mirroring the Rust and Go adapter
contract.

Structural divergence (load-bearing per Decision 1 of the v0.9.0
prompt and the round-24 C1 finding closure):
``onnx.checker.check_model()`` is **not** invoked anywhere in
furqan-lint. ONNX semantic validity is the responsibility of
furqan-lint's own checkers (D24-onnx, opset-compliance), which
are the authoritative source. Using ``onnx.checker`` would
conflate parse-failure with semantic-validity failure and overlap
with diagnostics that this package ships to detect.

Public surface
==============

* ``parse_model(path)`` -> ``ModelProto``: load an ONNX model from
  ``path`` and return the protobuf ``ModelProto``.
* ``extract_public_names(path)`` -> ``frozenset[str]``: return
  the ``input:NAME:SHAPE`` and ``output:NAME:SHAPE`` identifiers
  declared in the model's ``graph.input`` and ``graph.output``.
  Used by the additive-only diff path
  (``furqan-lint diff old.onnx new.onnx``).
* ``OnnxParseError``: raised when the ``.onnx`` protobuf cannot be
  loaded; the CLI converts this to exit code 2.
* ``OnnxExtrasNotInstalled``: raised when the ``[onnx]`` extra is
  missing from the install. CLI converts to exit code 1 plus the
  install hint.
* ``OnnxModule``: dataclass summary of a parsed ONNX model
  consumed by the runner. Translation lives in
  ``onnx_adapter.translator.to_onnx_module``.

Everything else (the runner internals, the dataflow walker, the
opset-compliance schema-lookup glue) is intentionally not
exported. The going-forward additive-only discipline applies.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


class OnnxExtrasNotInstalled(ImportError):
    """Raised when the ``[onnx]`` extra is missing from the install.

    Subclass of ``ImportError`` so callers that catch ``ImportError``
    behave correctly. Carries the canonical install hint as its
    message.
    """


class OnnxParseError(Exception):
    """Raised when an ``.onnx`` protobuf cannot be loaded.

    Carries the source path and an underlying-error detail string.
    The CLI maps this to exit code 2 (parse failure).
    """

    def __init__(self, path: str, detail: str) -> None:
        self.path = path
        self.detail = detail
        super().__init__(f"{path}: {detail}")


class OnnxRuntimeExtrasNotInstalled(ImportError):
    """Raised when the ``[onnx-runtime]`` extra is missing.

    Subclass of ``ImportError`` so callers that catch ``ImportError``
    behave correctly. v0.9.3+: distinguishes the inference-extra
    failure from the ``[onnx]`` graph-only extra failure
    (``OnnxExtrasNotInstalled``). The numpy-vs-ONNX divergence
    checker silent-passes when this would have been raised
    (Decision 6 condition (a)); the exception type exists for
    tests and any future caller that wants to surface the
    install-failure mode explicitly.
    """


class OnnxProfileExtrasNotInstalled(ImportError):
    """Raised when the ``[onnx-profile]`` extra is missing.

    Subclass of ``ImportError``. v0.9.4+: distinguishes the
    profile-extra failure from the ``[onnx]`` graph-only and
    ``[onnx-runtime]`` inference extras. The score-validity
    checker silent-passes when ``import onnx_tool`` raises
    (Decision 6 (a) of v0.9.4 prompt); the exception type
    exists for tests that surface install-failure modes
    explicitly.
    """


from furqan_lint.onnx_adapter.numpy_divergence import (  # noqa: E402
    NumpyDivergenceDiagnostic,
    check_numpy_divergence,
)
from furqan_lint.onnx_adapter.numpy_reference import (  # noqa: E402
    discover_numpy_reference,
)
from furqan_lint.onnx_adapter.probe_grid import (  # noqa: E402
    discover_probe_grids,
)
from furqan_lint.onnx_adapter.score_validity import (  # noqa: E402
    ScoreValidityDiagnostic,
    check_score_validity,
)
from furqan_lint.onnx_adapter.shape_coverage import (  # noqa: E402
    ShapeCoverageDiagnostic,
    check_shape_coverage,
)
from furqan_lint.onnx_adapter.translator import (  # noqa: E402
    BranchSummary,
    NodeSummary,
    OnnxModule,
    ValueInfoSummary,
)

__all__ = (
    "BranchSummary",
    "NodeSummary",
    "NumpyDivergenceDiagnostic",
    "OnnxExtrasNotInstalled",
    "OnnxModule",
    "OnnxParseError",
    "OnnxProfileExtrasNotInstalled",
    "OnnxRuntimeExtrasNotInstalled",
    "ScoreValidityDiagnostic",
    "ShapeCoverageDiagnostic",
    "ValueInfoSummary",
    "check_numpy_divergence",
    "check_score_validity",
    "check_shape_coverage",
    "discover_numpy_reference",
    "discover_probe_grids",
    "extract_public_names",
    "parse_model",
)


def parse_model(path: Path | str) -> Any:
    """Load an ONNX model and return its ``ModelProto``.

    Raises :class:`OnnxExtrasNotInstalled` if the ``onnx`` package
    is not available. Raises :class:`OnnxParseError` if the
    protobuf at ``path`` cannot be loaded.

    Does NOT run ONNX semantic-validity checks
    (``onnx.checker.check_model()``); that responsibility belongs
    to furqan-lint's own checkers per Decision 1 of the v0.9.0
    prompt.
    """
    from furqan_lint.onnx_adapter.parser import parse_model as _parse

    return _parse(path)


def extract_public_names(path: Path | str) -> frozenset[str]:
    """Return ``input:NAME:SHAPE`` / ``output:NAME:SHAPE`` identifiers.

    Lazy-imports
    ``furqan_lint.onnx_adapter.public_names.extract_public_names``
    so this package's import path does not require the ``onnx``
    package to be present (the missing-extras case is handled
    inside the helper, which raises
    :class:`OnnxExtrasNotInstalled` with the install hint).
    """
    from furqan_lint.onnx_adapter.public_names import (
        extract_public_names as _extract,
    )

    return _extract(path)
