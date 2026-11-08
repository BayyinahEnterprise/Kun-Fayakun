"""Discover NeuroGolf-convention numpy reference functions.

Convention (Decision 2 of v0.9.3 prompt): for each ``.onnx`` file
at path ``<dir>/<basename>.onnx``, the lint searches for a Python
file at ``<dir>/<basename>_build.py`` containing a top-level
callable ``numpy_reference``. The callable accepts one positional
argument (the input grid as a list-of-lists or numpy array) and
returns the expected output as a list-of-lists, numpy array, or
tuple of arrays for multi-output models.

The convention is NeuroGolf-specific by design (see Decision 9
and the four-place documented limit
``numpy_divergence_neurogolf_convention``). General-purpose
reference-discovery conventions (e.g., decorator annotation,
module-level registry) are a v0.9.5+ extension.

The loader uses ``importlib.util.spec_from_file_location`` and
does NOT modify ``sys.path`` or ``sys.modules``: a unique
per-invocation module name keeps the loaded module isolated to
the caller.
"""

from __future__ import annotations

import importlib.util
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any


def discover_numpy_reference(model_path: Path | str) -> Callable[..., Any] | None:
    """Return the ``numpy_reference`` callable from the sibling
    ``_build.py``, or ``None`` if absent / unloadable.

    Search location: for ``<dir>/<basename>.onnx``, look for
    ``<dir>/<basename>_build.py``. The loader uses
    ``importlib.util.spec_from_file_location`` with a unique module
    name (``_furqan_build_<uuid>``) so ``sys.modules`` is not
    polluted across invocations.

    Returns ``None`` (silent-pass per Decision 6 condition (b))
    when:

    * The ``_build.py`` file does not exist.
    * The file does not contain a top-level callable named
      ``numpy_reference``.
    * The file fails to load for any reason
      (``spec_from_file_location`` returns ``None``,
      ``module_from_spec`` raises, or ``exec_module`` raises).

    The silent-pass discipline means generic ONNX users with no
    NeuroGolf-shaped sidecar see no behavior change; only models
    with both a ``_build.py`` and a corresponding ``.json`` task
    file run the divergence check.
    """
    p = Path(model_path)
    candidate = p.parent / f"{p.stem}_build.py"
    if not candidate.is_file():
        return None
    # Unique module name avoids sys.modules pollution. We
    # intentionally do NOT register the module in sys.modules:
    # the loaded reference is one-shot per check invocation.
    mod_name = f"_furqan_build_{uuid.uuid4().hex}"
    try:
        spec = importlib.util.spec_from_file_location(mod_name, str(candidate))
    except Exception:
        return None
    if spec is None or spec.loader is None:
        return None
    try:
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception:
        return None
    ref = getattr(module, "numpy_reference", None)
    if not callable(ref):
        return None
    return ref  # type: ignore[no-any-return]
