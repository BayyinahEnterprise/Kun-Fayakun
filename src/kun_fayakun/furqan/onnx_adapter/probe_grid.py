"""Discover ARC-AGI task files for probe-grid extraction.

Convention (Decision 3 of v0.9.3 prompt): for each ``.onnx`` file
at path ``<dir>/<basename>.onnx``, the lint searches for a JSON
task file in two locations:

1. ``<dir>/<basename>.json`` (primary)
2. ``<dir>/../tasks/<basename>.json`` (fallback)

The two-location search handles the two common deployment
layouts: model and task file colocated, or task files in a
sibling ``tasks/`` directory.

The task file is expected to be in ARC-AGI format with a
top-level ``train`` array of ``{"input": [[...]], "output":
[[...]]}`` examples. Each ``train[i]['input']`` is used as a
probe grid; multi-example tasks emit one finding per diverging
probe.

The format itself is NeuroGolf-specific by design (see
Decision 9). General-purpose probe-grid formats are a v0.9.5+
extension.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _load_task_train_inputs(path: Path) -> list[Any] | None:
    """Load and validate one task file. Returns ``train[*]['input']``
    list, or ``None`` if the file is unparseable / malformed.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    train = data.get("train")
    if not isinstance(train, list) or not train:
        return None
    out: list[Any] = []
    for example in train:
        if not isinstance(example, dict):
            return None
        grid = example.get("input")
        if grid is None:
            return None
        out.append(grid)
    return out


def discover_probe_grids(model_path: Path | str) -> list[Any] | None:
    """Return a list of probe grids from ``train[*]['input']`` in the
    discovered ARC-AGI task file, or ``None``.

    Search order (Decision 3 of v0.9.3 prompt):

    1. ``<dir>/<basename>.json`` (primary)
    2. ``<dir>/../tasks/<basename>.json`` (fallback)

    Returns ``None`` (silent-pass per Decision 6 condition (c))
    when no task file is discoverable, when the file fails to
    parse as JSON, when the JSON top level is not a dict, or
    when ``train`` is missing / not a non-empty list, or when
    any train example is missing ``input``.

    Document order is preserved: probe grid 0 corresponds to
    ``train[0]['input']``, etc. Each grid is the raw nested
    list from the JSON; callers convert to ``numpy.ndarray``
    via ``np.array(grid)`` as needed.
    """
    p = Path(model_path)
    primary = p.parent / f"{p.stem}.json"
    fallback = p.parent.parent / "tasks" / f"{p.stem}.json"

    for candidate in (primary, fallback):
        if not candidate.is_file():
            continue
        grids = _load_task_train_inputs(candidate)
        if grids is not None:
            return grids
    return None
