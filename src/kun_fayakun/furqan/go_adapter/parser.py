"""Go adapter parser: invokes the bundled goast binary.

The binary lives at ``src/furqan_lint/go_adapter/bin/goast`` and
is built at install time via the ``[go]`` extra's PEP 517 build
hook. If the bundled binary is not present, ``parse_file`` raises
``GoExtrasNotInstalled`` with the install hint as its message.

There is NO ``$PATH`` fallback. A ``$PATH`` fallback would let a
contributor's stale ``goast`` from a different version pass tests
silently. The discovery order is bundled binary, then the
``FURQAN_LINT_GOAST_BIN`` env var (explicit dev override only),
then loud failure.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from furqan_lint.go_adapter._exceptions import (
    GoExtrasNotInstalled,
    GoParseError,
)

_PARSE_TIMEOUT_SECONDS = 10


def _locate_goast() -> Path:
    """Locate the goast binary in priority order:

    1. Bundled binary at ``go_adapter/bin/goast`` relative to the
       package (the production path; the PEP 517 build hook
       compiles it during install).
    2. ``FURQAN_LINT_GOAST_BIN`` env var (explicit dev override
       only; emits a stderr note so accidental reliance is
       visible).
    3. Raise ``GoExtrasNotInstalled`` with the install hint as
       its message. NO ``$PATH`` fallback.

    Structured with a single trailing return after a guard-raise
    block so D24 sees uniform path coverage. The ``raise`` form
    is intentionally placed inside an ``if resolved is None``
    guard rather than as a fall-through tail; D24 treats raise
    statements as conservatively unmodelled, so the trailing
    return must be the lexical terminator. See also
    ``rust_adapter.translator._assert_parses_cleanly`` for the
    same pattern.
    """
    pkg_root = Path(__file__).resolve().parent
    bundled = pkg_root / "bin" / "goast"
    resolved: Path | None = None
    if bundled.is_file() and os.access(bundled, os.X_OK):
        resolved = bundled
    else:
        override = os.environ.get("FURQAN_LINT_GOAST_BIN")
        if override:
            candidate = Path(override)
            if candidate.is_file() and os.access(candidate, os.X_OK):
                print(
                    f"[furqan-lint] using FURQAN_LINT_GOAST_BIN override: {candidate}",
                    file=sys.stderr,
                )
                resolved = candidate
    if resolved is None:
        raise GoExtrasNotInstalled("Go support not installed. Run: pip install furqan-lint[go]")
    return resolved


def parse_file(path: Path | str) -> dict[str, Any]:
    """Run goast on ``path`` and return the parsed JSON output.

    Raises ``GoExtrasNotInstalled`` if the bundled binary is not
    present (the CLI converts to exit code 1 + install hint).

    Raises ``GoParseError`` if the binary fails to parse the
    source (the CLI converts to exit code 2 + the binary's stderr
    message).

    The ``_PARSE_TIMEOUT_SECONDS`` ceiling defends against
    pathological inputs (deeply nested expressions, syntactically
    valid but unbounded recursion in goast's walker, etc.). The
    timeout converts to a ``GoParseError`` rather than a process
    crash.
    """
    binary = _locate_goast()
    target = str(path)
    try:
        result = subprocess.run(
            [str(binary), target],
            capture_output=True,
            text=True,
            timeout=_PARSE_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise GoParseError(f"goast timed out after {_PARSE_TIMEOUT_SECONDS}s on {target}") from e
    if result.returncode != 0:
        message = result.stderr.strip() or f"goast exit {result.returncode}"
        raise GoParseError(message)
    try:
        parsed: dict[str, Any] = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise GoParseError(f"goast emitted unparseable JSON: {e}") from e
    return parsed
