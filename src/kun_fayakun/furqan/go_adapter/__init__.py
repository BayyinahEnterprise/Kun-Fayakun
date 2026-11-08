"""Go adapter: opt-in via the ``[go]`` extra.

Provides D24 (all-paths-return) and D11 (status-coverage with the
Go ``(T, error)`` firing shape) on .go source files. The
``goast`` binary is built from
``src/furqan_lint/go_adapter/cmd/goast/main.go`` at install time
via the ``[go]`` extra's PEP 517 build hook; users do not need a
Go toolchain at runtime.

The cross-language may-fail predicate ``_is_may_fail_producer``
(Shape B, locked in v0.8.0 per ADR-002 §10 Q3 follow-up) lives in
``furqan_lint.runner``. The Go adapter imports it directly; it
does not maintain its own predicate.

Public surface
==============

* ``parse_file(path)`` -> ``dict``: invoke the bundled goast
  binary on ``path`` and return parsed JSON.
* ``extract_public_names(path)`` -> ``frozenset[str]``: return
  the uppercase-initial Go identifiers exposed by ``path``. Used
  by the additive-only diff path
  (``furqan-lint diff old.go new.go``). Added in v0.8.1.
* ``GoExtrasNotInstalled``: raised when the bundled binary is
  not present. CLI converts to exit code 1 plus the install hint.
* ``GoParseError``: raised when goast fails to parse the source.
  CLI converts to exit code 2 (PARSE ERROR).

Everything else (the translator, the runner, the build hook) is
intentionally not exported.
"""

from __future__ import annotations

from furqan_lint.go_adapter._exceptions import (
    GoExtrasNotInstalled,
    GoParseError,
)

__all__ = (
    "GoExtrasNotInstalled",
    "GoParseError",
    "extract_public_names",
    "parse_file",
)


def parse_file(path: object) -> dict[str, object]:
    """Parse ``path`` as Go source and return the goast JSON output.

    Lazy-imports ``furqan_lint.go_adapter.parser`` so importing this
    package does not require the bundled binary to be present.
    """
    from pathlib import Path

    from furqan_lint.go_adapter.parser import parse_file as _parse_file

    if isinstance(path, Path):
        return _parse_file(path)
    return _parse_file(Path(str(path)))


def extract_public_names(path: object) -> frozenset[str]:
    """Return uppercase-initial Go identifier names exposed by ``path``.

    Lazy-imports ``furqan_lint.go_adapter.public_names`` so this
    package's import path does not require the bundled binary to
    be present.
    """
    from pathlib import Path

    from furqan_lint.go_adapter.public_names import extract_public_names as _extract

    if isinstance(path, Path):
        return _extract(path)
    return _extract(Path(str(path)))
