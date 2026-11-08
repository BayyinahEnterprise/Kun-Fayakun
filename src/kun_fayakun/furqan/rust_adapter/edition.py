"""Find and parse the Rust edition of a source file.

Walks parents of a given path looking for the nearest ``Cargo.toml``.
If found, parses the ``[package].edition`` field (one of "2018",
"2021", "2024"). If absent or malformed, defaults to "2021".

The current implementation does not branch on edition: every
fixture parses identically across 2018/2021/2024. The hook exists so v0.7.x can add an
edition-conditional fixture without restructuring.
"""

from __future__ import annotations

# Python 3.10 ships ``tomllib`` only as a backport on PyPI; the
# project requires 3.10+ so we import the stdlib ``tomllib`` on
# 3.11+ and fall back to ``tomli`` on 3.10. Both APIs are
# byte-stream compatible.
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib as _tomllib
else:  # pragma: no cover - 3.10 fallback
    import tomli as _tomllib


_DEFAULT_EDITION = "2021"
_SUPPORTED_EDITIONS: frozenset[str] = frozenset({"2018", "2021", "2024"})


def edition_for(source_path: Path) -> str:
    """Return the Rust edition that applies to ``source_path``.

    Walks ``source_path``'s ancestors looking for the nearest
    ``Cargo.toml``. If found, reads ``[package].edition`` and
    returns it (provided the value is one of the supported
    editions). Otherwise returns the default ``"2021"``.

    A missing / malformed Cargo.toml or an unrecognised edition
    value silently falls back to the default. The fallback path is
    documented in the README under "Rust support (opt-in)".
    """
    for cargo_toml in _find_nearest_cargo_toml(source_path):
        return _edition_from_cargo_toml(cargo_toml)
    return _DEFAULT_EDITION


def _find_nearest_cargo_toml(source_path: Path) -> list[Path]:
    """Return a single-element list containing the nearest ancestor
    ``Cargo.toml`` of ``source_path``, or an empty list if none is
    found (or if path resolution fails).

    Returns a list rather than ``Path | None`` so the consumer-side
    discipline (D11) is honestly propagated.
    """
    try:
        anchor = source_path.resolve(strict=False)
    except OSError:
        return []
    for parent in (anchor, *anchor.parents):
        candidate = parent / "Cargo.toml"
        if candidate.is_file():
            return [candidate]
    return []


def _edition_from_cargo_toml(cargo_toml: Path) -> str:
    """Parse ``Cargo.toml`` and return ``[package].edition`` if it
    is one of the supported editions; otherwise return the default.

    Catches the broad ``Exception`` because malformed TOML, missing
    sections, and non-string edition values are all "fall back to
    default" cases for our purposes; we don't want a malformed
    Cargo.toml to crash the linter.
    """
    try:
        with cargo_toml.open("rb") as handle:
            data = _tomllib.load(handle)
    except (OSError, _tomllib.TOMLDecodeError):
        return _DEFAULT_EDITION
    package = data.get("package")
    if not isinstance(package, dict):
        return _DEFAULT_EDITION
    edition = package.get("edition")
    if isinstance(edition, str) and edition in _SUPPORTED_EDITIONS:
        return edition
    return _DEFAULT_EDITION
