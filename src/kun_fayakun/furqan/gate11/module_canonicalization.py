"""Module-source canonicalization for CASM v1.0.

The ``module_root_hash`` in the manifest is the SHA-256 of a
canonicalized module source. The canonicalization rules per the
Phase G11.0 prompt:

1. Read the module source as bytes.
2. Decode as UTF-8. Non-UTF-8 sources raise CASM-V-002.
3. Normalize line endings to ``\\n``.
4. Strip BOM if present.
5. Re-encode as UTF-8 bytes.
6. Compute SHA-256 on those bytes.

Whitespace, comments, and docstrings are part of the canonical
form. CASM v1.0 commits to the exact module source, not a
semantic equivalent. AST-level canonicalization is reserved for
v1.5+.
"""

from __future__ import annotations

import hashlib
from pathlib import Path


class ModuleCanonicalizationError(ValueError):
    """Raised when a module source cannot be canonicalized.

    Carries a CASM-V error code as ``code``. v1.0 raises with
    ``CASM-V-002`` when the source is not valid UTF-8.
    """

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


_BOM = b"\xef\xbb\xbf"


def canonicalize_module(path: Path | str) -> bytes:
    """Read ``path`` and return canonicalized bytes.

    Raises ``ModuleCanonicalizationError`` with code
    ``CASM-V-002`` if the source is not valid UTF-8.
    """
    p = Path(path)
    raw = p.read_bytes()
    # Step 4: strip BOM (must happen before decode-and-re-encode
    # so the canonical form is BOM-free regardless of input).
    if raw.startswith(_BOM):
        raw = raw[len(_BOM) :]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ModuleCanonicalizationError(
            "CASM-V-002",
            f"module source at {p} is not valid UTF-8: {e}",
        ) from e
    # Step 3: normalize line endings.
    # CRLF -> LF, then any remaining CR -> LF (handles old-Mac CR
    # line endings if they ever appear).
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.encode("utf-8")


def module_root_hash(path: Path | str) -> str:
    """Return ``"sha256:<hex64>"`` for the canonicalized source."""
    canonical = canonicalize_module(path)
    digest = hashlib.sha256(canonical).hexdigest()
    return f"sha256:{digest}"


__all__ = (
    "ModuleCanonicalizationError",
    "canonicalize_module",
    "module_root_hash",
)
