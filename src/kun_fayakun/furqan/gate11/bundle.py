"""CASM-Sigstore bundle file format read/write (T07).

A CASM-Sigstore bundle is stored as
``<module-name>.furqan.manifest.sigstore`` next to the module
source. JSON shape (top-level):

* ``manifest``: the CASM v1.0 manifest dict (Section ``manifest_schema``).
* ``sigstore_bundle``: the Sigstore Bundle dict-of-record for the
  signing event, as serialized via sigstore-python's
  ``Bundle.to_json()``.

The signature is computed over the canonical manifest JSON
(RFC 8785 + UTF-8). The Bundle inside includes:

* the signature
* the Fulcio-issued ephemeral certificate
* the Rekor inclusion proof / tlog entry
* the SCT (signed certificate timestamp)

This module imports ``sigstore`` lazily; round-trip JSON
serialization works without sigstore installed (we treat the
``sigstore_bundle`` payload as opaque dict-of-record), but
turning it into a verifiable Sigstore object requires the
[gate11] extra (which the verifier in T08 owns).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from furqan_lint.gate11.manifest_schema import (
    CasmSchemaError,
    Manifest,
)


class BundleParseError(ValueError):
    """Raised when a bundle file cannot be parsed.

    Carries a CASM-V error code as ``code``. T07 raises with
    ``CASM-V-010`` per the nine-step verification flow.
    """

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


@dataclass
class Bundle:
    """In-memory CASM-Sigstore bundle.

    ``manifest`` is the parsed ``Manifest`` dataclass.
    ``sigstore_bundle`` is held as ``Any`` because callers may
    pass either a sigstore-python ``Bundle`` object (sign path)
    or the dict-of-record (verify path). Serialization unifies
    on the dict-of-record.
    """

    manifest: Manifest
    sigstore_bundle: Any

    def to_json(self) -> dict[str, Any]:
        """Return the dict that ``write`` serializes to JSON."""
        sb = self.sigstore_bundle
        if hasattr(sb, "to_json"):
            sb_payload: Any = json.loads(sb.to_json())
        elif hasattr(sb, "_inner"):
            # Older sigstore-python versions exposed an _inner attr.
            sb_payload = json.loads(json.dumps(sb._inner, default=str))
        else:
            sb_payload = sb
        return {
            "manifest": self.manifest.to_dict(),
            "sigstore_bundle": sb_payload,
        }

    def write(self, path: Path | str) -> None:
        """Write the bundle to ``path`` as JSON."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8") as f:
            json.dump(self.to_json(), f, indent=2, sort_keys=True)
            f.write("\n")

    @staticmethod
    def read(path: Path | str) -> Bundle:
        """Read a bundle file from ``path``.

        Raises ``BundleParseError`` with code ``CASM-V-010`` on:

        * malformed JSON
        * missing ``manifest`` field
        * missing ``sigstore_bundle`` field
        * manifest schema violation (also wraps the underlying
          ``CasmSchemaError`` so the caller can read both
          ``CASM-V-010`` and ``CASM-V-001`` chains)
        """
        p = Path(path)
        try:
            with p.open(encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise BundleParseError(
                "CASM-V-010",
                f"bundle file {p} is not valid JSON: {e}",
            ) from e
        except OSError as e:
            raise BundleParseError(
                "CASM-V-010",
                f"could not read bundle file {p}: {e}",
            ) from e
        if not isinstance(data, dict):
            raise BundleParseError("CASM-V-010", "bundle JSON must be an object at top level")
        if "manifest" not in data:
            raise BundleParseError("CASM-V-010", "bundle missing 'manifest' field")
        if "sigstore_bundle" not in data:
            raise BundleParseError("CASM-V-010", "bundle missing 'sigstore_bundle' field")
        try:
            manifest = Manifest.from_dict(data["manifest"])
        except CasmSchemaError as e:
            raise BundleParseError(
                "CASM-V-010",
                f"bundle 'manifest' field failed schema validation: {e}",
            ) from e
        return Bundle(manifest=manifest, sigstore_bundle=data["sigstore_bundle"])


__all__ = (
    "Bundle",
    "BundleParseError",
)
