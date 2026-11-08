"""Sigstore-CASM Gate 11 v1.0 (Phase G11.0).

Cryptographic enforcement of the additive-only contract for a
Python module's public surface, via Sigstore (Newman 2022)
backing the Compositional Additive-only Surface Manifest (CASM)
JSON document.

The kiraman katibin (Al-Infitar 82:10-11; Qaf 50:17) record
without altering. Rekor's append-only transparency log is the
cryptographic analogue: every signing event is witnessed at
sign-time; the verifier opens the record at verify-time and
checks the inclusion proof.

Public surface (re-exported from submodules):

* ``Manifest`` -- CASM v1.0 dataclass; ``from_dict``,
  ``to_canonical_bytes``.
* ``module_root_hash`` -- SHA-256 of canonicalized module source.
* ``signature_fingerprint`` -- per-name signature hash.
* ``extract_public_surface`` -- AST-based public surface walker.
* ``Bundle`` -- read/write ``.furqan.manifest.sigstore``.
* ``Verifier`` / ``CasmVerificationError`` -- 9-step verification.
* ``sign_manifest`` -- OIDC sign path (network-bound; smoke-tested).

This package's submodules import ``sigstore`` and ``rfc8785``
lazily; importing ``furqan_lint.gate11`` itself does not pull
either dependency unless the [gate11] extra is installed.
"""

from __future__ import annotations

__all__ = (
    "CASM_VERSION",
    "GATE11_BUNDLE_SUFFIX",
)

CASM_VERSION = "1.0"

# CASM-Sigstore bundle filename suffix per the deliverable scope.
# A bundle for module ``foo/bar.py`` is stored as
# ``foo/bar.furqan.manifest.sigstore`` next to the module source.
# The .sigstore extension follows the Sigstore ecosystem
# convention so Sigstore-aware tools recognize the file format.
GATE11_BUNDLE_SUFFIX = ".furqan.manifest.sigstore"
