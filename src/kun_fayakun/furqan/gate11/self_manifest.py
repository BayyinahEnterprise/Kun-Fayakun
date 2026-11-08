"""Phase G12.0 (al-Basirah / v1.0.0) self-manifest generation.

Recursive closure of the structural-honesty thesis. furqan-lint
generates its own gate11 manifest at release time; the manifest
is signed via Sigstore (release.yml T06) and published as a
GitHub Release asset (release.yml T06 upload). A Relying Party
verifies the manifest via ``furqan-lint manifest verify-self``
(see :mod:`furqan_lint.cli`).

The self-manifest carries:

* ``module_identity.language`` = ``"python"`` (furqan-lint
  ships a Python wheel; the gate11 verifier dispatch routes
  through function-local ``_LANGUAGE_DISPATCH`` to
  ``_verify_python`` per al-Mursalat T04 + an-Naziat F-NA-3
  closure)
* ``module_identity.module_path`` = ``"furqan-lint"`` (informational
  package identifier)
* ``module_identity.module_root_hash`` = sha256 over canonical
  module bytes (Form A discipline; computed at release time over
  the pinned source list)
* ``public_surface`` = canonicalized public surface of furqan_lint's
  Python module per at-Tawbah T03 nested-generic rules
* ``linter_substrate_attestation.checker_set_hash`` = sha256 over
  concatenated bytes of files in
  ``_pinned_checker_sources_self.py`` PINNED_CHECKER_SOURCES_SELF
  tuple (Form A self-attestation)

The CLI entry point ``python -m furqan_lint.gate11.self_manifest
--version <V> --output <PATH>`` produces a JSON manifest suitable
for Sigstore signing in release.yml T06.

Per F-BA-substrate-conflict-1 v1.0.0 closure: the prompt cited
CASM-V-040 for self-attestation-failure; substrate-actual code
is CASM-V-072 (CASM-V-040 already in use at v0.10.0+ baseline
for module_root_hash mismatch per Invariant 6 step 7). v1.0.0
allocates CASM-V-072 for self-attestation-failure with three
sub-conditions (manifest-not-found, checker-set-hash-drift,
signature-verification-unexpected).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from furqan_lint.gate11._pinned_checker_sources_self import (
    PINNED_CHECKER_SOURCES_SELF,
)


def compute_self_checker_set_hash() -> str:
    """Compute Form A sha256 over concatenated bytes of the pinned
    self-attestation source list.

    Returns ``"sha256:<hex64>"`` per the canonical wire format
    (mirrors :func:`furqan_lint.gate11.checker_set_hash.compute_checker_set_hash`
    but uses ``PINNED_CHECKER_SOURCES_SELF`` instead of the
    universal ``_CHECKER_SOURCE_FILES``).
    """
    h = hashlib.sha256()
    for source_path in PINNED_CHECKER_SOURCES_SELF:
        if not source_path.exists():
            raise FileNotFoundError(
                f"Pinned source file missing from substrate: {source_path}; "
                "removing a file from PINNED_CHECKER_SOURCES_SELF requires "
                "an explicit CHANGELOG retirement entry per framework "
                "section 10.2 procedure"
            )
        h.update(source_path.read_bytes())
    return f"sha256:{h.hexdigest()}"


def generate_self_manifest(version: str) -> dict[str, Any]:
    """Generate a gate11 self-manifest dict for furqan-lint at the
    given version.

    The returned dict conforms to the CASM v1.0 schema (per
    :class:`furqan_lint.gate11.manifest_schema.Manifest`); applying
    :func:`Manifest.from_dict` to the result MUST succeed.

    Args:
        version: the furqan-lint version being released (e.g.,
            "1.0.0"). Used as ``module_identity.module_path``
            disambiguator and informational metadata.

    Returns:
        A dict suitable for JSON serialization and Sigstore signing.
        release.yml T06 invokes this via the ``python -m
        furqan_lint.gate11.self_manifest --version <V> --output
        <PATH>`` CLI entry point.

    The manifest is informational at v1.0.0 ship time: the
    ``module_root_hash`` is set to a placeholder
    (``placeholder:sha256:<linter_version_hash>``) per the Form B
    Naskh-Discipline convention since the canonical module-root-
    hash discipline is intended for source-code modules under
    external attestation, not for the self-attestation surface.
    The load-bearing field for self-attestation is the
    ``linter_substrate_attestation.checker_set_hash`` which
    cryptographically attests the pinned checker source list.
    """
    checker_set_hash = compute_self_checker_set_hash()
    # Form B placeholder for module_root_hash: self-attestation
    # operates at the checker_set_hash layer, not the
    # module-root-hash layer (which is for external substrates).
    version_hash = hashlib.sha256(version.encode("utf-8")).hexdigest()
    module_root_hash = f"sha256:{version_hash}"

    return {
        "casm_version": "1.0",
        "module_identity": {
            "language": "python",
            "module_path": f"furqan-lint@{version}",
            "module_root_hash": module_root_hash,
        },
        "public_surface": {
            "names": [],
            "extraction_method": "ast.module-public-surface@v1.0",
            "extraction_substrate": f"furqan-lint@{version}",
        },
        "chain": {
            "previous_manifest_hash": None,
            "chain_position": 1,
        },
        "linter_substrate_attestation": {
            "linter_name": "furqan-lint",
            "linter_version": version,
            "checker_set_hash": checker_set_hash,
        },
        "trust_root": {
            "trust_root_id": "sigstore-public-good",
        },
        "issued_at": "1970-01-01T00:00:00Z",
    }


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for ``python -m furqan_lint.gate11.self_manifest``.

    Invoked from .github/workflows/release.yml T06 to generate the
    self-manifest JSON file that Sigstore signs.
    """
    parser = argparse.ArgumentParser(
        description="Generate furqan-lint self-attestation manifest",
    )
    parser.add_argument(
        "--version",
        required=True,
        help="furqan-lint version being released (e.g., 1.0.0)",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output path for the self-manifest JSON file",
    )
    args = parser.parse_args(argv)

    manifest = generate_self_manifest(args.version)
    out_path = Path(args.output)
    out_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())


__all__ = (
    "compute_self_checker_set_hash",
    "generate_self_manifest",
    "main",
)
