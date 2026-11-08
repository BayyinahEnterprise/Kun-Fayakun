"""Phase G11.1 (as-Saffat): Rust manifest builder.

Constructs CASM v1.0 manifests for Rust source files. Reuses
the universal substrate (manifest schema, module
canonicalization, signature canonicalization) from Phase
G11.0; the Rust-specific pieces are surface extraction
(:mod:`rust_surface_extraction`) and signature canonicalization
(:mod:`rust_signature_canonicalization`).

The manifest's ``module_identity.language`` is ``"rust"``;
``public_surface.extraction_method`` is
``"tree-sitter.rust-public-surface@v1.0"``.

The ``linter_substrate_attestation.checker_set_hash`` field
uses Form A (substantive hash over pinned checker source) per
the audit H-6 propagation defense. Form B
(``placeholder:sha256:...``) is also accepted by the schema
validator for v0.11.x patch releases.
"""

from __future__ import annotations

import datetime
import hashlib
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from furqan_lint.gate11.manifest_schema import Manifest


# Same default trust-config as Phase G11.0; private-Rekor
# routing is a Phase G11.1 carry-forward to v1.5.
_DEFAULT_TRUST_ROOT = {
    "trust_root_id": "public-sigstore",
    "fulcio_url": "https://fulcio.sigstore.dev",
    "rekor_url": "https://rekor.sigstore.dev",
}


def build_manifest_rust(
    path: Path | str,
    previous_manifest: Manifest | None = None,
    *,
    trust_root: dict[str, str] | None = None,
    use_placeholder_checker_hash: bool = False,
) -> Manifest:
    """Build a CASM v1.0 manifest for a Rust source file.

    Args:
        path: path to the .rs source file. The path stored in
            the manifest is the path as given (caller is
            responsible for repo-relative normalization).
        previous_manifest: optional previous manifest in the
            chain. If supplied, the new manifest's
            ``chain.previous_manifest_hash`` is the SHA-256 of
            the previous manifest's RFC 8785 canonical bytes
            and ``chain_position`` increments by one.
        trust_root: optional trust-root override (dict with
            ``trust_root_id`` plus URLs). Defaults to public
            Sigstore.
        use_placeholder_checker_hash: if True, use Form B
            (``placeholder:sha256:<hex>`` prefix) for the
            ``checker_set_hash``. Defaults to False (Form A,
            substantive hash over pinned checker source).
    """
    from furqan_lint import __version__ as linter_version
    from furqan_lint.gate11.checker_set_hash import (
        compute_checker_set_hash,
        compute_checker_set_hash_placeholder,
    )
    from furqan_lint.gate11.manifest_schema import Manifest
    from furqan_lint.gate11.module_canonicalization import (
        module_root_hash,
    )
    from furqan_lint.gate11.rust_surface_extraction import (
        extract_public_surface_rust,
    )

    source_path = Path(path)
    public_names = extract_public_surface_rust(source_path)
    root_hash = module_root_hash(source_path)

    if use_placeholder_checker_hash:
        checker_hash = compute_checker_set_hash_placeholder(linter_version)
    else:
        checker_hash = compute_checker_set_hash()

    if previous_manifest is None:
        previous_manifest_hash: str | None = None
        chain_position = 1
    else:
        prev_canonical = previous_manifest.to_canonical_bytes()
        previous_manifest_hash = "sha256:" + hashlib.sha256(prev_canonical).hexdigest()
        chain_position = int(previous_manifest.chain.get("chain_position", 0)) + 1

    issued_at = (
        datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )

    data = {
        "casm_version": "1.0",
        "module_identity": {
            "language": "rust",
            "module_path": str(source_path),
            "module_root_hash": root_hash,
        },
        "public_surface": {
            "names": public_names,
            "extraction_method": "tree-sitter.rust-public-surface@v1.0",
            "extraction_substrate": (f"furqan-lint v{linter_version}"),
        },
        "chain": {
            "previous_manifest_hash": previous_manifest_hash,
            "chain_position": chain_position,
        },
        "linter_substrate_attestation": {
            "linter_name": "furqan-lint",
            "linter_version": linter_version,
            "checker_set_hash": checker_hash,
        },
        "trust_root": trust_root or dict(_DEFAULT_TRUST_ROOT),
        "issued_at": issued_at,
    }
    return Manifest.from_dict(data)
