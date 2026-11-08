"""Phase G11.0.6 (as-Saff / v0.11.8) Rust language facade.

This module is the procedural facade for ``language=rust``
manifests dispatched by ``furqan_lint.gate11.verification.verify``.

It is **purely additive** at v0.11.8: the existing
``Verifier(...).verify_bundle(...)`` class API in
``verification.py`` continues to be the byte-stable substrate
that all production callers (``gate11/cli.py``) and all tests
use directly. The module-level ``verify(manifest, args)`` function
in verification.py composes a Verifier instance internally and
delegates to ``_verify_rust`` (this file) when
``manifest.module_identity['language'] == "rust"``.

The facade signature ``_verify_rust(manifest, args)`` accepts the
parsed Manifest plus the argparse namespace from gate11/cli.py
(carrying bundle_path, module_path, force_refresh,
expected_identity, expected_issuer, allow_any_identity). The
``manifest`` parameter is informational only at this layer --
verification.Verifier.verify_bundle re-parses the bundle from
``args.bundle_path`` to enforce the byte-stable single-source-of-
truth contract; the manifest argument is kept for future
language-specific pre-flight checks.

For Rust manifests, step 7 (module-hash recompute) operates over
``module_path`` pointing at the Rust crate root; step 8 (public
surface compare) uses the Rust surface extractor in
``rust_surface_extraction.py``. These delegations remain inside
``Verifier.verify_bundle`` -- the facade itself does no
language-specific logic; it merely composes the trust config and
delegates.

D24 discipline: this module's helpers use single-trailing-return
shape (raise on miss, return on hit) so the path-coverage analysis
sees terminal coverage across all branches.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from furqan_lint.gate11.verification import (
    TrustConfig,
    VerificationResult,
    Verifier,
)

if TYPE_CHECKING:
    import argparse

    from furqan_lint.gate11.manifest_schema import Manifest


def _verify_rust(
    manifest: Manifest,
    args: argparse.Namespace,
) -> VerificationResult:
    """Procedural facade for ``language=rust`` manifest verification.

    Composes a ``Verifier`` instance with the trust config implied
    by ``args`` and delegates to ``verify_bundle``. Existing
    callers using ``Verifier(...).verify_bundle(...)`` directly
    are unaffected.

    The ``manifest`` parameter is informational at this layer:
    ``Verifier.verify_bundle`` re-parses the bundle from
    ``args.bundle_path`` to enforce the byte-stable single-source-
    of-truth contract. The argument is retained for
    language-specific pre-flight checks added in future phases.

    Raises ``CasmVerificationError`` with the underlying CASM-V-NNN
    code if any of the nine verification steps fail. Returns the
    populated ``VerificationResult`` on success.
    """
    # Per F-RN-1 v1.5 absorption + al-Mursalat T02 Edit 2:
    # honor caller-passed trust_config via args Namespace
    # attribute if attached by the CLI; fall back to
    # default TrustConfig() when absent (preserves v0.11.8
    # programmatic-RP backward compatibility for callers
    # that don't set args.trust_config).
    trust_config = getattr(args, "trust_config", None) or TrustConfig()
    verifier = Verifier(trust_config=trust_config)
    return verifier.verify_bundle(
        bundle_path=args.bundle_path,
        module_path=args.module_path,
        force_refresh=getattr(args, "force_refresh", False),
        expected_identity=getattr(args, "expected_identity", None),
        expected_issuer=getattr(args, "expected_issuer", None),
        allow_any_identity=getattr(args, "allow_any_identity", False),
    )


__all__ = ("_verify_rust",)
