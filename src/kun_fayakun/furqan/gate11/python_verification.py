"""Phase G11.0.6 (as-Saff / v0.11.8) Python language facade.

This module is the procedural facade for ``language=python``
manifests dispatched by ``furqan_lint.gate11.verification.verify``.

It is **purely additive** at v0.11.8: the existing
``Verifier(...).verify_bundle(...)`` class API in
``verification.py`` continues to be the byte-stable substrate
that all production callers (``gate11/cli.py``) and all tests
use directly. The module-level ``verify(manifest, args)`` function
in verification.py composes a Verifier instance internally and
delegates to ``_verify_python`` (this file) when
``manifest.module_identity['language'] == "python"``.

The Route B refactor unblocks Phase G11.2 (al-Mursalat / Go) and
Phase G11.3 (an-Naziat / ONNX), both of which T00-halted because
their prompts assumed Route A (per-language modules already
extracted) but substrate-truth at v0.11.7 was a monolithic
Verifier class with no module-level dispatch surface.

The facade signature ``_verify_python(manifest, args)`` accepts
the parsed Manifest plus the argparse namespace from gate11/cli.py
(carrying bundle_path, module_path, force_refresh,
expected_identity, expected_issuer, allow_any_identity). The
``manifest`` parameter is informational only at this layer --
verification.Verifier.verify_bundle re-parses the bundle from
``args.bundle_path`` to enforce the byte-stable single-source-of-
truth contract; the manifest argument is kept for future
language-specific pre-flight checks (e.g., Go module-graph
validation in Phase G11.2).

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


def _verify_python(
    manifest: Manifest,
    args: argparse.Namespace,
) -> VerificationResult:
    """Procedural facade for ``language=python`` manifest verification.

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


__all__ = ("_verify_python",)
