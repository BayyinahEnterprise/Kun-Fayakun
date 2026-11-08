"""Phase G11.3 (an-Naziat / v0.13.0) ONNX language facade.

This module is the procedural facade for ``language=onnx``
manifests dispatched by
``furqan_lint.gate11.verification.verify``.

Mirror of as-Saff (v0.11.8) ``python_verification.py`` and
``rust_verification.py`` private handlers + al-Mursalat
(v0.12.0) ``go_verification.py``, adapted for ONNX substrate.
The substrate convention is preserved verbatim: private
``_verify_onnx(manifest, args)`` function only;
``__all__ = ("_verify_onnx",)``; no public ``verify`` alias.

It is **purely additive** at v0.13.0: the existing
``Verifier(...).verify_bundle(...)`` class API in
``verification.py`` continues to be the byte-stable substrate
that all production callers (``gate11/cli.py``) and all tests
use directly. The module-level ``verify(manifest, args)``
function in verification.py composes a Verifier instance
internally and delegates to ``_verify_onnx`` (this file) when
``manifest.module_identity['language'] == "onnx"`` (T09 wires
this entry into the function-local ``_LANGUAGE_DISPATCH``).

The facade signature ``_verify_onnx(manifest, args)`` accepts
the parsed Manifest plus the argparse namespace from
gate11/cli.py (carrying bundle_path, module_path,
trust_config, force_refresh, expected_identity,
expected_issuer, allow_any_identity). The ``manifest``
parameter is informational only at this layer --
``verification.Verifier.verify_bundle`` re-parses the bundle
from ``args.bundle_path`` to enforce the byte-stable
single-source-of-truth contract; the manifest argument is
kept for future ONNX-specific pre-flight checks
(opset-policy-mismatch CASM-V-070, dim-param-violation
CASM-V-071) that operate on the manifest's
``module_identity.onnx`` ``OnnxIdentitySection`` against the
substrate ModelProto at ``args.module_path``.

ONNX-specific consistency-check semantics (per T01-allocated
codes):

* ``CASM-V-070``: opset-policy-mismatch. Manifest's
  ``OnnxIdentitySection.opset_imports`` differs from
  substrate ModelProto's ``opset_imports``. Enforced
  mechanically through the canonicalized graph-shape surface
  from :mod:`furqan_lint.gate11.onnx_signature_canonicalization`
  rules 9-12 (divergent canonical strings when opset_imports
  drift); the canonicalization-string mismatch surfaces at
  the existing signature-verification step 6 of the 9-step
  verification flow.

* ``CASM-V-071``: dim-param-violation. Manifest's
  ``OnnxIdentitySection`` declares a dim_param (symbolic
  dimension) for an input but the substrate ModelProto's
  same input has a concrete dim_value (or vice versa).
  Enforced through rule 10 of the canonicalization (symbolic
  vs concrete dims preserved faithfully; drift produces
  divergent canonical strings).

Per F-RN-1 v1.5 absorption + F-PB-NZ-2 v1.6 absorption: this
body honors caller-passed ``args.trust_config`` via
``getattr(args, "trust_config", None) or TrustConfig()``. The
``verify_bundle`` call uses the substrate-canonical six-kwarg
pattern (bundle_path=, module_path=, force_refresh=,
expected_identity=, expected_issuer=, allow_any_identity=)
matching as-Saff (v0.11.8) ``_verify_python`` and al-Mursalat
(v0.12.0) ``_verify_go``. The v1.5-era single-arg
``verifier.verify_bundle(manifest)`` skeleton was
substrate-untrue at v0.12.0; v0.10.0's bundle verification
API moved through the as-Saff + al-Mursalat sigstore-rebase
evolution and is now six-kwarg-shaped.

API pattern mirrored from the v0.12.0-LIVE Python / Rust / Go
private handlers per an-Naziat T00 step 6 pre-flight
verification record (NOT v1.5 single-arg skeleton; NOT
at-Tawbah-era reference). The Verifier class internally uses
the ``SgVerifier(_inner=trusted_root)`` construction with
``TrustedRoot.production()/staging()`` fallback per H-5
propagation defense; ``UnsafeNoOp()`` policy under explicit
``--allow-any-identity`` opt-in per C-1 refuse-without-policy
default (CASM-V-035).

D24 discipline: this module's helpers use single-trailing-return
shape (raise on miss, return on hit) so the path-coverage
analysis sees terminal coverage across all branches.
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


def _verify_onnx(
    manifest: Manifest,
    args: argparse.Namespace,
) -> VerificationResult:
    """Procedural facade for ``language=onnx`` manifest verification.

    Composes a ``Verifier`` instance with the trust config implied
    by ``args`` and delegates to ``verify_bundle``. Existing
    callers using ``Verifier(...).verify_bundle(...)`` directly
    are unaffected (the Verifier class is byte-stable from
    v0.11.7 onward).

    The ``manifest`` parameter is informational at this layer:
    ``Verifier.verify_bundle`` re-parses the bundle from
    ``args.bundle_path`` to enforce the byte-stable
    single-source-of-truth contract. The argument is retained
    for ONNX-specific pre-flight checks added in future
    phases (e.g., explicit opset-policy / dim_param consistency
    surfacing before signature verification, if the divergent-
    canonical-string mechanism proves diagnostic-insufficient
    at Round 40+ post-ship audit).

    Per F-RN-1 v1.5 absorption + F-PB-NZ-2 v1.6 absorption:
    honors caller-passed ``args.trust_config`` if attached to
    the args Namespace by the CLI; falls back to default
    ``TrustConfig()`` when absent (preserves v0.11.8
    programmatic-RP backward compat).

    For ONNX-language manifests,
    ``Verifier.verify_bundle``'s 9-step flow operates as for
    Python / Rust / Go with ONNX-specific differences at
    step 8 (per SAFETY_INVARIANTS.md Invariant 6 step 8
    extension):

    1. Parse bundle (CASM-V-010 on JSON / schema failure)
    2. Check casm_version == "1.0" (CASM-V-001)
    3. Check language == "onnx" matches this verifier
       (CASM-V-001; generalized at T02 per an-Naziat to
       include onnx in the supported set; closed-form mushaf
       chain after this phase)
    4. Load Sigstore trust root via TUF (CASM-V-020 ADVISORY
       / CASM-V-021)
    5. Re-canonicalize the manifest (RFC 8785; Invariant 3)
       -- for ONNX manifests this consumes the
       ``module_identity.onnx`` ``OnnxIdentitySection`` via
       :func:`furqan_lint.gate11.onnx_signature_canonicalization.canonicalize`
       (rules 9-12)
    6. Verify Sigstore signature; enforce identity policy
       (CASM-V-030..036; CASM-V-032 on mismatch; CASM-V-035
       refuse-without-policy default; CASM-V-036 on identity
       extraction TypeError)
    7. Compare module_root_hash to the on-disk ONNX
       ModelProto bytes (CASM-V-040 on mismatch)
    8. Compare public_surface against the live extraction
       (ONNX-side via ``onnx.graph-io-surface@v1.0``
       extraction-method identifier per Invariant 5;
       canonicalization rules 9-12 produce divergent
       canonical strings when opset_imports drift
       (CASM-V-070) or dim_param drift (CASM-V-071) between
       manifest and substrate ModelProto)
    9. Check chain_pointer integrity (CASM-V-060 / CASM-V-061)

    Raises ``CasmVerificationError`` with the underlying
    CASM-V-NNN code if any of the nine verification steps fail.
    Returns the populated ``VerificationResult`` on success.
    """
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


__all__ = ("_verify_onnx",)
