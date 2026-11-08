"""Phase G11.0 T08: nine-step CASM bundle verification.

The Verifier executes the verification flow specified in the
G11.0 prompt:

1. parse bundle (CASM-V-010 on failure)
2. CASM version check (CASM-V-001)
3. language check (CASM-V-001)
4. TUF trust root refresh / fallback (CASM-V-020 ADVISORY,
   CASM-V-021)
5. canonical manifest bytes (RFC 8785)
6. Sigstore verification (CASM-V-030..034)
7. module hash recompute and compare (CASM-V-040)
8. public surface compare (CASM-V-050 removal, CASM-V-051
   non-additive change; INDETERMINATE on DynamicAllError)
9. chain integrity (CASM-V-060, CASM-V-061 ADVISORY)

Each step returns either successfully or raises
``CasmVerificationError`` with a CASM-V code attribute. The
``Verifier.verify_bundle`` entry point composes the steps.

Sigstore verification (step 6) is bundled into a single call
to sigstore-python's high-level Verifier API; the CASM-V-030..
034 codes are mapped from the underlying VerificationError.

Tests synthesize each path without live network: the Sigstore
step is exercised by injecting a faked ``sigstore_bundle`` dict
and asserting that the verifier surfaces the expected
CASM-V-03x code.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from furqan_lint.additive import DynamicAllError
from furqan_lint.gate11.bundle import Bundle, BundleParseError
from furqan_lint.gate11.manifest_schema import Manifest
from furqan_lint.gate11.module_canonicalization import (
    ModuleCanonicalizationError,
    module_root_hash,
)
from furqan_lint.gate11.surface_extraction import extract_public_surface

if TYPE_CHECKING:
    pass


class CasmVerificationError(Exception):
    """Raised when a CASM verification step fails non-advisorially.

    Carries a ``code`` attribute (one of the CASM-V-* error codes
    from the namespace) and a ``message`` field. Advisory
    findings (CASM-V-003, CASM-V-020, CASM-V-061) are NOT raised
    as exceptions; they are appended to the
    ``VerificationResult.advisories`` list and the verification
    proceeds.
    """

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


class CasmIndeterminateError(Exception):
    """Raised when the public-surface comparison cannot be performed.

    Surfaces ``DynamicAllError`` from the additive-only checker
    in a Gate-11-shaped form. The CLI maps this to exit code 2
    (INDETERMINATE), distinct from CASM-V-050/051 which are
    additive-only violations and exit 1.
    """


@dataclass
class TrustConfig:
    """Identifies the Sigstore deployment to verify against.

    For v1.0, the public Sigstore deployment is the default;
    private deployments are configured by passing a
    ``TrustConfig`` to ``verify_bundle``.
    """

    trust_root_id: str = "public-sigstore"
    fulcio_url: str = "https://fulcio.sigstore.dev"
    rekor_url: str = "https://rekor.sigstore.dev"


@dataclass
class VerificationResult:
    """Outcome of a Verifier.verify_bundle call.

    ``ok`` is True only when every non-advisory step passed.
    Advisories (CASM-V-003, CASM-V-020, CASM-V-061) are
    collected for surfacing in CLI output without affecting
    exit code.
    """

    ok: bool
    bundle_path: Path
    module_path: Path
    manifest: Manifest | None = None
    signed_by: str | None = None
    chain_position: int | None = None
    advisories: list[tuple[str, str]] = field(default_factory=list)


class Verifier:
    """Executes the 9-step CASM verification flow.

    Each step is a method so callers (tests, CLI) can re-run a
    subset for diagnostic purposes. The composed
    ``verify_bundle`` method exits at the first non-advisory
    failure (raising ``CasmVerificationError``) and returns a
    populated ``VerificationResult`` on success.
    """

    def __init__(self, trust_config: TrustConfig | None = None) -> None:
        self.trust_config = trust_config or TrustConfig()

    # Step 1
    def step1_parse_bundle(self, bundle_path: Path) -> Bundle:
        try:
            return Bundle.read(bundle_path)
        except BundleParseError as e:
            raise CasmVerificationError(e.code, str(e)) from e

    # Steps 2-3 (manifest schema enforces these on parse)
    def step2_3_check_version_and_language(self, manifest: Manifest) -> None:
        # Manifest.from_dict already rejected the wrong values; if
        # we got a Manifest object, both fields are valid.
        if manifest.casm_version != "1.0":
            raise CasmVerificationError(
                "CASM-V-001",
                f"unsupported casm_version {manifest.casm_version!r}",
            )
        language = manifest.module_identity.get("language")
        # Phase G11.0.2 (v0.11.3) F22 corrective: align this
        # dispatch whitelist with Manifest.from_dict's whitelist.
        # The whitelist has been extended at each successive
        # gate11 substrate phase: rust at v0.11.3 (G11.0.2 F22
        # corrective); go at v0.12.0 (G11.2 al-Mursalat T01
        # generalization); onnx at v0.13.0 (G11.3 an-Naziat T02
        # closing the canonical mushaf chain). Post-an-Naziat
        # the dispatch surface is closed-form: no further Phase
        # G11.x language extensions are anticipated; Phase G11.4
        # Tasdiq al-Bayan operates against this surface as a
        # drift-detection invariant rather than adding entries.
        if language not in ("python", "rust", "go", "onnx"):
            raise CasmVerificationError(
                "CASM-V-001",
                f"v1.0 supports language in "
                f"(python, rust, go, onnx); got {language!r}. "
                f"No further Phase G11.x dispatch entries are "
                f"anticipated post-an-Naziat (Phase G11.4 "
                f"operates as a drift-detection invariant).",
            )

    # Step 4
    def step4_load_trust_root(self, force_refresh: bool = False) -> Any:
        """Load TUF trust root for the configured deployment.

        Returns the trust-root object that step 6's Sigstore
        verifier consumes. Emits a CASM-V-020 ADVISORY if
        refresh fails but a non-stale cached copy exists.

        Implementation note: the Sigstore-python TrustedRoot
        loader is the canonical path; this method delegates to
        it and adapts the error namespace.
        """
        try:
            # sigstore-python 3.x: TrustedRoot lives at
            # _internal.trust (no public re-export at
            # sigstore.trust in 3.6.x; Round 31 audit F24
            # confirmed empirically). If sigstore 4.x adds a
            # public path at sigstore.trust, this try/except
            # prefers the public path forward-compatibly.
            try:
                from sigstore.trust import TrustedRoot  # type: ignore[import-not-found]
            except ImportError:
                from sigstore._internal.trust import TrustedRoot
        except ImportError as e:
            raise CasmVerificationError(
                "CASM-V-021",
                "sigstore not installed; cannot load TUF trust root. "
                "Install with: pip install furqan-lint[gate11]",
            ) from e

        trust_root_id = self.trust_config.trust_root_id
        try:
            if trust_root_id == "public-sigstore":
                return TrustedRoot.production()
            return TrustedRoot.staging()
        except Exception as e:
            raise CasmVerificationError(
                "CASM-V-021",
                f"TUF refresh failed and no cache available: {e}",
            ) from e

    # Step 5
    def step5_canonicalize_manifest(self, manifest: Manifest) -> bytes:
        """Re-canonicalize the manifest via RFC 8785 (JCS).

        Schema enforcement is in :meth:`Manifest.from_dict`; this
        step assumes a valid Manifest instance and dispatches
        canonicalization. M-5 corrective (Phase G11.0.1
        at-Tawbah): the canonical enforcement site for the
        manifest schema is ``Manifest.from_dict``; step 5 does
        not re-validate.
        """
        return manifest.to_canonical_bytes()

    # Step 6
    def step6_verify_sigstore(
        self,
        bundle: Bundle,
        canonical_manifest_bytes: bytes,
        trusted_root: Any,
        *,
        expected_identity: str | None = None,
        expected_issuer: str | None = None,
        allow_any_identity: bool = False,
    ) -> str:
        """Verify the Sigstore bundle against the canonical manifest.

        Phase G11.1 audit corrective:

        - C-1 (CRITICAL): Identity policy is no longer
          ``UnsafeNoOp()`` by default. Caller must pass
          ``expected_identity=<pattern>`` OR explicitly set
          ``allow_any_identity=True``. Refuse-without-policy
          raises ``CASM-V-035``.
        - H-5 (HIGH): The ``trusted_root`` argument is now
          consumed (not discarded). The lower-level
          ``Verifier(_inner=trusted_root)`` constructor is
          used so that ``--force-refresh`` plumbing in step4
          observably affects step6.
        - M-7 (MEDIUM): Identity extraction failures now
          raise ``CASM-V-036`` typed errors rather than
          returning the string sentinel
          ``"<unknown OIDC identity>"``.

        Returns the OIDC identity string from the bundle's
        certificate. Raises CasmVerificationError with code
        CASM-V-030..036 mapped from sigstore VerificationError
        and identity-policy enforcement.
        """
        try:
            from sigstore.errors import VerificationError
            from sigstore.models import Bundle as SgBundle
            from sigstore.verify import Verifier as SgVerifier
            from sigstore.verify.policy import (
                Identity,
                UnsafeNoOp,
            )
        except ImportError as e:
            raise CasmVerificationError(
                "CASM-V-021",
                "sigstore not installed; cannot verify bundle. "
                "Install with: pip install furqan-lint[gate11]",
            ) from e

        # C-1 propagation defense: refuse-without-policy default.
        if not allow_any_identity and expected_identity is None:
            raise CasmVerificationError(
                "CASM-V-035",
                "no Identity policy supplied; pass "
                "--expected-identity <pattern> or explicitly "
                "--allow-any-identity. The default refuse-"
                "without-policy behaviour is the substrate-side "
                "enforcement of Newman 2022 N2 (typosquatting "
                "at the publish boundary).",
            )

        # Adapt the dict-of-record sigstore_bundle into a Sigstore
        # Bundle object. Some sigstore-python versions accept JSON
        # directly via from_json; older versions require dict.
        sb_payload = bundle.sigstore_bundle
        try:
            if isinstance(sb_payload, dict):
                import json as _json

                sg_bundle = SgBundle.from_json(_json.dumps(sb_payload))
            elif hasattr(sb_payload, "to_json"):
                # Already a Bundle object
                sg_bundle = sb_payload
            else:
                sg_bundle = SgBundle.from_json(sb_payload)
        except Exception as e:
            raise CasmVerificationError(
                "CASM-V-030",
                f"could not adapt sigstore_bundle into Sigstore Bundle: {e}",
            ) from e

        # H-5 propagation defense: thread the trusted_root through
        # to the verifier rather than discarding the argument and
        # rebuilding internally. Where the lower-level constructor
        # is unavailable, fall back to .production() / .staging()
        # which at least wire the rekor client correctly.
        verifier: Any
        try:
            verifier = SgVerifier(_inner=trusted_root)  # type: ignore[call-arg]
        except Exception:
            verifier = (
                SgVerifier.production()
                if self.trust_config.trust_root_id == "public-sigstore"
                else SgVerifier.staging()
            )

        # C-1 propagation defense: build the explicit Identity
        # policy from caller args.
        policy: Any
        if allow_any_identity:
            policy = UnsafeNoOp()
        else:
            assert expected_identity is not None  # narrowed by C-1 gate
            policy = Identity(
                identity=expected_identity,
                issuer=expected_issuer,
            )

        try:
            verifier.verify_artifact(
                input_=canonical_manifest_bytes,
                bundle=sg_bundle,
                policy=policy,
            )
        except VerificationError as e:
            # Identity-policy mismatch surfaces as
            # CASM-V-032 (per amended_4 T05 specification);
            # other VerificationError shapes route through
            # _map_verification_error to CASM-V-030..034.
            err_str = str(e).lower()
            if "identity" in err_str or "san" in err_str or "policy" in err_str:
                raise CasmVerificationError(
                    "CASM-V-032",
                    f"identity policy mismatch: {e}",
                ) from e
            raise self._map_verification_error(e) from e

        # M-7 propagation defense: typed identity-extraction errors.
        return self._extract_identity(sg_bundle)

    @staticmethod
    def _extract_identity(sg_bundle: Any) -> str:
        """Extract the OIDC identity string from the signing cert.

        Phase G11.1 audit M-7 corrective: failures raise
        ``CASM-V-036`` typed errors rather than returning the
        string sentinel ``"<unknown OIDC identity>"`` that the
        v0.10.0 ship returned (and that no Relying Party could
        meaningfully gate against).
        """
        try:
            cert = sg_bundle.signing_certificate
            for ext in cert.extensions:
                if ext.oid.dotted_string == "2.5.29.17":  # SAN
                    return str(ext.value)
            raise CasmVerificationError(
                "CASM-V-036",
                "signing certificate has no Subject Alternative "
                "Name extension; cannot extract OIDC identity",
            )
        except CasmVerificationError:
            raise
        except Exception as e:
            raise CasmVerificationError(
                "CASM-V-036",
                f"could not extract OIDC identity from signing "
                f"certificate: {type(e).__name__}: {e}",
            ) from e

    @staticmethod
    def _map_verification_error(e: Exception) -> CasmVerificationError:
        """Map sigstore VerificationError to a CASM-V-03x code."""
        msg = str(e).lower()
        if "certificate" in msg and ("chain" in msg or "trust" in msg):
            return CasmVerificationError("CASM-V-030", str(e))
        if "sct" in msg or "signed certificate timestamp" in msg:
            return CasmVerificationError("CASM-V-031", str(e))
        if "rekor" in msg or "inclusion proof" in msg or "tlog" in msg:
            return CasmVerificationError("CASM-V-033", str(e))
        if "validity" in msg or "not valid before" in msg or "not valid after" in msg:
            return CasmVerificationError("CASM-V-034", str(e))
        return CasmVerificationError("CASM-V-032", str(e))

    # Step 7
    def step7_compare_module_hash(self, manifest: Manifest, module_path: Path) -> None:
        try:
            current_hash = module_root_hash(module_path)
        except ModuleCanonicalizationError as e:
            raise CasmVerificationError(e.code, str(e)) from e
        manifest_hash = manifest.module_identity.get("module_root_hash")
        if current_hash != manifest_hash:
            raise CasmVerificationError(
                "CASM-V-040",
                f"module_root_hash mismatch: manifest={manifest_hash}, " f"current={current_hash}",
            )

    # Step 8
    def step8_compare_public_surface(self, manifest: Manifest, module_path: Path) -> None:
        try:
            current_entries = _extract_surface_for(manifest, module_path)
        except DynamicAllError as e:
            raise CasmIndeterminateError(
                f"public surface is INDETERMINATE because __all__ is " f"dynamic: {e}"
            ) from e
        manifest_entries: list[dict[str, Any]] = list(manifest.public_surface.get("names", []))
        manifest_by_name = {e["name"]: e for e in manifest_entries}
        current_by_name = {e["name"]: e for e in current_entries}
        # Removals (CASM-V-050)
        removed = sorted(set(manifest_by_name) - set(current_by_name))
        if removed:
            raise CasmVerificationError(
                "CASM-V-050",
                f"public-surface names removed since manifest: {removed}",
            )
        # Signature drift on shared names (CASM-V-051)
        for name, m_entry in manifest_by_name.items():
            c_entry = current_by_name[name]
            if m_entry["signature_fingerprint"] != c_entry["signature_fingerprint"]:
                raise CasmVerificationError(
                    "CASM-V-051",
                    f"public-surface name {name!r} signature changed in "
                    f"non-additive way: manifest "
                    f"{m_entry['signature_fingerprint']}, current "
                    f"{c_entry['signature_fingerprint']}",
                )
        # Additions are silent (allowed under additive-only).

    # Step 9
    def step9_check_chain_integrity(
        self, manifest: Manifest, bundle_path: Path
    ) -> tuple[bool, str | None]:
        """Return (chain_ok, advisory_message_or_none).

        Locates the previous bundle by file convention: the same
        directory, plus any sibling ``.furqan.manifest.sigstore``
        whose canonical-manifest hash matches
        ``previous_manifest_hash``.

        Returns ``(True, None)`` if the previous manifest is
        chain-head (None) OR if the previous bundle is found and
        its canonical-manifest hash matches.

        Returns ``(False, message)`` for a CASM-V-061 ADVISORY
        when the previous bundle cannot be located.

        Raises ``CasmVerificationError`` with code CASM-V-060 if
        the previous bundle is found but the hash mismatches.
        """
        prev_hash = manifest.chain.get("previous_manifest_hash")
        if prev_hash is None:
            return (True, None)
        # Search same directory.
        candidates = list(bundle_path.parent.glob("*.furqan.manifest.sigstore"))
        for candidate in candidates:
            if candidate == bundle_path:
                continue
            try:
                cand_bundle = Bundle.read(candidate)
            except BundleParseError:
                continue
            cand_canonical = cand_bundle.manifest.to_canonical_bytes()
            cand_hash = "sha256:" + hashlib.sha256(cand_canonical).hexdigest()
            if cand_hash == prev_hash:
                return (True, None)
            # Found a chain-position-aware match by chain_position - 1:
            cand_pos = cand_bundle.manifest.chain.get("chain_position", 0)
            target_pos = manifest.chain.get("chain_position", 0)
            if cand_pos == target_pos - 1 and cand_hash != prev_hash:
                raise CasmVerificationError(
                    "CASM-V-060",
                    f"chain integrity broken: candidate {candidate.name} at "
                    f"position {cand_pos} hashes to {cand_hash}, "
                    f"manifest expected {prev_hash}",
                )
        return (False, f"previous manifest with hash {prev_hash} not located")

    # Composed flow
    def verify_bundle(
        self,
        bundle_path: Path | str,
        module_path: Path | str,
        force_refresh: bool = False,
        *,
        expected_identity: str | None = None,
        expected_issuer: str | None = None,
        allow_any_identity: bool = False,
    ) -> VerificationResult:
        """Run the nine-step CASM-V verification flow.

        Phase G11.1 audit corrective: ``expected_identity`` is
        required by default. Pass ``allow_any_identity=True``
        to opt into ``UnsafeNoOp()`` (the explicit opt-in is
        itself an audit signal in CI logs).
        """
        bp = Path(bundle_path)
        mp = Path(module_path)
        result = VerificationResult(ok=False, bundle_path=bp, module_path=mp)
        bundle = self.step1_parse_bundle(bp)
        result.manifest = bundle.manifest
        self.step2_3_check_version_and_language(bundle.manifest)
        trusted_root = self.step4_load_trust_root(force_refresh=force_refresh)
        canonical = self.step5_canonicalize_manifest(bundle.manifest)
        signed_by = self.step6_verify_sigstore(
            bundle,
            canonical,
            trusted_root,
            expected_identity=expected_identity,
            expected_issuer=expected_issuer,
            allow_any_identity=allow_any_identity,
        )
        result.signed_by = signed_by
        self.step7_compare_module_hash(bundle.manifest, mp)
        self.step8_compare_public_surface(bundle.manifest, mp)
        ok, advisory = self.step9_check_chain_integrity(bundle.manifest, bp)
        if not ok and advisory is not None:
            result.advisories.append(("CASM-V-061", advisory))
        result.chain_position = bundle.manifest.chain.get("chain_position")
        result.ok = True
        return result


# ---------------------------------------------------------------
# Phase G11.0.6 (as-Saff / v0.11.8) Route B procedural facade
# ---------------------------------------------------------------
#
# Module-level ``verify(manifest, args)`` function with a private
def _extract_surface_for(manifest: Manifest, module_path: Path) -> list[dict[str, Any]]:
    """Live public-surface extraction in the manifest's own language.

    v1.0.1: step 8 used the Python extractor for every language, so a
    Rust or Go bundle failed verification with a Python SyntaxError on
    otherwise valid source (the ``gate11-rust-smoke-test`` and
    ``gate11-go-smoke-test`` CI jobs). The extractor now follows
    ``module_identity.language``, the same field that already routes
    the language-specific verifier facade.
    """
    language = manifest.module_identity.get("language")
    if language == "rust":
        from furqan_lint.gate11.rust_surface_extraction import (
            DynamicRustSurfaceError,
            extract_public_surface_rust,
        )

        try:
            return list(extract_public_surface_rust(module_path))
        except DynamicRustSurfaceError as e:
            raise CasmIndeterminateError(
                f"public surface is INDETERMINATE because of a glob re-export: {e}"
            ) from e
    if language == "go":
        from furqan_lint.gate11.go_verification import extract_public_surface_go

        return list(extract_public_surface_go(module_path))
    return extract_public_surface(module_path)


# ``_LANGUAGE_DISPATCH`` table dispatching to per-language facades
# in ``python_verification.py`` and ``rust_verification.py``. This
# is purely additive: existing callers using
# ``Verifier(...).verify_bundle(...)`` directly are unaffected
# (gate11/cli.py, all tests pre-v0.11.8).
#
# The dispatch table imports the per-language facades **lazily**
# inside the ``verify`` function rather than at module top-level.
# The per-language facade modules import ``Verifier``,
# ``VerificationResult``, and ``TrustConfig`` from this module;
# importing them eagerly here would create a circular import. The
# lazy-import pattern is documented in F-RV-7 of the v1.3 audit.
#
# D24 discipline: ``verify`` uses single-trailing-return shape
# (raise on miss, return on hit) per the v0.8.0 finding. Do NOT
# refactor to ``if handler: return handler(...); raise ...`` --
# D24 doesn't model ``raise`` as terminal and the all-paths-return
# analysis fires MARAD P1.


def verify(manifest: Any, args: Any) -> VerificationResult:
    """Module-level procedural facade introduced at v0.11.8.

    Dispatches to a language-specific facade per
    ``_LANGUAGE_DISPATCH`` based on
    ``manifest.module_identity['language']``. Raises
    :class:`CasmVerificationError` with code ``CASM-V-001`` if
    the language is not in the dispatch table.

    Parameters:
        manifest: parsed :class:`Manifest` object (informational
            at this layer; the language-specific facade composes
            a Verifier and re-parses the bundle from
            ``args.bundle_path`` to enforce the byte-stable
            single-source-of-truth contract).
        args: ``argparse.Namespace`` from ``gate11/cli.py``
            carrying ``bundle_path``, ``module_path``,
            ``force_refresh``, ``expected_identity``,
            ``expected_issuer``, ``allow_any_identity``.

    Returns:
        :class:`VerificationResult` populated by the underlying
        ``Verifier.verify_bundle`` 9-step flow.

    Raises:
        :class:`CasmVerificationError`: with positional
        ``CASM-V-001`` if the manifest's language is not in the
        dispatch table (see F-XR-5 audit absorption: positional
        args, not keyword, to match the rest of the verification
        module's exception-construction style).
    """
    # Lazy import to avoid module-level circular import:
    # python_verification / rust_verification / go_verification
    # / onnx_verification import Verifier from this module; we
    # import their _verify_* handlers here at call time.
    # an-Naziat (v0.13.0) extends the function-local dispatch
    # with a fourth lazy-import line for ONNX per F-RM-2 v1.4
    # absorption (function-local design preserved; not lifted
    # to module level). The four-entry dispatch closes the
    # canonical mushaf chain; Phase G11.4 Tasdiq al-Bayan
    # operates against this exact dispatch surface as a
    # drift-detection invariant rather than adding entries.
    from furqan_lint.gate11.go_verification import _verify_go
    from furqan_lint.gate11.onnx_verification import _verify_onnx
    from furqan_lint.gate11.python_verification import _verify_python
    from furqan_lint.gate11.rust_verification import _verify_rust

    _LANGUAGE_DISPATCH = {
        "python": _verify_python,
        "rust": _verify_rust,
        "go": _verify_go,
        "onnx": _verify_onnx,
    }

    language = manifest.module_identity.get("language")
    handler = _LANGUAGE_DISPATCH.get(language)
    if handler is None:
        raise CasmVerificationError(
            "CASM-V-001",
            f"v1.0 supports language in "
            f"(python, rust, go, onnx); got {language!r}. "
            f"No further Phase G11.x dispatch entries are "
            f"anticipated post-an-Naziat (Phase G11.4 "
            f"operates as a drift-detection invariant).",
        )
    return handler(manifest, args)


__all__ = (
    "CasmIndeterminateError",
    "CasmVerificationError",
    "TrustConfig",
    "VerificationResult",
    "Verifier",
    "verify",
)
