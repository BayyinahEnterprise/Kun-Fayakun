"""Phase G11.2 (al-Mursalat / v0.12.0) Go language facade.

This module is the procedural facade for ``language=go``
manifests dispatched by
``furqan_lint.gate11.verification.verify``.

Mirror of as-Saff (v0.11.8) ``python_verification.py`` and
``rust_verification.py`` private handlers, adapted for Go
substrate. The substrate convention is preserved verbatim:
private ``_verify_go(manifest, args)`` function only;
``__all__ = ("_verify_go",)``; no public ``verify`` alias.

It is **purely additive** at v0.12.0: the existing
``Verifier(...).verify_bundle(...)`` class API in
``verification.py`` continues to be the byte-stable substrate
that all production callers (``gate11/cli.py``) and all tests
use directly. The module-level ``verify(manifest, args)``
function in verification.py composes a Verifier instance
internally and delegates to ``_verify_go`` (this file) when
``manifest.module_identity['language'] == "go"``.

The facade signature ``_verify_go(manifest, args)`` accepts
the parsed Manifest plus the argparse namespace from
gate11/cli.py (carrying bundle_path, module_path,
trust_config, force_refresh, expected_identity, expected_issuer,
allow_any_identity). The ``manifest`` parameter is informational
only at this layer -- ``verification.Verifier.verify_bundle``
re-parses the bundle from ``args.bundle_path`` to enforce the
byte-stable single-source-of-truth contract; the manifest
argument is kept for future language-specific pre-flight
checks (e.g., Go module-graph validation).

Per F-RN-1 v1.5 absorption: this body honors caller-passed
``args.trust_config`` via ``getattr(args, "trust_config", None)
or TrustConfig()``. The CLI loads trust_config via existing
``_trust_config_from_path`` helper and attaches to the args
Namespace; programmatic Relying Parties not setting
``args.trust_config`` get default behavior matching v0.11.8
backward-compat semantics.

API pattern mirrored from the v0.11.8-LIVE Python and Rust
private handlers per al-Mursalat T00 step 6 pre-flight
verification record (NOT the at-Tawbah-era reference; the
v0.11.5 G11.0.4 al-Bayyina F24 corrective re-routed the
sigstore import paths). The Verifier class internally uses
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

from pathlib import Path
from typing import TYPE_CHECKING, Any

from furqan_lint.gate11.verification import (
    TrustConfig,
    VerificationResult,
    Verifier,
)

if TYPE_CHECKING:
    import argparse

    from furqan_lint.gate11.manifest_schema import Manifest


def _verify_go(
    manifest: Manifest,
    args: argparse.Namespace,
) -> VerificationResult:
    """Procedural facade for ``language=go`` manifest verification.

    Composes a ``Verifier`` instance with the trust config implied
    by ``args`` and delegates to ``verify_bundle``. Existing
    callers using ``Verifier(...).verify_bundle(...)`` directly
    are unaffected (the Verifier class is byte-stable from
    v0.11.7 onward).

    The ``manifest`` parameter is informational at this layer:
    ``Verifier.verify_bundle`` re-parses the bundle from
    ``args.bundle_path`` to enforce the byte-stable
    single-source-of-truth contract. The argument is retained
    for language-specific pre-flight checks added in future
    phases (e.g., Go module-graph dependency validation).

    Per F-RN-1 v1.5 absorption: honors caller-passed
    ``args.trust_config`` if attached to the args Namespace by
    the CLI; falls back to default ``TrustConfig()`` when absent
    (preserves v0.11.8 programmatic-RP backward compat).

    For Go-language manifests, ``Verifier.verify_bundle``'s
    9-step flow operates as for Python and Rust:

    1. Parse bundle (CASM-V-010 on JSON / schema failure)
    2. Check casm_version == "1.0" (CASM-V-001)
    3. Check language == "go" matches this verifier (CASM-V-001;
       generalized at T01 per al-Mursalat to include go in the
       supported set)
    4. Load Sigstore trust root via TUF (CASM-V-020 ADVISORY /
       CASM-V-021)
    5. Re-canonicalize the manifest (RFC 8785; Invariant 3)
    6. Verify Sigstore signature; enforce identity policy
       (CASM-V-030..036; CASM-V-032 on mismatch; CASM-V-035
       refuse-without-policy default; CASM-V-036 on identity
       extraction TypeError)
    7. Compare module_root_hash to the on-disk Go module path
       (CASM-V-040 on mismatch)
    8. Compare public_surface.names to the live extraction
       (Go-side extraction via goast per Invariant 5
       ``goast.go-public-surface@v1.0`` extraction-method
       identifier; canonicalization rules 6-8 per
       go_signature_canonicalization.py for nested generics +
       channel direction)
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


# ---------------------------------------------------------------------------
# v1.0.1: Go public surface and manifest builder.
#
# Before v1.0.1 the CLI routed only ``.rs`` to a language-specific
# builder, so ``manifest init foo.go`` fell through to the Python
# builder and failed with a SyntaxError, and verification step 8 parsed
# Go source with Python's ``ast``. Both made the Go Gate 11 pipeline
# unusable end to end (the ``gate11-go-smoke-test`` CI job had been red
# on ``main`` since v0.12.0). The Go substrate lives in this module,
# which is already pinned in ``_CHECKER_SOURCE_FILES`` and
# ``PINNED_CHECKER_SOURCES_SELF``, so every line here is covered by the
# checker-set hash.
# ---------------------------------------------------------------------------

_GO_EXTRACTION_METHOD = "goast.go-public-surface@v1.0"


def extract_public_surface_go(path: Path | str) -> list[dict[str, str]]:
    """Return the ASCII-sorted ``public_surface.names`` list for a Go file.

    Exported top-level functions carry a signature fingerprint over
    their canonical signature (parameters, return types, variadic flag;
    rules 6-8 in ``go_signature_canonicalization``), so a changed
    signature is CASM-V-051. Every other exported name goast reports
    (types, constants, variables, receiver-qualified methods) is tracked
    by presence only: its fingerprint covers just its name and kind, so
    its removal is CASM-V-050 but a change to its definition is not
    detected. Its kind is a CASM v1.0 schema kind read from the source
    by ``_go_name_kind``. That asymmetry is documented in
    ``docs/gate11-symmetry.md``.

    Raises whatever ``furqan_lint.go_adapter.parse_file`` raises
    (``GoExtrasNotInstalled`` without the goast binary, ``GoParseError``
    on unparseable source).
    """
    from furqan_lint.gate11.go_signature_canonicalization import (
        canonical_signature_fingerprint,
        canonicalize_function_signature,
    )
    from furqan_lint.go_adapter import parse_file

    data: dict[str, Any] = parse_file(path)
    source = Path(path).read_text(encoding="utf-8")
    public = list(data.get("public_names", []) or [])
    top_level = {name for name in public if "." not in name}
    # goast lists methods in ``functions`` under their bare name (the
    # receiver-qualified ``Type.Method`` appears only in public_names),
    # so a bare name can belong to a method, a top-level function, or
    # both. Only bare names exported at top level get a signature, and
    # every same-named candidate is folded into one fingerprint, so a
    # change to any of them is CASM-V-051 (never silently missed).
    sigs: dict[str, list[dict[str, object]]] = {}
    for fn in data.get("functions", []) or []:
        if not fn.get("exported") or fn["name"] not in top_level:
            continue
        params = list(fn.get("params", []) or [])
        is_variadic = bool(params) and str(params[-1].get("type", "")).startswith("...")
        sigs.setdefault(fn["name"], []).append(
            canonicalize_function_signature(
                fn["name"],
                params,
                list(fn.get("return_type_names", []) or []),
                is_variadic=is_variadic,
            )
        )
    entries: dict[str, dict[str, str]] = {}
    for name, candidates in sigs.items():
        payload: object = (
            candidates[0]
            if len(candidates) == 1
            else sorted(candidates, key=canonical_signature_fingerprint)
        )
        entries[name] = {
            "name": name,
            "kind": "function",
            "signature_fingerprint": canonical_signature_fingerprint(payload),
        }
    for name in public:
        if name not in entries:
            kind = _go_name_kind(name, source)
            entries[name] = {
                "name": name,
                "kind": kind,
                "signature_fingerprint": canonical_signature_fingerprint(
                    {"name": name, "kind": kind, "presence_only": True}
                ),
            }
    return [entries[k] for k in sorted(entries)]


def _go_name_kind(name: str, source: str) -> str:
    """CASM v1.0 schema kind for an exported Go name other than a
    top-level function: ``function`` for a receiver-qualified method
    (``Type.Method``), ``struct`` / ``trait`` (interface) /
    ``alias`` (``type A = B``) / ``type_alias`` (other named types) for
    a ``type`` declaration, ``constant`` otherwise (``const`` and
    ``var``). Read from the source text; goast reports only the name."""
    import re

    if "." in name:
        return "function"
    ident = re.escape(name)
    decl = rf"(?m)^\s*(?:type\s+)?{ident}\s+"
    if re.search(decl + r"struct\b", source):
        return "struct"
    if re.search(decl + r"interface\b", source):
        return "trait"
    if re.search(rf"(?m)^\s*(?:type\s+)?{ident}\s*=", source) and re.search(
        rf"\btype\b[^\n]*\b{ident}\s*=|type\s*\(", source
    ):
        return "alias"
    if re.search(rf"(?m)^\s*type\s+{ident}\b", source):
        return "type_alias"
    return "constant"


def build_manifest_go(
    path: Path | str,
    previous_manifest: Manifest | None = None,
    *,
    trust_root: dict[str, str] | None = None,
    use_placeholder_checker_hash: bool = False,
) -> Manifest:
    """Build a CASM v1.0 manifest for a Go source file.

    Mirrors ``rust_manifest.build_manifest_rust``: same chain and
    attestation fields, ``module_identity.language == "go"`` and
    ``public_surface.extraction_method == "goast.go-public-surface@v1.0"``.
    """
    import datetime
    import hashlib

    from furqan_lint import __version__ as linter_version
    from furqan_lint.gate11.checker_set_hash import (
        compute_checker_set_hash,
        compute_checker_set_hash_placeholder,
    )
    from furqan_lint.gate11.manifest_schema import Manifest as _Manifest
    from furqan_lint.gate11.module_canonicalization import module_root_hash

    source_path = Path(path)
    if previous_manifest is None:
        previous_manifest_hash: str | None = None
        chain_position = 1
    else:
        prev_canonical = previous_manifest.to_canonical_bytes()
        previous_manifest_hash = "sha256:" + hashlib.sha256(prev_canonical).hexdigest()
        chain_position = int(previous_manifest.chain.get("chain_position", 0)) + 1
    checker_hash = (
        compute_checker_set_hash_placeholder(linter_version)
        if use_placeholder_checker_hash
        else compute_checker_set_hash()
    )
    issued_at = (
        datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    return _Manifest.from_dict(
        {
            "casm_version": "1.0",
            "module_identity": {
                "language": "go",
                "module_path": str(source_path),
                "module_root_hash": module_root_hash(source_path),
            },
            "public_surface": {
                "names": extract_public_surface_go(source_path),
                "extraction_method": _GO_EXTRACTION_METHOD,
                "extraction_substrate": f"furqan-lint v{linter_version}",
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
            "trust_root": trust_root
            or {
                "trust_root_id": "public-sigstore",
                "fulcio_url": "https://fulcio.sigstore.dev",
                "rekor_url": "https://rekor.sigstore.dev",
            },
            "issued_at": issued_at,
        }
    )


__all__ = ("_verify_go", "build_manifest_go", "extract_public_surface_go")
