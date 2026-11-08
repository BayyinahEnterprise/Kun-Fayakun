"""Gate 11 CLI handlers (T09).

Subcommands implemented in this module:

* ``furqan-lint manifest init <module-path>``: create the first
  manifest in a chain and sign via Sigstore (T06).
* ``furqan-lint manifest verify <bundle-path>``: run the
  9-step verification flow (T08).
* ``furqan-lint manifest update <module-path>``: create a
  successor manifest in the chain; requires an existing
  adjacent bundle.

Flag parsing in this module is intentionally minimal: the
upstream ``furqan_lint.cli.main`` dispatcher only routes here
when ``args[0] == "manifest"``. Parsing of options such as
``--trust-config`` happens here.

CLI exit codes per the deliverable:

* 0: verification PASSED, or ADVISORY-only.
* 1: a non-advisory CASM-V error fired.
* 2: INDETERMINATE (e.g., DynamicAllError on the public surface).
"""

from __future__ import annotations

import datetime
import hashlib
import json
import sys
from pathlib import Path

from furqan_lint.gate11 import CASM_VERSION, GATE11_BUNDLE_SUFFIX
from furqan_lint.gate11.bundle import Bundle, BundleParseError
from furqan_lint.gate11.checker_set_hash import (
    compute_checker_set_hash as _compute_checker_set_hash,
)
from furqan_lint.gate11.manifest_schema import CasmSchemaError, Manifest
from furqan_lint.gate11.module_canonicalization import (
    ModuleCanonicalizationError,
    module_root_hash,
)
from furqan_lint.gate11.surface_extraction import (
    DynamicAllError,
    extract_public_surface,
)
from furqan_lint.gate11.verification import (
    CasmIndeterminateError,
    CasmVerificationError,
    TrustConfig,
)


def _bundle_path_for(module_path: Path) -> Path:
    """Return the canonical bundle path for ``module_path``.

    Phase G11.1 amended_4 T05.1: bundle naming preserves the
    full module filename (including its language extension) plus
    the ``.furqan.manifest.sigstore`` suffix so that
    ``foo.py`` -> ``foo.py.furqan.manifest.sigstore`` and
    ``foo.rs`` -> ``foo.rs.furqan.manifest.sigstore``. The
    extension is preserved in the bundle name so the verifier
    can route on the .py / .rs / .go / .onnx hint when the
    user invokes ``furqan-lint manifest verify <bundle>``.
    """
    return module_path.parent / (module_path.name + GATE11_BUNDLE_SUFFIX)


def _build_manifest_dict(
    module_path: Path,
    chain_position: int,
    previous_manifest_hash: str | None,
    trust_config: TrustConfig,
    linter_version: str,
) -> dict[str, object]:
    """Build a CASM v1.0 manifest dict for ``module_path``.

    Raises ``DynamicAllError`` if ``__all__`` is dynamic; the
    caller (init / update) maps this to exit code 2.
    """
    names_entries = extract_public_surface(module_path)
    return {
        "casm_version": CASM_VERSION,
        "module_identity": {
            "language": "python",
            "module_path": str(module_path),
            "module_root_hash": module_root_hash(module_path),
        },
        "public_surface": {
            "names": names_entries,
            "extraction_method": "ast.module-public-surface@v1.0",
            "extraction_substrate": f"furqan-lint v{linter_version}",
        },
        "chain": {
            "previous_manifest_hash": previous_manifest_hash,
            "chain_position": chain_position,
        },
        "linter_substrate_attestation": {
            "linter_name": "furqan-lint",
            "linter_version": linter_version,
            # Phase G11.1 audit H-6 propagation defense: the
            # substantive ``checker_set_hash`` is computed over
            # the pinned checker source files via
            # :func:`furqan_lint.gate11.checker_set_hash.compute_checker_set_hash`.
            # The Phase G11.0 v0.10.0 ship used
            # ``sha256(linter_version)`` (a placeholder dressed
            # as a commitment); v0.11.0 corrects this for both
            # Python and Rust pipelines.
            "checker_set_hash": _compute_checker_set_hash(),
        },
        "trust_root": {
            "trust_root_id": trust_config.trust_root_id,
            "fulcio_url": trust_config.fulcio_url,
            "rekor_url": trust_config.rekor_url,
        },
        "issued_at": (
            datetime.datetime.now(datetime.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        ),
    }


def _parse_options(args: list[str]) -> tuple[list[str], dict[str, object]]:
    """Parse common Gate 11 options out of an argv list.

    Returns ``(positional, opts)`` where ``opts`` may carry
    ``trust_config_path`` (Path or None).
    """
    positional: list[str] = []
    opts: dict[str, object] = {
        "trust_config_path": None,
        "force_refresh": False,
        "expected_identity": None,
        "expected_issuer": None,
        "allow_any_identity": False,
        "use_placeholder_checker_hash": False,
    }
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--trust-config":
            if i + 1 >= len(args):
                print("--trust-config requires a path argument", file=sys.stderr)
                raise SystemExit(2)
            opts["trust_config_path"] = Path(args[i + 1])
            i += 2
        elif a == "--force-refresh":
            opts["force_refresh"] = True
            i += 1
        elif a == "--expected-identity":
            # Phase G11.1 audit C-1 corrective: identity policy.
            if i + 1 >= len(args):
                print(
                    "--expected-identity requires a pattern argument",
                    file=sys.stderr,
                )
                raise SystemExit(2)
            opts["expected_identity"] = args[i + 1]
            i += 2
        elif a == "--expected-issuer":
            if i + 1 >= len(args):
                print(
                    "--expected-issuer requires an issuer URL argument",
                    file=sys.stderr,
                )
                raise SystemExit(2)
            opts["expected_issuer"] = args[i + 1]
            i += 2
        elif a == "--allow-any-identity":
            # Explicit opt-in to UnsafeNoOp(); presence in CI logs
            # is itself an audit signal (Sulayman-Naml ADVISORY).
            opts["allow_any_identity"] = True
            i += 1
        elif a == "--placeholder-checker-hash":
            # Phase G11.1 audit H-6 Form B: opt into placeholder
            # prefix for v0.11.x patch releases.
            opts["use_placeholder_checker_hash"] = True
            i += 1
        else:
            positional.append(a)
            i += 1
    return positional, opts


def _trust_config_from_path(path: Path | None) -> TrustConfig:
    if path is None:
        return TrustConfig()
    if not path.is_file():
        print(f"trust-config file not found: {path}", file=sys.stderr)
        raise SystemExit(2)
    data = json.loads(path.read_text(encoding="utf-8"))
    return TrustConfig(
        trust_root_id=str(data.get("trust_root_id", "public-sigstore")),
        fulcio_url=str(data.get("fulcio_url", "https://fulcio.sigstore.dev")),
        rekor_url=str(data.get("rekor_url", "https://rekor.sigstore.dev")),
    )


def cmd_manifest_init(args: list[str]) -> int:
    """``furqan-lint manifest init <module-path>``.

    Creates the first manifest in a chain (chain_position=1,
    previous_manifest_hash=None) and signs it via Sigstore.
    """
    positional, opts = _parse_options(args)
    if not positional:
        print(
            "usage: furqan-lint manifest init <module-path> " "[--trust-config PATH]",
            file=sys.stderr,
        )
        return 2
    module_path = Path(positional[0])
    if not module_path.is_file():
        print(f"module not found: {module_path}", file=sys.stderr)
        return 1
    trust_config = _trust_config_from_path(
        opts["trust_config_path"]  # type: ignore[arg-type]
    )

    from furqan_lint import __version__

    # Phase G11.1 dispatch: .rs goes to the Rust manifest builder;
    # .py keeps the existing Python pipeline.
    try:
        if module_path.suffix == ".rs":
            from furqan_lint.gate11.rust_manifest import (
                build_manifest_rust,
            )
            from furqan_lint.gate11.rust_surface_extraction import (
                DynamicRustSurfaceError,
            )

            try:
                manifest = build_manifest_rust(
                    module_path,
                    trust_root={
                        "trust_root_id": trust_config.trust_root_id,
                        "fulcio_url": trust_config.fulcio_url,
                        "rekor_url": trust_config.rekor_url,
                    },
                    use_placeholder_checker_hash=bool(opts["use_placeholder_checker_hash"]),
                )
            except DynamicRustSurfaceError as e:
                print(f"INDETERMINATE: {e}", file=sys.stderr)
                return 2
        elif module_path.suffix == ".go":
            # v1.0.1: .go previously fell through to the Python
            # builder and failed with a SyntaxError.
            manifest = _build_go_manifest(module_path, trust_config, opts, previous=None)
        else:
            manifest_dict = _build_manifest_dict(
                module_path,
                chain_position=1,
                previous_manifest_hash=None,
                trust_config=trust_config,
                linter_version=__version__,
            )
            manifest = Manifest.from_dict(manifest_dict)
    except DynamicAllError as e:
        print(f"INDETERMINATE: {e}", file=sys.stderr)
        return 2
    except _GoManifestUnavailable:
        return 1  # reason already printed
    except (ModuleCanonicalizationError, CasmSchemaError) as e:
        print(f"{e.code}: {e}", file=sys.stderr)
        return 1

    try:
        from furqan_lint.gate11.signing import sign_manifest
    except ImportError:
        print(
            "Gate 11 signing requires the [gate11] extra: " "pip install furqan-lint[gate11]",
            file=sys.stderr,
        )
        return 1

    try:
        sg_bundle = sign_manifest(manifest)
    except Exception as e:
        print(f"signing failed: {e}", file=sys.stderr)
        return 1

    out_path = _bundle_path_for(module_path)
    Bundle(manifest=manifest, sigstore_bundle=sg_bundle).write(out_path)
    print(f"CASM-INIT  {out_path}")
    return 0


class _GoManifestUnavailable(Exception):
    """The Go manifest could not be built; the reason was printed."""


def _build_go_manifest(
    module_path: Path,
    trust_config: TrustConfig,
    opts: dict[str, object],
    previous: Manifest | None,
) -> Manifest:
    """Build a Go manifest, or print the reason and raise
    ``_GoManifestUnavailable`` (the CLI exits 1 with a message, not a
    traceback).

    v1.0.2: this returned ``Manifest | None`` in v1.0.1. The callers
    checked for None correctly, but inside a ``try`` block, where D11
    deliberately does not trust a guard (documented limit
    ``guard_inside_try``), so furqan-lint's self-check reported both
    callers. Raising keeps the contract total: there is no None arm to
    collapse."""
    from furqan_lint.gate11.go_verification import build_manifest_go
    from furqan_lint.go_adapter import GoExtrasNotInstalled, GoParseError

    try:
        return build_manifest_go(
            module_path,
            previous_manifest=previous,
            trust_root={
                "trust_root_id": trust_config.trust_root_id,
                "fulcio_url": trust_config.fulcio_url,
                "rekor_url": trust_config.rekor_url,
            },
            use_placeholder_checker_hash=bool(opts.get("use_placeholder_checker_hash")),
        )
    except GoExtrasNotInstalled as e:
        print(f"Go Gate 11 support not installed: {e}", file=sys.stderr)
        raise _GoManifestUnavailable from e
    except GoParseError as e:
        print(f"Go parse error: {e}", file=sys.stderr)
        raise _GoManifestUnavailable from e


def cmd_manifest_verify(args: list[str]) -> int:
    """``furqan-lint manifest verify <bundle-path>``."""
    positional, opts = _parse_options(args)
    if not positional:
        print(
            "usage: furqan-lint manifest verify <bundle-path> "
            "[--trust-config PATH] [--force-refresh]",
            file=sys.stderr,
        )
        return 2
    bundle_path = Path(positional[0])
    if not bundle_path.is_file():
        print(f"bundle not found: {bundle_path}", file=sys.stderr)
        return 1
    trust_config = _trust_config_from_path(
        opts["trust_config_path"]  # type: ignore[arg-type]
    )

    # Module path: resolved by stripping the GATE11_BUNDLE_SUFFIX
    # and trying both .py and the parent directory.
    if bundle_path.name.endswith(GATE11_BUNDLE_SUFFIX):
        # Phase G11.1: bundle name is "<module_filename>.furqan.manifest.sigstore"
        # so stripping the suffix yields the original module
        # filename (extension included).
        module_filename = bundle_path.name[: -len(GATE11_BUNDLE_SUFFIX)]
        module_path = bundle_path.parent / module_filename
    else:
        print(
            f"bundle filename does not end with {GATE11_BUNDLE_SUFFIX!r}",
            file=sys.stderr,
        )
        return 1

    if not module_path.is_file():
        # Best-effort: also accept the manifest's recorded module_path.
        try:
            bundle = Bundle.read(bundle_path)
            recorded = Path(bundle.manifest.module_identity["module_path"])
            if recorded.is_file():
                module_path = recorded
        except (BundleParseError, KeyError):
            pass

    if not module_path.is_file():
        print(f"module not found for bundle {bundle_path}", file=sys.stderr)
        return 1

    # Per al-Mursalat T02 Edit 3a (Route a1-via-args):
    # build args Namespace from opts + positional +
    # loaded trust_config; load manifest from bundle;
    # route through verification.verify single canonical
    # dispatch dict (function-local _LANGUAGE_DISPATCH).
    # Per F-RN-1 v1.5 absorption: trust_config attached
    # to Namespace so private handlers honor it via
    # getattr(args, "trust_config", None) or TrustConfig().
    import argparse as _argparse

    from furqan_lint.gate11 import verification as _verification

    try:
        _manifest = Bundle.read(bundle_path).manifest
    except (BundleParseError, KeyError, CasmSchemaError) as e:
        print(f"bundle parse failed for {bundle_path}: {e}", file=sys.stderr)
        return 1
    _namespace = _argparse.Namespace(
        bundle_path=bundle_path,
        module_path=module_path,
        trust_config=trust_config,
        trust_config_path=opts["trust_config_path"],
        expected_identity=opts["expected_identity"],
        expected_issuer=opts["expected_issuer"],
        allow_any_identity=bool(opts["allow_any_identity"]),
        force_refresh=bool(opts["force_refresh"]),
    )
    try:
        result = _verification.verify(_manifest, _namespace)
    except CasmIndeterminateError as e:
        print(f"INDETERMINATE: {e}", file=sys.stderr)
        return 2
    except CasmVerificationError as e:
        if e.code in {"CASM-V-020", "CASM-V-061"}:
            # ADVISORY codes should not raise; defensive map.
            print(f"ADVISORY {e.code}: {e}", file=sys.stderr)
            return 0
        print(f"{e.code}: {e}", file=sys.stderr)
        return 1

    print(f"CASM-OK  {module_path}")
    print(f"  signed_by: {result.signed_by}")
    if result.manifest is not None:
        print(f"  signed_at: {result.manifest.issued_at}")
    print(f"  chain_position: {result.chain_position}")
    for code, msg in result.advisories:
        print(f"  ADVISORY {code}: {msg}")
    return 0


def cmd_manifest_update(args: list[str]) -> int:
    """``furqan-lint manifest update <module-path>``.

    Creates a successor manifest in the chain. Requires an
    adjacent bundle at ``<module_path.with_suffix(GATE11_BUNDLE_SUFFIX)>``;
    the new manifest's ``previous_manifest_hash`` is the
    canonical-bytes hash of the existing bundle's manifest, and
    ``chain_position`` is the previous + 1.
    """
    positional, opts = _parse_options(args)
    if not positional:
        print(
            "usage: furqan-lint manifest update <module-path> " "[--trust-config PATH]",
            file=sys.stderr,
        )
        return 2
    module_path = Path(positional[0])
    if not module_path.is_file():
        print(f"module not found: {module_path}", file=sys.stderr)
        return 1
    bundle_path = _bundle_path_for(module_path)
    if not bundle_path.is_file():
        print(
            f"no existing bundle at {bundle_path}; use 'manifest init' "
            f"to create the first manifest in a chain",
            file=sys.stderr,
        )
        return 1
    try:
        existing = Bundle.read(bundle_path)
    except BundleParseError as e:
        print(f"{e.code}: {e}", file=sys.stderr)
        return 1
    prev_canonical = existing.manifest.to_canonical_bytes()
    prev_hash = "sha256:" + hashlib.sha256(prev_canonical).hexdigest()
    next_position = int(existing.manifest.chain.get("chain_position", 0)) + 1
    trust_config = _trust_config_from_path(
        opts["trust_config_path"]  # type: ignore[arg-type]
    )

    from furqan_lint import __version__

    # v1.0.1: route on the module's language, as ``init`` does. Before,
    # ``update`` always used the Python builder, so it failed on .rs and
    # .go sources.
    try:
        if module_path.suffix == ".rs":
            from furqan_lint.gate11.rust_manifest import build_manifest_rust
            from furqan_lint.gate11.rust_surface_extraction import (
                DynamicRustSurfaceError,
            )

            try:
                manifest = build_manifest_rust(
                    module_path,
                    previous_manifest=existing.manifest,
                    trust_root={
                        "trust_root_id": trust_config.trust_root_id,
                        "fulcio_url": trust_config.fulcio_url,
                        "rekor_url": trust_config.rekor_url,
                    },
                )
            except DynamicRustSurfaceError as e:
                print(f"INDETERMINATE: {e}", file=sys.stderr)
                return 2
        elif module_path.suffix == ".go":
            manifest = _build_go_manifest(
                module_path, trust_config, opts, previous=existing.manifest
            )
        else:
            manifest_dict = _build_manifest_dict(
                module_path,
                chain_position=next_position,
                previous_manifest_hash=prev_hash,
                trust_config=trust_config,
                linter_version=__version__,
            )
            manifest = Manifest.from_dict(manifest_dict)
    except DynamicAllError as e:
        print(f"INDETERMINATE: {e}", file=sys.stderr)
        return 2
    except _GoManifestUnavailable:
        return 1  # reason already printed
    except (ModuleCanonicalizationError, CasmSchemaError) as e:
        print(f"{e.code}: {e}", file=sys.stderr)
        return 1

    try:
        from furqan_lint.gate11.signing import sign_manifest
    except ImportError:
        print(
            "Gate 11 signing requires the [gate11] extra: " "pip install furqan-lint[gate11]",
            file=sys.stderr,
        )
        return 1

    try:
        sg_bundle = sign_manifest(manifest)
    except Exception as e:
        print(f"signing failed: {e}", file=sys.stderr)
        return 1

    Bundle(manifest=manifest, sigstore_bundle=sg_bundle).write(bundle_path)
    print(f"CASM-UPDATE  {bundle_path}  chain_position={next_position}")
    return 0


def cmd_check_gate11(directory: Path, opts: dict[str, object]) -> int:
    """``furqan-lint check --gate11 <path>``.

    Walks the path for ``*.furqan.manifest.sigstore`` bundles and
    runs ``manifest verify`` on each. Silent no-op when no
    bundles are present.
    """
    bundles = sorted(directory.rglob(f"*{GATE11_BUNDLE_SUFFIX}"))
    if not bundles:
        return 0
    # Per al-Mursalat T02 Edit 3b (Route a1-via-args;
    # F-PF-2 v1.7 asymmetric vs Edit 3a):
    # cmd_check_gate11 receives PRE-PARSED directory + opts
    # from dispatch_manifest upstream (signature divergence
    # from cmd_manifest_verify per F-PF-2 absorption);
    # single trust_config load shared across all bundles;
    # per-bundle Namespace built from shared base + per-
    # bundle path; route through verification.verify.
    import argparse as _argparse

    from furqan_lint.gate11 import verification as _verification

    trust_config = _trust_config_from_path(
        opts["trust_config_path"]  # type: ignore[arg-type]
    )
    overall = 0
    for bp in bundles:
        if bp.name.endswith(GATE11_BUNDLE_SUFFIX):
            stem = bp.name[: -len(GATE11_BUNDLE_SUFFIX)]
            module_path = bp.parent / f"{stem}.py"
        else:
            continue
        if not module_path.is_file():
            try:
                bundle = Bundle.read(bp)
                recorded = Path(bundle.manifest.module_identity["module_path"])
                if recorded.is_file():
                    module_path = recorded
            except (BundleParseError, KeyError):
                pass
        if not module_path.is_file():
            print(f"GATE11-SKIP  {bp}  module not found", file=sys.stderr)
            continue
        try:
            _manifest = Bundle.read(bp).manifest
        except (BundleParseError, KeyError, CasmSchemaError) as e:
            print(f"{bp}  bundle parse failed: {e}", file=sys.stderr)
            overall = max(overall, 1)
            continue
        _namespace = _argparse.Namespace(
            bundle_path=bp,
            module_path=module_path,
            trust_config=trust_config,
            trust_config_path=opts["trust_config_path"],
            expected_identity=opts["expected_identity"],
            expected_issuer=opts["expected_issuer"],
            allow_any_identity=bool(opts["allow_any_identity"]),
            force_refresh=False,
        )
        try:
            result = _verification.verify(_manifest, _namespace)
        except CasmIndeterminateError as e:
            print(f"INDETERMINATE  {bp}  {e}", file=sys.stderr)
            overall = max(overall, 2)
            continue
        except CasmVerificationError as e:
            print(f"{e.code}  {bp}  {e}", file=sys.stderr)
            overall = max(overall, 1)
            continue
        print(f"CASM-OK  {module_path}  signed_by={result.signed_by}")
        for code, msg in result.advisories:
            print(f"  ADVISORY {code}: {msg}")
    return overall


def cmd_manifest_verify_self(args: list[str]) -> int:  # noqa: PLR0915
    """``furqan-lint manifest verify-self [--version V]`` -- al-Basirah T05.

    Verifies furqan-lint's own gate11 self-attestation manifest.
    Downloads the signed self-manifest + Sigstore bundle from the
    convention-based GitHub Release URL derived from the version
    (default: the installed furqan-lint version), verifies the
    Sigstore signature over the published JSON bytes with the
    release workflow's identity pinned (v1.0.2; see
    ``_verify_self_signature``), then compares the attested
    checker_set_hash with the installed package.

    Recursive closure of the structural-honesty thesis: the
    verifier verifies the verifier's own release.

    Per F-BA-substrate-conflict-1 v1.0.0 closure: failure surfaces
    CASM-V-072 (substrate-actual; NOT prompt-cited 040 which was
    in-use at v0.10.0+ baseline) with three sub-conditions
    named:

        (a) manifest-not-found (convention-based URL 404 or
            network fetch failure)
        (b) checker-set-hash-drift (manifest's claim differs from
            installed pinned source list)
        (c) signature-verification-unexpected (Sigstore failure
            not covered by CASM-V-030..036)
    """
    import importlib.metadata as _md
    import json as _json
    import tempfile as _tempfile
    import urllib.error as _urllib_error
    import urllib.request as _urllib_request

    positional, opts = _parse_options(args)
    # Parse --version (optional override of installed version):
    requested_version: str | None = None
    i = 0
    rest = list(positional)
    while i < len(rest):
        if rest[i] == "--version" and i + 1 < len(rest):
            requested_version = rest[i + 1]
            del rest[i : i + 2]
            continue
        i += 1
    if requested_version is None:
        try:
            requested_version = _md.version("furqan-lint")
        except _md.PackageNotFoundError:
            print(
                "furqan-lint package metadata not found; pass --version "
                "explicitly to verify a specific release",
                file=sys.stderr,
            )
            return 1

    base_url = (
        "https://github.com/BayyinahEnterprise/furqan-lint/"
        f"releases/download/v{requested_version}"
    )
    manifest_url = f"{base_url}/self_manifest.json"
    bundle_url = f"{base_url}/self_manifest.bundle"

    tmp_dir = Path(_tempfile.mkdtemp(prefix="furqan_self_attest_"))
    manifest_local = tmp_dir / "self_manifest.json"
    bundle_local = tmp_dir / "self_manifest.bundle"

    try:
        _urllib_request.urlretrieve(manifest_url, manifest_local)
        _urllib_request.urlretrieve(bundle_url, bundle_local)
    except (_urllib_error.HTTPError, _urllib_error.URLError, OSError) as e:
        # CASM-V-072 sub-condition (a): manifest-not-found
        print(
            f"CASM-V-072: self-attestation-failure sub-condition "
            f"(a) manifest-not-found at expected URL {manifest_url}: {e}",
            file=sys.stderr,
        )
        return 1

    # Parse manifest:
    try:
        manifest_data = _json.loads(manifest_local.read_text(encoding="utf-8"))
        _manifest = Manifest.from_dict(manifest_data)
    except (ValueError, KeyError, CasmSchemaError) as e:
        print(
            f"CASM-V-072: self-attestation-failure sub-condition "
            f"(a) manifest-not-parseable: {e}",
            file=sys.stderr,
        )
        return 1

    # v1.0.2: verify the Sigstore signature FIRST, over the exact bytes
    # the release workflow signed, before trusting anything the manifest
    # says. The release workflow (release.yml, al-Basirah T06) runs
    # ``python -m sigstore sign --bundle self_manifest.bundle
    # self_manifest.json``: the signed artifact is the JSON file's raw
    # bytes and ``self_manifest.bundle`` is a bare Sigstore bundle. Up to
    # v1.0.1 this handler instead routed through ``verification.verify``,
    # which reads a CASM ``{manifest, sigstore_bundle}`` wrapper and runs
    # steps 7-8 (source hash and Python surface) against the manifest
    # file itself, so it failed on every real release with "bundle
    # missing 'manifest' field". The identity policy defaults to the
    # release workflow at this version's tag.
    default_identity = (
        "https://github.com/BayyinahEnterprise/furqan-lint/"
        f".github/workflows/release.yml@refs/tags/v{requested_version}"
    )
    default_issuer = "https://token.actions.githubusercontent.com"
    trust_config = _trust_config_from_path(
        opts["trust_config_path"]  # type: ignore[arg-type]
    )
    try:
        signed_by = _verify_self_signature(
            manifest=_manifest,
            manifest_bytes=manifest_local.read_bytes(),
            bundle_path=bundle_local,
            trust_config=trust_config,
            expected_identity=opts["expected_identity"] or default_identity,  # type: ignore[arg-type]
            expected_issuer=opts["expected_issuer"] or default_issuer,  # type: ignore[arg-type]
            allow_any_identity=bool(opts["allow_any_identity"]),
            force_refresh=bool(opts["force_refresh"]),
        )
    except CasmIndeterminateError as e:
        print(f"INDETERMINATE: {e}", file=sys.stderr)
        return 2
    except CasmVerificationError as e:
        # Per F-BA standing rule: identity-path errors pass through as
        # their own CASM-V-030..036 codes; anything else is CASM-V-072
        # sub-condition (c).
        if e.code in {
            "CASM-V-030",
            "CASM-V-031",
            "CASM-V-032",
            "CASM-V-033",
            "CASM-V-034",
            "CASM-V-035",
            "CASM-V-036",
        }:
            print(f"{e.code}: {e}", file=sys.stderr)
            return 1
        print(
            f"CASM-V-072: self-attestation-failure sub-condition "
            f"(c) signature-verification-unexpected ({e.code}): {e}",
            file=sys.stderr,
        )
        return 1

    # Verify checker_set_hash matches the installed pinned source list:
    from furqan_lint.gate11.self_manifest import (
        compute_self_checker_set_hash,
    )

    installed_hash = compute_self_checker_set_hash()
    manifest_hash = _manifest.linter_substrate_attestation.get("checker_set_hash")
    # The manifest's hash is over the substrate AT RELEASE TIME; the
    # installed-hash is computed over the substrate of the currently-
    # installed furqan-lint. Drift between these is CASM-V-072 sub-
    # condition (b), checked only when verifying the installed version
    # (verifying another release's manifest is expected to differ).
    if manifest_hash != installed_hash and requested_version == _md.version("furqan-lint"):
        print(
            f"CASM-V-072: self-attestation-failure sub-condition "
            f"(b) checker-set-hash-drift: manifest claims "
            f"{manifest_hash!r}, installed pinned source list "
            f"computes {installed_hash!r}",
            file=sys.stderr,
        )
        return 1

    print(f"CASM-OK  furqan-lint@{requested_version} self-attestation")
    print(f"  signed_by: {signed_by}")
    print(f"  signed_at: {_manifest.issued_at}")
    print(f"  checker_set_hash: {manifest_hash}")
    return 0


def _verify_self_signature(
    *,
    manifest: Manifest,
    manifest_bytes: bytes,
    bundle_path: Path,
    trust_config: TrustConfig,
    expected_identity: str | None,
    expected_issuer: str | None,
    allow_any_identity: bool,
    force_refresh: bool,
) -> str:
    """Verify a release's self-manifest signature (v1.0.2).

    ``bundle_path`` is a bare Sigstore bundle over ``manifest_bytes``,
    the exact bytes of ``self_manifest.json`` as published. Reuses the
    nine-step verifier's trust-root loading (step 4) and Sigstore
    verification with identity policy (step 6), so error codes and the
    refuse-without-policy default are shared; steps 7-8 do not apply
    (the manifest attests the installed package, not a source file).
    Returns the signer identity.
    """
    import json as _json

    from furqan_lint.gate11.verification import Verifier

    try:
        raw = _json.loads(bundle_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise CasmVerificationError("CASM-V-010", f"self_manifest.bundle is not JSON: {e}") from e
    if not isinstance(raw, dict) or ("messageSignature" not in raw and "dsseEnvelope" not in raw):
        raise CasmVerificationError(
            "CASM-V-010",
            "self_manifest.bundle is not a Sigstore bundle " "(no messageSignature / dsseEnvelope)",
        )
    verifier = Verifier(trust_config=trust_config)
    trusted_root = verifier.step4_load_trust_root(force_refresh=force_refresh)
    return verifier.step6_verify_sigstore(
        Bundle(manifest=manifest, sigstore_bundle=raw),
        manifest_bytes,
        trusted_root,
        expected_identity=expected_identity,
        expected_issuer=expected_issuer,
        allow_any_identity=allow_any_identity,
    )


def dispatch_manifest(args: list[str]) -> int:
    """Top-level dispatcher invoked from furqan_lint.cli.main()
    when args[0] == "manifest"."""
    if not args:
        print(
            "usage: furqan-lint manifest <init|verify|verify-self|update> ...",
            file=sys.stderr,
        )
        return 2
    sub = args[0]
    rest = args[1:]
    if sub == "init":
        return cmd_manifest_init(rest)
    if sub == "verify":
        return cmd_manifest_verify(rest)
    if sub == "verify-self":
        return cmd_manifest_verify_self(rest)
    if sub == "update":
        return cmd_manifest_update(rest)
    print(f"unknown manifest action: {sub}", file=sys.stderr)
    return 2


__all__ = (
    "cmd_check_gate11",
    "cmd_manifest_init",
    "cmd_manifest_update",
    "cmd_manifest_verify",
    "cmd_manifest_verify_self",
    "dispatch_manifest",
)
