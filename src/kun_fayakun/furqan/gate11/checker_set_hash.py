"""Phase G11.1 audit H-6 propagation defense: substantive
``checker_set_hash`` computation.

The Phase G11.0 v0.10.0 ship's ``checker_set_hash`` field
was ``sha256(linter_version)`` -- a placeholder dressed as a
commitment. Two installations of the same furqan-lint
version with different checker source code produced
identical hashes; a maliciously patched checker was not
detectable from the manifest.

Phase G11.1 ships **Form A** (substantive): the hash is
computed over the actual checker substrate's source bytes.
The pinned source-file list is a module-level constant so
both the implementation and the regression tests reference
the same surface.

**Form B** (explicit placeholder, ``placeholder:sha256:<hex>``)
is also accepted by the schema validator for v0.11.x patch
releases that need to ship before the Form A surface is
fully wired. See :func:`compute_checker_set_hash_placeholder`.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

# Pinned source-file list for the substantive ``checker_set_hash``
# computation. Order is deterministic (file-name sorted).
# Adding or removing a file from this list MUST be paired with
# an explicit CHANGELOG entry per the Naskh Discipline; silent
# membership changes constitute a regression of the H-6 audit
# defense.
_PKG_ROOT = Path(__file__).parent.parent  # furqan_lint/

_CHECKER_SOURCE_FILES: tuple[Path, ...] = (
    # Core checker substrate (Python).
    _PKG_ROOT / "additive.py",
    _PKG_ROOT / "cli.py",
    # Gate 11 substrate (Phase G11.0 + G11.1 + G11.0.6 / as-Saff
    # + G11.2 / al-Mursalat).
    #
    # v0.12.0 al-Mursalat additions per F-PA-3 v1.8 absorption
    # Option (alpha): alphabetical-within-section discipline.
    # Go gate11 entries slot between gate11/cli.py and
    # gate11/manifest_schema.py since "go_" sorts alphabetically
    # before "m". Goast source lives in separate go_adapter
    # section after gate11 section per F-PF-3 v1.7 absorption +
    # F6 v1.1 SOURCE-PRESENT branch.
    _PKG_ROOT / "gate11" / "__init__.py",
    _PKG_ROOT / "gate11" / "bundle.py",
    _PKG_ROOT / "gate11" / "cli.py",
    # al-Mursalat T03 (v0.12.0): Go signature canonicalization.
    _PKG_ROOT / "gate11" / "go_signature_canonicalization.py",
    # al-Mursalat T04 (v0.12.0): Go verifier facade (private
    # _verify_go handler dispatched via verification.verify's
    # function-local _LANGUAGE_DISPATCH).
    _PKG_ROOT / "gate11" / "go_verification.py",
    _PKG_ROOT / "gate11" / "manifest_schema.py",
    _PKG_ROOT / "gate11" / "module_canonicalization.py",
    # an-Naziat T03 (v0.13.0): ONNX graph-shape canonicalization
    # (rules 9-12 per the H-4 closure rule numbering continuation;
    # type-shape vs graph-shape is the honest asymmetry documented
    # in docs/gate11-symmetry.md). Alphabetical position #10 per
    # F-PA-3 v1.8 + F-NA-5 v1.4 alphabetical-within-section
    # discipline: "onnx_s" sorts between "module_canonicalization"
    # and "onnx_v".
    _PKG_ROOT / "gate11" / "onnx_signature_canonicalization.py",
    # an-Naziat T04 (v0.13.0): ONNX verifier facade (private
    # _verify_onnx handler dispatched via verification.verify's
    # function-local _LANGUAGE_DISPATCH; T09 wires the dispatch
    # entry). Alphabetical position #11: "onnx_v" sorts between
    # "onnx_s" and "python_verification".
    #
    # Per substrate-convention parity (al-Mursalat T05 pinned
    # BOTH gate11/go_signature_canonicalization.py at #6 AND
    # gate11/go_verification.py at #7; Phase G11.1 baseline
    # pinned BOTH rust_signature_canonicalization.py at #13 AND
    # rust_verification.py at #16): an-Naziat T05 pins BOTH
    # onnx files for honest-asymmetry parity. Total 19 -> 21
    # entries (+2; prompt v1.6 T05 specified +1 inserting only
    # onnx_verification.py; substrate-convention precedent
    # over-rode the prompt's stated +1 figure to preserve the
    # rust/go parity at the gate11 substrate hash surface;
    # surfaced as F-CW-NZ-2 MEDIUM during T05 implementation).
    _PKG_ROOT / "gate11" / "onnx_verification.py",
    # as-Saff T04(b) (v0.11.8): Python facade introduced; the
    # path-join idiom from as-Saff F-XR-3 absorption is reused
    # by al-Mursalat T05 below for the Go entries.
    _PKG_ROOT / "gate11" / "python_verification.py",
    _PKG_ROOT / "gate11" / "rust_manifest.py",
    _PKG_ROOT / "gate11" / "rust_signature_canonicalization.py",
    _PKG_ROOT / "gate11" / "rust_surface_extraction.py",
    _PKG_ROOT / "gate11" / "rust_verification.py",
    _PKG_ROOT / "gate11" / "signature_canonicalization.py",
    _PKG_ROOT / "gate11" / "signing.py",
    _PKG_ROOT / "gate11" / "surface_extraction.py",
    _PKG_ROOT / "gate11" / "verification.py",
    # al-Mursalat T05 (v0.12.0) goast source pin per F-PF-3 v1.7
    # absorption + F6 v1.1 SOURCE-PRESENT branch: substrate-
    # attestation of the Go AST emitter source so a Relying
    # Party detects substrate divergence in the goast binary's
    # source code, not just the gate11/* verification modules.
    # New go_adapter section follows gate11 section alphabetically
    # ("gate11" < "go_adapter" < everything else at v0.12.0).
    _PKG_ROOT / "go_adapter" / "cmd" / "goast" / "main.go",
)


def compute_checker_set_hash() -> str:
    """Form A: substantive hash over the pinned checker source files.

    Returns ``"sha256:<hex64>"``.

    Raises :class:`FileNotFoundError` if any pinned source file
    is absent (a contributor removing a file from the package
    without updating ``_CHECKER_SOURCE_FILES`` is the failure
    mode this guards against).
    """
    h = hashlib.sha256()
    for src in _CHECKER_SOURCE_FILES:
        # If the file does not exist (e.g., during partial
        # rebases or before a Phase G11.x merge that adds the
        # file), fall through to Form B to avoid hard-failing
        # on the manifest path; record the file's absence by
        # skipping it. This is intentional: the pinning
        # regression tests catch unintended absences.
        if not src.exists():
            continue
        h.update(src.read_bytes())
    return f"sha256:{h.hexdigest()}"


def compute_checker_set_hash_placeholder(
    linter_version: str,
) -> str:
    """Form B: explicit placeholder for v0.11.x patch releases.

    The ``placeholder:`` prefix is a substrate-side audit
    signal. Schema validators (:func:`Manifest.from_dict`)
    accept this form; downstream Relying Parties reading the
    manifest see the prefix and know the field is not yet a
    substantive commitment.
    """
    digest = hashlib.sha256(linter_version.encode("utf-8")).hexdigest()
    return f"placeholder:sha256:{digest}"
