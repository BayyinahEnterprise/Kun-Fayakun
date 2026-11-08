"""Pinned source-file list for furqan-lint's own self-attestation.

Phase G12.0 al-Basirah (v1.0.0+): the recursive closure of the
structural-honesty thesis. furqan-lint attests its own substrate
via this pinned source list; the Form A checker_set_hash
(per H-6 corrective at v0.11.2 at-Tawbah) computed over the
concatenated bytes of the files below in pinned-list order is
the substrate-of-record for ``furqan-lint manifest verify-self``.

Adding a file: requires a v1.x.0 minor release and CHANGELOG
entry per Naskh Discipline.
Removing a file: requires v1.x.0 minor release and CHANGELOG
retirement entry per framework section 10.2 procedure.
Modifying file contents: produces a different self-attestation
hash, which is the design (the hash attests the checker code's
integrity; drift between manifest and substrate raises
CASM-V-072 sub-condition (b) checker-set-hash-drift).

Per F-BA-substrate-conflict-1 v1.0.0 closure: prompt T02
specified speculative paths
(``src/furqan_lint/checkers/d24.py`` etc.) that do not match
substrate-actual layout. Substrate-actual layout has no
``checkers/`` directory; checker modules live at top-level
``src/furqan_lint/`` (additive.py, return_none.py,
zero_return.py) plus the gate11/ substrate. This list uses
substrate-actual paths per SUBSTRATE-ACTUAL-OVERRIDES-PROMPT
disposition.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

_PKG_ROOT = Path(__file__).parent.parent  # furqan_lint/

# Pinned source-file list (relative to furqan_lint/ package root).
# Order is deterministic (substrate-actual canonical-alphabetical-
# within-section per F-PA-3 v1.8 discipline mirrored to self).
PINNED_CHECKER_SOURCES_SELF: Final[tuple[Path, ...]] = (
    # Core checker substrate (top-level furqan_lint/):
    _PKG_ROOT / "additive.py",
    _PKG_ROOT / "cli.py",
    _PKG_ROOT / "return_none.py",
    _PKG_ROOT / "zero_return.py",
    # Gate 11 substrate (alphabetical within section per F-PA-3 +
    # F-NA-5 + F-CW-NZ-2 conventions inherited from prior phases):
    _PKG_ROOT / "gate11" / "__init__.py",
    _PKG_ROOT / "gate11" / "_pinned_checker_sources_self.py",
    _PKG_ROOT / "gate11" / "bundle.py",
    _PKG_ROOT / "gate11" / "checker_set_hash.py",
    _PKG_ROOT / "gate11" / "cli.py",
    _PKG_ROOT / "gate11" / "go_signature_canonicalization.py",
    _PKG_ROOT / "gate11" / "go_verification.py",
    _PKG_ROOT / "gate11" / "manifest_schema.py",
    _PKG_ROOT / "gate11" / "module_canonicalization.py",
    _PKG_ROOT / "gate11" / "onnx_signature_canonicalization.py",
    _PKG_ROOT / "gate11" / "onnx_verification.py",
    _PKG_ROOT / "gate11" / "python_verification.py",
    _PKG_ROOT / "gate11" / "rust_manifest.py",
    _PKG_ROOT / "gate11" / "rust_signature_canonicalization.py",
    _PKG_ROOT / "gate11" / "rust_surface_extraction.py",
    _PKG_ROOT / "gate11" / "rust_verification.py",
    _PKG_ROOT / "gate11" / "self_manifest.py",
    _PKG_ROOT / "gate11" / "signature_canonicalization.py",
    _PKG_ROOT / "gate11" / "signing.py",
    _PKG_ROOT / "gate11" / "surface_extraction.py",
    _PKG_ROOT / "gate11" / "verification.py",
)


__all__ = ("PINNED_CHECKER_SOURCES_SELF",)
