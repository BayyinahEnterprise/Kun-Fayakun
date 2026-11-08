"""CASM v1.0 manifest schema and canonical-bytes serialization.

The CASM manifest is a JSON document whose canonical bytes
(RFC 8785) are the message Sigstore signs. Field semantics are
specified in the Phase G11.0 prompt; this module enforces them
at parse time so downstream code can rely on the manifest being
well-formed.

Top-level fields (all required unless marked OPTIONAL):

* ``casm_version``: schema version. v1.0 implementations reject
  manifests with ``casm_version != "1.0"`` (CASM-V-001).
* ``module_identity.language``: one of ``"python"`` (Phase G11.0,
  v0.10.0), ``"rust"`` (Phase G11.1, v0.11.0), ``"go"`` (Phase
  G11.2, v0.12.0), or ``"onnx"`` (Phase G11.3, v0.13.0); other
  values raise CASM-V-001.
* ``module_identity.module_path``: informational repo-relative
  path. Cryptographic identity is ``module_root_hash``.
* ``module_identity.module_root_hash``: ``"sha256:<hex64>"``.
* ``public_surface.names``: ASCII-sorted list of public-name
  entries; each has ``name``, ``kind``
  (``"function"|"class"|"constant"``), and
  ``signature_fingerprint``.
* ``public_surface.extraction_method``: identifier (v1.0 ships
  ``"ast.module-public-surface@v1.0"``).
* ``public_surface.extraction_substrate``: linter version that
  performed extraction.
* ``chain.previous_manifest_hash``: SHA-256 of the previous
  manifest's canonical JSON, or ``None`` for chain head.
* ``chain.chain_position``: 1-indexed.
* ``linter_substrate_attestation``: ``linter_name``,
  ``linter_version``, ``checker_set_hash``.
* ``trust_root``: ``trust_root_id`` plus informational
  ``fulcio_url`` and ``rekor_url``.
* ``issued_at``: ISO-8601 UTC timestamp string.

Reserved values rejected by v1.0:

* ``kind`` of ``"alias"`` or ``"module"`` (reserved for future
  use; presence is a schema violation).
* Languages other than ``"python"`` / ``"rust"`` / ``"go"`` /
  ``"onnx"`` (the complete mushaf chain after Phase G11.3
  an-Naziat v0.13.0 ship).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from furqan_lint.gate11 import CASM_VERSION


class CasmSchemaError(ValueError):
    """Raised when a CASM manifest dict fails schema validation.

    Carries a CASM-V error code as the ``code`` attribute so the
    Verifier (T08) can map the failure to the canonical error
    namespace.
    """

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


# Phase G11.1 (as-Saffat) extends the kind whitelist with Rust
# kinds. Python kinds remain unchanged: function / class / constant.
# Rust adds: struct, enum, trait, type_alias, alias.
# Go (Phase G11.2, v0.12.0) reuses the same whitelist (function /
# struct / interface / type_alias / constant map to existing kinds).
# ONNX (Phase G11.3, v0.13.0) attests graph inputs/outputs rather
# than named kinds; the kind whitelist is bypassed for
# ``language == "onnx"`` manifests (ValueInfoSummary entries are
# parsed via the ``module_identity.onnx`` nested structure).
_VALID_KINDS = frozenset(
    {
        "function",
        "class",
        "constant",
        "struct",
        "enum",
        "trait",
        "type_alias",
        "alias",
    }
)


# Phase G11.0 (Python, v0.10.0) shipped python-only. Each Phase
# G11.x release extends this tuple to its substrate; Phase G11.3
# (an-Naziat, v0.13.0) closes the canonical mushaf chain.
SUPPORTED_LANGUAGES: tuple[str, ...] = ("python", "rust", "go", "onnx")


@dataclass(frozen=True)
class ValueInfoSummary:
    """Canonical summary of one ONNX ``ValueInfo`` entry.

    Represents either a graph input or a graph output. Carries
    the symbolic / concrete dimension distinction faithfully:
    int dims are concrete (per ``dim_value``); str dims are
    symbolic (per ``dim_param``).

    Phase G11.3 (an-Naziat, v0.13.0): an-Naziat T02 introduces
    this dataclass as the canonical ONNX ValueInfo entry. The
    canonicalization rules at
    :mod:`furqan_lint.gate11.onnx_signature_canonicalization`
    (rules 9-12) consume this dataclass directly; symbolic-vs-
    concrete divergence between manifest and substrate
    ModelProto raises ``CASM-V-071``.

    Frozen to preserve manifest immutability after parse.
    """

    name: str
    dtype: str  # canonical TensorProto.DataType name (e.g., "FLOAT", "INT64")
    shape: tuple[int | str, ...]  # int = concrete dim_value; str = symbolic dim_param


@dataclass(frozen=True)
class OnnxIdentitySection:
    """Canonical ``module_identity.onnx`` nested structure.

    Present iff ``module_identity.language == "onnx"``. Captures
    the four ModelProto fields that the graph-shape canonical
    surface depends on: ``opset_imports``, ``ir_version``,
    ``inputs``, ``outputs``.

    Phase G11.3 (an-Naziat, v0.13.0): an-Naziat T02 introduces
    this dataclass. The verification path consumes it in
    :mod:`furqan_lint.gate11.onnx_verification` to enforce
    opset-policy consistency (``CASM-V-070`` on mismatch with
    substrate ModelProto's ``opset_imports``) and dim_param
    consistency (``CASM-V-071`` on symbolic-vs-concrete
    divergence).
    """

    opset_imports: tuple[tuple[str, int], ...]
    ir_version: int
    inputs: tuple[ValueInfoSummary, ...]
    outputs: tuple[ValueInfoSummary, ...]


@dataclass(frozen=True)
class PublicName:
    """One entry in ``public_surface.names``.

    Frozen to ensure manifest immutability after parse.
    """

    name: str
    kind: str
    signature_fingerprint: str

    @staticmethod
    def from_dict(data: dict[str, Any]) -> PublicName:
        if not isinstance(data, dict):
            raise CasmSchemaError("CASM-V-001", "public_surface.names entry must be a dict")
        for required in ("name", "kind", "signature_fingerprint"):
            if required not in data:
                raise CasmSchemaError(
                    "CASM-V-001",
                    f"public_surface.names entry missing field {required!r}",
                )
        kind = data["kind"]
        if kind not in _VALID_KINDS:
            raise CasmSchemaError(
                "CASM-V-001",
                f"public_surface.names entry has unsupported kind {kind!r}; "
                f"v1.0 supports {sorted(_VALID_KINDS)}",
            )
        return PublicName(
            name=str(data["name"]),
            kind=kind,
            signature_fingerprint=str(data["signature_fingerprint"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "signature_fingerprint": self.signature_fingerprint,
        }


@dataclass(frozen=True)
class Manifest:
    """CASM v1.0 manifest.

    Frozen dataclass so the canonical-bytes path cannot be
    accidentally invalidated by post-parse mutation.
    """

    casm_version: str
    module_identity: dict[str, Any]
    public_surface: dict[str, Any]
    chain: dict[str, Any]
    linter_substrate_attestation: dict[str, Any]
    trust_root: dict[str, Any]
    issued_at: str

    @staticmethod
    def from_dict(data: dict[str, Any]) -> Manifest:  # noqa: PLR0915
        """Parse and validate a CASM manifest dict.

        Raises ``CasmSchemaError`` with code ``CASM-V-001`` on
        unsupported version or language; with ``CASM-V-001``
        also on missing top-level fields or reserved
        ``kind`` values.
        """
        if not isinstance(data, dict):
            raise CasmSchemaError("CASM-V-001", "manifest must be a dict at top level")
        version = data.get("casm_version")
        if version != CASM_VERSION:
            raise CasmSchemaError(
                "CASM-V-001",
                f"unsupported casm_version {version!r}; "
                f"v1.0 implementations require {CASM_VERSION!r}",
            )
        required = (
            "module_identity",
            "public_surface",
            "chain",
            "linter_substrate_attestation",
            "trust_root",
            "issued_at",
        )
        for k in required:
            if k not in data:
                raise CasmSchemaError(
                    "CASM-V-001",
                    f"manifest missing required top-level field {k!r}",
                )
        module_identity = data["module_identity"]
        if not isinstance(module_identity, dict):
            raise CasmSchemaError("CASM-V-001", "module_identity must be a dict")
        for k in ("language", "module_path", "module_root_hash"):
            if k not in module_identity:
                raise CasmSchemaError(
                    "CASM-V-001",
                    f"module_identity missing field {k!r}",
                )
        language = module_identity["language"]
        # Phase G11.1 (as-Saffat) extended accepted languages
        # to include "rust"; Phase G11.2 (al-Mursalat, v0.12.0)
        # extended to "go"; Phase G11.3 (an-Naziat, v0.13.0)
        # extends to "onnx" -- closing the canonical mushaf
        # chain. No further Phase G11.x language extensions
        # are anticipated; Phase G11.4 Tasdiq al-Bayan
        # operates against this surface as a drift-detection
        # invariant rather than adding entries.
        if language not in SUPPORTED_LANGUAGES:
            raise CasmSchemaError(
                "CASM-V-001",
                f"v1.0 supports only language in {SUPPORTED_LANGUAGES!r}; " f"got {language!r}.",
            )
        module_root_hash = module_identity["module_root_hash"]
        if not isinstance(module_root_hash, str) or not module_root_hash.startswith("sha256:"):
            raise CasmSchemaError(
                "CASM-V-001",
                "module_root_hash must be the string 'sha256:<hex64>'",
            )
        public_surface = data["public_surface"]
        if not isinstance(public_surface, dict):
            raise CasmSchemaError("CASM-V-001", "public_surface must be a dict")
        for k in ("names", "extraction_method", "extraction_substrate"):
            if k not in public_surface:
                raise CasmSchemaError(
                    "CASM-V-001",
                    f"public_surface missing field {k!r}",
                )
        names = public_surface["names"]
        if not isinstance(names, list):
            raise CasmSchemaError("CASM-V-001", "public_surface.names must be a list")
        # Validate each name; reserved kinds raise here.
        for entry in names:
            PublicName.from_dict(entry)
        # ASCII-sorted requirement: enforce so the canonical-bytes
        # path is deterministic at the manifest level too.
        sorted_names = sorted([e["name"] for e in names])
        actual_names = [e["name"] for e in names]
        if sorted_names != actual_names:
            raise CasmSchemaError(
                "CASM-V-001",
                "public_surface.names must be ASCII-sorted by name; " "got out-of-order entries",
            )
        chain = data["chain"]
        if not isinstance(chain, dict):
            raise CasmSchemaError("CASM-V-001", "chain must be a dict")
        for k in ("previous_manifest_hash", "chain_position"):
            if k not in chain:
                raise CasmSchemaError("CASM-V-001", f"chain missing field {k!r}")
        cp = chain["chain_position"]
        if not isinstance(cp, int) or cp < 1:
            raise CasmSchemaError(
                "CASM-V-001",
                "chain.chain_position must be a 1-indexed integer",
            )
        prev = chain["previous_manifest_hash"]
        if prev is not None and not (isinstance(prev, str) and prev.startswith("sha256:")):
            raise CasmSchemaError(
                "CASM-V-001",
                "chain.previous_manifest_hash must be None or " "'sha256:<hex64>'",
            )
        attest = data["linter_substrate_attestation"]
        if not isinstance(attest, dict):
            raise CasmSchemaError("CASM-V-001", "linter_substrate_attestation must be a dict")
        for k in ("linter_name", "linter_version", "checker_set_hash"):
            if k not in attest:
                raise CasmSchemaError(
                    "CASM-V-001",
                    f"linter_substrate_attestation missing field {k!r}",
                )
        # Phase G11.1 audit H-6 propagation defense:
        # checker_set_hash MUST be either "sha256:<hex64>"
        # (Form A, substantive hash over actual checker source)
        # OR "placeholder:sha256:<hex64>" (Form B, explicit
        # placeholder for v0.11.x patch releases pending the
        # Phase G11.0.1 corrective release that closes the H-6
        # finding in the Python verifier). Bare-string
        # placeholders dressed as real hashes (the v0.10.0
        # ship's failure mode) are NOT accepted.
        csh = attest["checker_set_hash"]
        if not isinstance(csh, str) or not (
            csh.startswith("sha256:") or csh.startswith("placeholder:sha256:")
        ):
            raise CasmSchemaError(
                "CASM-V-001",
                "linter_substrate_attestation.checker_set_hash must "
                "be 'sha256:<hex64>' (Form A, substantive) or "
                "'placeholder:sha256:<hex64>' (Form B, explicit "
                "placeholder); got "
                f"{csh!r}",
            )
        trust_root = data["trust_root"]
        if not isinstance(trust_root, dict):
            raise CasmSchemaError("CASM-V-001", "trust_root must be a dict")
        if "trust_root_id" not in trust_root:
            raise CasmSchemaError(
                "CASM-V-001",
                "trust_root.trust_root_id is required",
            )
        return Manifest(
            casm_version=str(version),
            module_identity=dict(module_identity),
            public_surface=dict(public_surface),
            chain=dict(chain),
            linter_substrate_attestation=dict(attest),
            trust_root=dict(trust_root),
            issued_at=str(data["issued_at"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "casm_version": self.casm_version,
            "module_identity": dict(self.module_identity),
            "public_surface": dict(self.public_surface),
            "chain": dict(self.chain),
            "linter_substrate_attestation": dict(self.linter_substrate_attestation),
            "trust_root": dict(self.trust_root),
            "issued_at": self.issued_at,
        }

    def to_canonical_bytes(self) -> bytes:
        """Serialize via RFC 8785 JSON canonical form.

        These bytes are the message Sigstore signs in T06 and the
        message the Verifier (T08) feeds into bundle verification.
        Determinism is load-bearing: any two equivalent manifests
        (modulo key-order in inner dicts) must produce identical
        bytes.
        """
        import rfc8785

        # rfc8785 canonicalizes dict-key order, normalizes whitespace,
        # uses ECMAScript JSON number formatting, and emits UTF-8
        # bytes. We delegate fully rather than hand-rolling.
        return rfc8785.dumps(self.to_dict())


__all__ = (
    "SUPPORTED_LANGUAGES",
    "CasmSchemaError",
    "Manifest",
    "OnnxIdentitySection",
    "PublicName",
    "ValueInfoSummary",
)
