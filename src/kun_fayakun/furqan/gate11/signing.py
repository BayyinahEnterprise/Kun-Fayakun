"""OIDC-keyed Sigstore signing for CASM manifests (T06).

Wraps sigstore-python's high-level signing API to sign the
canonical bytes of a ``Manifest``. Returns a Sigstore ``Bundle``
object that callers (T07) serialize to ``.furqan.manifest.sigstore``.

Identity sources:

* explicit ``IdentityToken`` passed by the caller
* ambient OIDC in CI (e.g., ``GITHUB_ACTIONS``) via
  ``sigstore.oidc.detect_credential``
* interactive OIDC device flow via ``sigstore.oidc.Issuer.production().identity_token()``

This module imports ``sigstore`` lazily so importing
``furqan_lint.gate11.signing`` does not pull the dependency
unless the [gate11] extra is installed.

Network-bound: the signing path requires a live Fulcio + Rekor
deployment. Unit tests do not exercise this path. The smoke
test ``tests/test_gate11_signing.py`` is gated by the
``FURQAN_LINT_GATE11_SMOKE_TEST`` environment variable and
runs in CI on push to ``main`` only.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from furqan_lint.gate11.manifest_schema import Manifest

if TYPE_CHECKING:
    from sigstore.models import Bundle


class SigningExtrasNotInstalled(ImportError):
    """Raised when [gate11] extra is missing.

    Subclass of ``ImportError`` so callers that catch
    ``ImportError`` behave correctly. Mirrors the
    OnnxExtrasNotInstalled / OnnxRuntimeExtrasNotInstalled /
    OnnxProfileExtrasNotInstalled pattern from the v0.9.x
    extras.
    """


def _resolve_identity_token(identity_token: Any | None) -> Any:
    """Return a sigstore.oidc.IdentityToken.

    Priority:

    1. caller-supplied token (already an IdentityToken)
    2. ambient OIDC in CI via detect_credential
    3. interactive OIDC device flow
    """
    try:
        from sigstore.oidc import IdentityToken, Issuer, detect_credential
    except ImportError as e:
        raise SigningExtrasNotInstalled(
            "Gate 11 signing requires the [gate11] extra: " "pip install furqan-lint[gate11]"
        ) from e

    if identity_token is not None:
        if isinstance(identity_token, IdentityToken):
            return identity_token
        # Caller passed a raw token string; wrap it.
        return IdentityToken(str(identity_token))

    if os.environ.get("GITHUB_ACTIONS") == "true":
        token = detect_credential()
        if token is not None:
            return IdentityToken(token)

    issuer = Issuer.production()
    return issuer.identity_token()


def sign_manifest(manifest: Manifest, identity_token: Any | None = None) -> Bundle:
    """Sign ``manifest.to_canonical_bytes()`` and return a Sigstore Bundle.

    The bundle is the data structure T07 serializes to
    ``.furqan.manifest.sigstore``.
    """
    try:
        from sigstore.sign import SigningContext
    except ImportError as e:
        raise SigningExtrasNotInstalled(
            "Gate 11 signing requires the [gate11] extra: " "pip install furqan-lint[gate11]"
        ) from e

    canonical = manifest.to_canonical_bytes()
    token = _resolve_identity_token(identity_token)
    ctx = SigningContext.production()
    with ctx.signer(token) as signer:
        # sign_artifact accepts bytes directly per sigstore-python
        # 3.x. canonical is the RFC 8785 message bytes.
        return signer.sign_artifact(canonical)


__all__ = (
    "SigningExtrasNotInstalled",
    "sign_manifest",
)
