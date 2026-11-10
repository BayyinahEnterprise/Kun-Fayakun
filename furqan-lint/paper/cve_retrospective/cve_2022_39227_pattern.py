# Bismillah ir-Rahman ir-Rahim
"""
CVE-2022-39227 pattern: python-jwt token verification bypass.

An attacker could craft a JWT that bypasses signature verification.
The root cause involved exception handling during verification
where certain error conditions were silently swallowed.

furqan-lint rule mapping: MR-005 (empty except in auth context),
MR-002 (broad except without re-raise)
"""

import json
import hmac
import hashlib
import base64

def verify_token_vulnerable(token, secret):
    """Vulnerable pattern: broad exception swallows verification failure."""
    parts = token.split('.')
    if len(parts) != 3:
        return None
    header, payload, signature = parts
    try:
        expected_sig = hmac.new(
            secret.encode(),
            f"{header}.{payload}".encode(),
            hashlib.sha256
        ).digest()
        decoded_sig = base64.urlsafe_b64decode(signature + '==')
        if hmac.compare_digest(expected_sig, decoded_sig):
            return json.loads(base64.urlsafe_b64decode(payload + '=='))
    except Exception:
        pass  # BUG: swallowed verification error returns None
              # but caller may treat None differently than explicit reject
    return None

def verify_token_safe(token, secret):
    """Fixed: explicit error handling, no silent swallowing."""
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Malformed JWT: expected 3 parts")
    header, payload, signature = parts
    try:
        expected_sig = hmac.new(
            secret.encode(),
            f"{header}.{payload}".encode(),
            hashlib.sha256
        ).digest()
        decoded_sig = base64.urlsafe_b64decode(signature + '==')
    except Exception as e:
        raise ValueError(f"JWT decode failed: {e}") from e
    if not hmac.compare_digest(expected_sig, decoded_sig):
        raise ValueError("JWT signature mismatch")
    return json.loads(base64.urlsafe_b64decode(payload + '=='))
# Bismillah ir-Rahman ir-Rahim
