# Bismillah ir-Rahman ir-Rahim
"""
CVE-2017-1000433 pattern: pysaml2 assert-based auth bypass.

pysaml2's _verify() used assert to validate passwords. Running Python
with -O stripped the assert, accepting any password. CVSS 8.1.

Fixed in pysaml2 4.5.0.

furqan-lint rule mapping: SI-006 (assert used for validation)
"""

def _verify_vulnerable(password, expected_hash):
    """Vulnerable: assert for password validation."""
    computed = hash_password(password)
    assert computed == expected_hash  # BUG: stripped by python -O
    return True

def _verify_fixed(password, expected_hash):
    """Fixed: explicit check that survives optimization."""
    computed = hash_password(password)
    if computed != expected_hash:
        raise ValueError("Password verification failed")
    return True

def hash_password(pw):
    import hashlib
    return hashlib.sha256(pw.encode()).hexdigest()
# Bismillah ir-Rahman ir-Rahim
