# Bismillah ir-Rahman ir-Rahim
"""
CVE-2018-1000805 pattern: Paramiko SSH auth bypass.

Paramiko's server-side implementation allowed authentication bypass
when the server's check_auth_* methods raised exceptions that were
caught too broadly, allowing unauthenticated access.

furqan-lint rule mapping: MR-002 (broad except without re-raise),
MR-005 (empty except in authentication context)
"""

class VulnerableSSHServer:
    """Simplified pattern from the Paramiko auth bypass."""

    def check_channel_request(self, kind, chanid):
        return 0  # OPEN_SUCCEEDED

    def check_auth_password(self, username, password):
        """Vulnerable: broad except around auth check."""
        try:
            return self._validate_credentials(username, password)
        except Exception:
            pass  # BUG: swallowed auth error = silent bypass
            # If _validate_credentials raises (DB down, LDAP timeout),
            # this returns None, which some callers treat as success

    def check_auth_password_fixed(self, username, password):
        """Fixed: explicit error handling, deny on failure."""
        try:
            return self._validate_credentials(username, password)
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"Auth check failed: {e}")
            return -1  # AUTH_FAILED: deny on error, don't silently pass

    def _validate_credentials(self, username, password):
        raise NotImplementedError
# Bismillah ir-Rahman ir-Rahim
