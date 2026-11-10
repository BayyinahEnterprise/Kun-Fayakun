# Bismillah ir-Rahman ir-Rahim
"""
CVE-2024-45231 pattern: Django password reset server error info leak.

When an email backend raised an exception during password reset,
Django's broad exception handling exposed server error details
to the attacker, confirming email existence.

furqan-lint rule mapping: MR-002 (broad except without re-raise),
MR-005 (empty except block)
"""

class PasswordResetView:
    """Simplified pattern from the vulnerable Django code."""

    def send_reset_email(self, email):
        """Vulnerable: broad except leaks timing/error info."""
        try:
            self._send_mail(email)
        except Exception:
            pass  # BUG: swallows send failure silently
            # Attacker can distinguish "email exists but send failed"
            # from "email doesn't exist" via response timing/status

    def send_reset_email_fixed(self, email):
        """Fixed: consistent behavior regardless of send outcome."""
        try:
            self._send_mail(email)
        except Exception:
            # Log internally but don't change user-facing response
            import logging
            logging.getLogger(__name__).exception("Password reset email failed")
            raise  # Let the view handle the error consistently

    def _send_mail(self, email):
        raise NotImplementedError
# Bismillah ir-Rahman ir-Rahim
