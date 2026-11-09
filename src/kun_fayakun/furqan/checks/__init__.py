# Bismillah ir-Rahman ir-Rahim
"""
Furqan structural honesty checks.

Each module implements one check family derived from the eight Furqan constructs.
All checks operate on Python's ast.Module -- no external dependencies required.

Seven check modules, 37 rules total:
  ring_close       RC-001 to RC-005   Unclosed resources
  marad            MR-001 to MR-007   Silent failure / swallowed exceptions
  trust_boundary   TB-001 to TB-006   Type confusion at trust boundaries
  scan_incomplete  SI-001 to SI-007   Catch-all types, blanket suppressions
  secrets          TB-010 to TB-014   Hardcoded credentials, debug mode
  injection        TB-015 to TB-020   Shell/SQL/template injection
  crypto           TB-021 to TB-025   Insecure hashing, SSL/TLS misconfig
"""

from kun_fayakun.furqan.checks.ring_close import check_ring_close
from kun_fayakun.furqan.checks.marad import check_marad
from kun_fayakun.furqan.checks.trust_boundary import check_trust_boundary
from kun_fayakun.furqan.checks.scan_incomplete import check_scan_incomplete
from kun_fayakun.furqan.checks.secrets import check_secrets
from kun_fayakun.furqan.checks.injection import check_injection
from kun_fayakun.furqan.checks.crypto import check_crypto

__all__ = [
    "check_ring_close",
    "check_marad",
    "check_trust_boundary",
    "check_scan_incomplete",
    "check_secrets",
    "check_injection",
    "check_crypto",
]

# Bismillah ir-Rahman ir-Rahim
