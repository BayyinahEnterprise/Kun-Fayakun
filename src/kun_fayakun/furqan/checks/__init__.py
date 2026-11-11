# Bismillah ir-Rahman ir-Rahim
"""
Furqan structural honesty checks -- v2.2.0.

Each module implements one check family derived from the eight Furqan constructs.
All checks operate on Python's ast.Module -- no external dependencies required.

Eight check modules, 51 Python rules (48 active by default, 3 informational):
  ring_close       RC-001 to RC-005 (5)   Unclosed resources
  marad            MR-001/002/003/005/007/008/009 (7)   Silent failure, resource exhaustion
  trust_boundary   TB-001 to TB-003 (3, informational, off by default)
  scan_incomplete  SI-001 to SI-007 (7)   Catch-all types, blanket suppressions
  secrets          TB-004 to TB-006, TB-010 to TB-014 (8)   Eval, exec, pickle, hardcoded creds
  injection        TB-015 to TB-020, TB-027, TB-028 (8)   Shell/SQL/template/XML/ORM injection
  crypto           TB-021 to TB-026 (6)   Insecure hashing, SSL/TLS, weak random
  cve_patterns     TB-035 to TB-041, MR-008/009 (9)   CVE-derived: amplification, dunder
                   traversal, path join, security bypass, ReDoS, alg:none, dynamic import,
                   unbounded threads, unguarded recursion
"""

__version__ = "2.2.0"

from kun_fayakun.furqan.checks.ring_close import check_ring_close
from kun_fayakun.furqan.checks.marad import check_marad
from kun_fayakun.furqan.checks.trust_boundary import check_trust_boundary
from kun_fayakun.furqan.checks.scan_incomplete import check_scan_incomplete
from kun_fayakun.furqan.checks.secrets import check_secrets
from kun_fayakun.furqan.checks.injection import check_injection
from kun_fayakun.furqan.checks.crypto import check_crypto
from kun_fayakun.furqan.checks.cve_patterns import check_cve_patterns

__all__ = [
    "check_ring_close",
    "check_marad",
    "check_trust_boundary",
    "check_scan_incomplete",
    "check_secrets",
    "check_injection",
    "check_crypto",
    "check_cve_patterns",
]

# Bismillah ir-Rahman ir-Rahim
