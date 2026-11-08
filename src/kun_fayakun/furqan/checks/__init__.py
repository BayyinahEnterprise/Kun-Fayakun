# Bismillah ir-Rahman ir-Rahim
"""
Furqan structural honesty checks.

Each module implements one check family derived from the eight Furqan constructs.
All checks operate on Python's ast.Module -- no external dependencies required.
"""

from kun_fayakun.furqan.checks.ring_close import check_ring_close
from kun_fayakun.furqan.checks.marad import check_marad
from kun_fayakun.furqan.checks.trust_boundary import check_trust_boundary
from kun_fayakun.furqan.checks.scan_incomplete import check_scan_incomplete

__all__ = [
    "check_ring_close",
    "check_marad",
    "check_trust_boundary",
    "check_scan_incomplete",
]

# Bismillah ir-Rahman ir-Rahim
