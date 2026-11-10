# Bismillah ir-Rahman ir-Rahim
"""
CVE-2024-35195 pattern: requests Session verify bypass.

The vulnerable pattern: a Session used with verify=False creates a pooled
connection that persists verify=False for subsequent requests, even when
verify=True is set later. The root cause is connection reuse without
resetting TLS state.

furqan-lint rule mapping: RC-003 (connection/session not closed)
The Session object holds pooled connections that leak TLS state.
"""

import requests

def fetch_internal_then_external(internal_url, external_url):
    """Vulnerable pattern from CVE-2024-35195."""
    session = requests.Session()
    # First request: internal service, skip cert verify
    session.get(internal_url, verify=False)
    # Second request: external service, should verify cert
    # BUG: pooled connection from first request reuses verify=False
    response = session.get(external_url, verify=True)
    return response
    # Session never closed -- pooled connections persist

def fetch_with_cleanup(internal_url, external_url):
    """Fixed pattern: close session between trust contexts."""
    with requests.Session() as session:
        session.get(internal_url, verify=False)
    # Session closed, pool drained
    with requests.Session() as session:
        response = session.get(external_url, verify=True)
        return response
# Bismillah ir-Rahman ir-Rahim
