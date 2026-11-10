# Bismillah ir-Rahman ir-Rahim
"""
CVE-2020-27619 pattern: CPython test suite eval() on HTTP content.

CPython's test suite called eval() on content received from an HTTP
server, allowing code execution if the server was malicious. CVSS 9.8.

Fixed in CPython 3.9.1, 3.8.7.

furqan-lint rule mapping: TB-005 (eval/exec on untrusted input)
"""

def fetch_and_eval_vulnerable(url):
    """Vulnerable: eval on HTTP response body."""
    import urllib.request
    response = urllib.request.urlopen(url)
    data = response.read().decode()
    # BUG: eval on untrusted network data
    return eval(data)

def fetch_and_parse_fixed(url):
    """Fixed: parse with safe methods instead of eval."""
    import urllib.request
    import json
    response = urllib.request.urlopen(url)
    data = response.read().decode()
    return json.loads(data)  # Safe: only parses JSON
# Bismillah ir-Rahman ir-Rahim
