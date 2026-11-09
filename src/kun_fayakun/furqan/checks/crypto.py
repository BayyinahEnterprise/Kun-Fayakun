# Bismillah ir-Rahman ir-Rahim
"""
CRYPTO checks: insecure hashing, SSL/TLS misconfigurations.

Trust-boundary violations where cryptographic protections are
weakened or bypassed.

Rules:
    TB-021  Insecure hash function (MD5, SHA1) for non-checksum use
    TB-022  requests verify=False (SSL verification disabled)
    TB-023  SSL context with check_hostname=False
    TB-024  SSL context with CERT_NONE (no certificate verification)
    TB-025  SSL/TLS insecure protocol version
"""

from __future__ import annotations

import ast
from typing import List

from kun_fayakun.furqan.checks.finding import Finding, Fix, Severity

# Weak hash algorithms
_WEAK_HASHES = {"md5", "sha1", "md4", "md2", "sha"}


def check_crypto(tree: ast.Module, path: str) -> List[Finding]:
    """Run all crypto/SSL checks."""
    findings: List[Finding] = []
    findings.extend(_check_insecure_hash(tree, path))
    findings.extend(_check_requests_verify_false(tree, path))
    findings.extend(_check_ssl_no_check_hostname(tree, path))
    findings.extend(_check_ssl_cert_none(tree, path))
    findings.extend(_check_ssl_insecure_version(tree, path))
    return findings


def _check_insecure_hash(tree: ast.Module, path: str) -> List[Finding]:
    """TB-021: hashlib.md5() or hashlib.sha1() -- weak for security use."""
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name = _get_call_name(node)
        if not func_name:
            continue
        # hashlib.md5(), hashlib.sha1()
        if func_name.startswith("hashlib."):
            algo = func_name.split(".")[-1].lower()
            if algo in _WEAK_HASHES:
                # Check for usedforsecurity=False (Python 3.9+ safe marker)
                is_marked_safe = False
                for kw in node.keywords:
                    if kw.arg == "usedforsecurity":
                        if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                            is_marked_safe = True
                if not is_marked_safe:
                    findings.append(Finding(
                        rule="TB-021",
                        path=path,
                        line=node.lineno,
                        col=node.col_offset,
                        message=f"Insecure hash `{algo}` -- weak against collision attacks",
                        severity=Severity.MEDIUM,
                        fix=Fix.RECALIBRATE,
                        detail="MD5 and SHA1 are broken for security purposes (signatures, "
                               "password hashing, integrity proofs). Use SHA-256 or better. "
                               "If this is a non-security checksum, pass usedforsecurity=False.",
                    ))
        # hashlib.new("md5")
        if func_name in ("hashlib.new", "new") and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if arg.value.lower() in _WEAK_HASHES:
                    is_marked_safe = False
                    for kw in node.keywords:
                        if kw.arg == "usedforsecurity":
                            if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                                is_marked_safe = True
                    if not is_marked_safe:
                        findings.append(Finding(
                            rule="TB-021",
                            path=path,
                            line=node.lineno,
                            col=node.col_offset,
                            message=f"Insecure hash `{arg.value}` via hashlib.new()",
                            severity=Severity.MEDIUM,
                            fix=Fix.RECALIBRATE,
                            detail="MD5 and SHA1 are broken for security purposes. "
                                   "Use SHA-256 or better. If non-security, pass "
                                   "usedforsecurity=False.",
                        ))
    return findings


def _check_requests_verify_false(tree: ast.Module, path: str) -> List[Finding]:
    """TB-022: requests.get/post/etc with verify=False."""
    findings: List[Finding] = []
    _http_methods = {"get", "post", "put", "patch", "delete", "head", "options", "request"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name = _get_call_name(node)
        if not func_name:
            continue
        method = func_name.split(".")[-1].lower()
        if method in _http_methods:
            for kw in node.keywords:
                if kw.arg == "verify":
                    if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        findings.append(Finding(
                            rule="TB-022",
                            path=path,
                            line=node.lineno,
                            col=node.col_offset,
                            message="SSL verification disabled with verify=False",
                            severity=Severity.HIGH,
                            fix=Fix.RECALIBRATE,
                            detail="Disabling SSL verification allows man-in-the-middle "
                                   "attacks. If you need to trust a custom CA, pass the "
                                   "CA bundle path to verify= instead of False.",
                        ))
    return findings


def _check_ssl_no_check_hostname(tree: ast.Module, path: str) -> List[Finding]:
    """TB-023: ssl context with check_hostname = False."""
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (isinstance(target, ast.Attribute)
                        and target.attr == "check_hostname"
                        and isinstance(node.value, ast.Constant)
                        and node.value.value is False):
                    findings.append(Finding(
                        rule="TB-023",
                        path=path,
                        line=node.lineno,
                        col=node.col_offset,
                        message="SSL check_hostname disabled -- hostname verification bypassed",
                        severity=Severity.HIGH,
                        fix=Fix.RECALIBRATE,
                        detail="Disabling hostname verification means the certificate's "
                               "subject is not checked against the server hostname, "
                               "enabling man-in-the-middle attacks.",
                    ))
    return findings


def _check_ssl_cert_none(tree: ast.Module, path: str) -> List[Finding]:
    """TB-024: ssl.CERT_NONE (no certificate verification)."""
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Attribute) and target.attr == "verify_mode":
                    val = node.value
                    # ssl.CERT_NONE or CERT_NONE
                    if isinstance(val, ast.Attribute) and val.attr == "CERT_NONE":
                        findings.append(Finding(
                            rule="TB-024",
                            path=path,
                            line=node.lineno,
                            col=node.col_offset,
                            message="SSL verify_mode set to CERT_NONE -- no certificate verification",
                            severity=Severity.HIGH,
                            fix=Fix.RECALIBRATE,
                            detail="CERT_NONE means the server's certificate is not "
                                   "verified at all. Use CERT_REQUIRED with a proper "
                                   "CA bundle.",
                        ))
                    if isinstance(val, ast.Name) and val.id == "CERT_NONE":
                        findings.append(Finding(
                            rule="TB-024",
                            path=path,
                            line=node.lineno,
                            col=node.col_offset,
                            message="SSL verify_mode set to CERT_NONE",
                            severity=Severity.HIGH,
                            fix=Fix.RECALIBRATE,
                            detail="CERT_NONE disables certificate verification entirely. "
                                   "Use ssl.CERT_REQUIRED.",
                        ))
    return findings


def _check_ssl_insecure_version(tree: ast.Module, path: str) -> List[Finding]:
    """TB-025: Insecure SSL/TLS protocol version."""
    findings: List[Finding] = []
    _insecure_protocols = {
        "PROTOCOL_SSLv2", "PROTOCOL_SSLv3", "PROTOCOL_SSLv23",
        "PROTOCOL_TLS",  # allows negotiation down to old versions
        "PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in _insecure_protocols:
            findings.append(Finding(
                rule="TB-025",
                path=path,
                line=node.lineno,
                col=node.col_offset,
                message=f"Insecure SSL/TLS protocol: {node.attr}",
                severity=Severity.HIGH,
                fix=Fix.RECALIBRATE,
                detail="SSLv2, SSLv3, TLSv1.0 and TLSv1.1 have known vulnerabilities. "
                       "Use ssl.PROTOCOL_TLS_CLIENT (Python 3.6+) which negotiates "
                       "the highest available TLS version with proper defaults.",
            ))
    return findings


def _get_call_name(node: ast.Call) -> str | None:
    """Extract dotted name from a Call node."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts = []
        current = func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            return ".".join(reversed(parts))
    return None


# Bismillah ir-Rahman ir-Rahim
