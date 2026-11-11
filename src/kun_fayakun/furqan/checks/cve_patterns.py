# Bismillah ir-Rahman ir-Rahim
"""
CVE-derived pattern checks: rules targeting vulnerability patterns observed
in real-world CVEs that no existing linter catches.

These rules were added after the CVE validation study (Paper 3) showed that
9 of 19 triple-MISS CVEs had AST-reachable root causes.

Rules:
    TB-035  Unbounded repr/format in exception message (amplification DoS)
    TB-036  Unguarded dunder attribute access from external input
    TB-037  os.path.join without basename sanitization on untrusted input
    TB-038  Hardcoded security-bypass parameter (trust_remote_code, verify=False)
    TB-039  Catastrophic backtracking regex pattern (ReDoS)
    TB-040  JWT alg:none in algorithm allowlist
    TB-041  Unrestricted importlib.import_module from untrusted input
    MR-008  Unbounded thread/process creation without pool
    MR-009  Recursive function call without depth guard
"""

from __future__ import annotations

import ast
import re
from typing import List

from kun_fayakun.furqan.checks.finding import Finding, Fix, Severity


def check_cve_patterns(tree: ast.Module, source: str, path: str) -> List[Finding]:
    """Run all CVE-derived pattern checks on an AST."""
    findings: List[Finding] = []
    findings.extend(_check_exception_amplification(tree, path))
    findings.extend(_check_dunder_traversal(tree, path))
    findings.extend(_check_path_join_unsanitized(tree, path))
    findings.extend(_check_hardcoded_security_bypass(tree, path))
    findings.extend(_check_redos_patterns(tree, source, path))
    findings.extend(_check_jwt_alg_none(tree, path))
    findings.extend(_check_unrestricted_import(tree, path))
    findings.extend(_check_unbounded_thread_creation(tree, path))
    findings.extend(_check_recursive_no_depth(tree, source, path))
    return findings


# ============================================================================
# TB-035: Unbounded repr/format in exception message
# CVE-2025-65015 (joserfc): ExceededSizeError interpolates {header!r}
# ============================================================================

def _check_exception_amplification(tree: ast.Module, path: str) -> List[Finding]:
    """TB-035: f-string or format with repr/str of variable in raise statement.

    Pattern: raise SomeError(f"...{variable!r}...") or f"...{variable}..."
    where variable could be attacker-controlled input. The repr of a large
    bytestring amplifies into the exception message, log, and traceback.
    """
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Raise) and node.exc is not None:
            # Check if the exception is constructed with an f-string
            exc = node.exc
            if isinstance(exc, ast.Call) and exc.args:
                for arg in exc.args:
                    if isinstance(arg, ast.JoinedStr):
                        # f-string in exception -- check for !r or !s conversions
                        for val in arg.values:
                            if isinstance(val, ast.FormattedValue):
                                if val.conversion in (ord('r'), ord('s')):
                                    findings.append(Finding(
                                        rule="TB-035",
                                        path=path,
                                        line=node.lineno,
                                        col=node.col_offset,
                                        message="Exception message interpolates repr/str of variable -- unbounded amplification risk",
                                        severity=Severity.MEDIUM,
                                        fix=Fix.RECALIBRATE,
                                        detail="f-string with !r or !s conversion in a raise statement "
                                               "can amplify attacker-controlled input into exception messages, "
                                               "logs, and tracebacks. Truncate or hash the value instead.",
                                    ))
                                    break
                                elif val.conversion == -1:
                                    # Plain interpolation without conversion -- still risky
                                    # but only flag if it looks like a parameter name
                                    if isinstance(val.value, ast.Name):
                                        findings.append(Finding(
                                            rule="TB-035",
                                            path=path,
                                            line=node.lineno,
                                            col=node.col_offset,
                                            message="Exception message interpolates variable -- potential amplification if input is unbounded",
                                            severity=Severity.LOW,
                                            fix=Fix.RECALIBRATE,
                                            detail="Variable interpolated into exception message via f-string. "
                                                   "If the variable holds attacker-controlled data, the exception "
                                                   "message, log entry, and traceback could grow unboundedly.",
                                        ))
                                        break
    return findings


# ============================================================================
# TB-036: Unguarded dunder attribute access
# CVE-2025-58367 (deepdiff): Delta paths traverse __dunder__ attributes
# ============================================================================

def _check_dunder_traversal(tree: ast.Module, path: str) -> List[Finding]:
    """TB-036: getattr/setattr/delattr with a string that could contain dunders.

    Pattern: getattr(obj, attacker_string) without checking for __
    This enables class pollution and potentially RCE.
    """
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in ("getattr", "setattr", "delattr") and len(node.args) >= 2:
                attr_arg = node.args[1]
                # If the attribute name is a variable (not a string literal), flag it
                if isinstance(attr_arg, ast.Name):
                    findings.append(Finding(
                        rule="TB-036",
                        path=path,
                        line=node.lineno,
                        col=node.col_offset,
                        message=f"{node.func.id}() with variable attribute name -- dunder traversal risk",
                        severity=Severity.HIGH,
                        fix=Fix.RECALIBRATE,
                        detail=f"{node.func.id}(obj, variable) where the attribute name comes from a "
                               "variable. If the variable is attacker-influenced, double-underscore "
                               "attributes (__class__, __init__, __globals__) become reachable, "
                               "enabling class pollution or code execution. Validate against an "
                               "allowlist or reject names starting with '__'.",
                    ))
                # Also flag subscript access: getattr(obj, parts[i])
                elif isinstance(attr_arg, ast.Subscript):
                    findings.append(Finding(
                        rule="TB-036",
                        path=path,
                        line=node.lineno,
                        col=node.col_offset,
                        message=f"{node.func.id}() with dynamic attribute from sequence -- dunder traversal risk",
                        severity=Severity.HIGH,
                        fix=Fix.RECALIBRATE,
                        detail=f"{node.func.id}(obj, seq[idx]) where the attribute comes from indexed "
                               "data. If the sequence is attacker-controlled, dunder attributes "
                               "become reachable.",
                    ))
    return findings


# ============================================================================
# TB-037: os.path.join without basename sanitization
# CVE-2025-67720 (pyrofork): path traversal via unsanitized filename
# ============================================================================

def _check_path_join_unsanitized(tree: ast.Module, path: str) -> List[Finding]:
    """TB-037: os.path.join where the last component is a variable.

    Pattern: os.path.join(base_dir, user_filename) without os.path.basename()
    Enables path traversal if user_filename contains '../'.
    """
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            # Match os.path.join(...)
            is_path_join = False
            if isinstance(func, ast.Attribute) and func.attr == "join":
                if isinstance(func.value, ast.Attribute) and func.value.attr == "path":
                    if isinstance(func.value.value, ast.Name) and func.value.value.id == "os":
                        is_path_join = True
            # Also match Path(...) / variable
            if not is_path_join:
                continue

            if len(node.args) >= 2:
                last_arg = node.args[-1]
                # Flag if last argument is a variable (not a literal)
                if isinstance(last_arg, (ast.Name, ast.Attribute, ast.Subscript)):
                    findings.append(Finding(
                        rule="TB-037",
                        path=path,
                        line=node.lineno,
                        col=node.col_offset,
                        message="os.path.join with variable filename -- path traversal risk without basename()",
                        severity=Severity.HIGH,
                        fix=Fix.RECALIBRATE,
                        detail="os.path.join(base, variable) where the filename comes from a "
                               "variable. If the variable is attacker-controlled (e.g. from "
                               "network metadata), '../' sequences enable path traversal. "
                               "Apply os.path.basename() to the untrusted component.",
                    ))
    return findings


# ============================================================================
# TB-038: Hardcoded security-bypass parameter
# CVE-2026-27893 (vllm): trust_remote_code=True hardcoded
# ============================================================================

_SECURITY_BYPASS_KWARGS = {
    "trust_remote_code": True,
    "verify": False,
    "check_hostname": False,
    "verify_ssl": False,
    "ssl_verify": False,
    "validate_certs": False,
}

def _check_hardcoded_security_bypass(tree: ast.Module, path: str) -> List[Finding]:
    """TB-038: Keyword argument that disables a security check, hardcoded.

    Pattern: func(trust_remote_code=True) or func(verify=False)
    These override user security settings with insecure defaults.
    """
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg in _SECURITY_BYPASS_KWARGS:
                    expected = _SECURITY_BYPASS_KWARGS[kw.arg]
                    if isinstance(kw.value, ast.Constant) and kw.value.value == expected:
                        findings.append(Finding(
                            rule="TB-038",
                            path=path,
                            line=node.lineno,
                            col=node.col_offset,
                            message=f"Hardcoded {kw.arg}={expected} -- security check disabled",
                            severity=Severity.HIGH,
                            fix=Fix.RECALIBRATE,
                            detail=f"The keyword argument {kw.arg}={expected} is hardcoded, "
                                   "disabling a security check. If this overrides a user-configurable "
                                   "setting, it creates a security bypass. Use the caller's "
                                   "configuration instead of a hardcoded value.",
                        ))
    return findings


# ============================================================================
# TB-039: Catastrophic backtracking regex (ReDoS)
# CVE-2025-3264 (transformers): regex with nested quantifiers
# ============================================================================

# Patterns that suggest ReDoS vulnerability: nested quantifiers
_REDOS_INDICATORS = re.compile(
    r'(?:'
    r'\([^)]*[+*][^)]*\)[+*]'  # (a+)+ or (a*)*
    r'|'
    r'\.[+*].*\.[+*]'           # .*....*
    r'|'
    r'(?:\[[^\]]+\][+*]){2}'    # [a-z]+[a-z]+
    r')'
)

def _check_redos_patterns(tree: ast.Module, source: str, path: str) -> List[Finding]:
    """TB-039: Regular expression with nested quantifiers suggesting ReDoS.

    Pattern: re.compile("(a+)+") or similar nested-quantifier constructs.
    """
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            # Match re.compile(), re.search(), re.match(), re.sub(), re.findall()
            is_re_call = False
            if isinstance(func, ast.Attribute) and func.attr in (
                "compile", "search", "match", "sub", "findall", "finditer", "fullmatch"
            ):
                if isinstance(func.value, ast.Name) and func.value.id == "re":
                    is_re_call = True

            if is_re_call and node.args:
                pattern_node = node.args[0]
                pattern_str = None
                if isinstance(pattern_node, ast.Constant) and isinstance(pattern_node.value, str):
                    pattern_str = pattern_node.value
                elif isinstance(pattern_node, ast.JoinedStr):
                    # f-string patterns -- skip, can't analyze statically
                    continue

                if pattern_str and _REDOS_INDICATORS.search(pattern_str):
                    # Check for DOTALL-like patterns too
                    findings.append(Finding(
                        rule="TB-039",
                        path=path,
                        line=node.lineno,
                        col=node.col_offset,
                        message="Regex pattern with nested quantifiers -- potential ReDoS",
                        severity=Severity.HIGH,
                        fix=Fix.RECALIBRATE,
                        detail=f"The regex pattern contains nested quantifiers that may cause "
                               "catastrophic backtracking on crafted input. Consider rewriting "
                               "with atomic groups, possessive quantifiers (regex module), "
                               "or replacing with a non-regex parser.",
                    ))
    return findings


# ============================================================================
# TB-040: JWT alg:none in algorithm allowlist
# CVE-2026-28802 (Authlib): default JWT helper permits alg:none
# ============================================================================

def _check_jwt_alg_none(tree: ast.Module, path: str) -> List[Finding]:
    """TB-040: String 'none' in a list/set/tuple assigned to an algorithms variable.

    Pattern: algorithms = ["HS256", "none"] or ALGORITHMS = {..., "none", ...}
    Allowing alg:none in JWT verification lets unsigned tokens bypass signature checks.
    """
    findings: List[Finding] = []
    for node in ast.walk(tree):
        # Check assignments where the value is a list/set/tuple containing "none"
        if isinstance(node, ast.Assign):
            for target in node.targets:
                target_name = ""
                if isinstance(target, ast.Name):
                    target_name = target.id.lower()
                elif isinstance(target, ast.Attribute):
                    target_name = target.attr.lower()

                if any(kw in target_name for kw in ("algorithm", "alg", "allowed_alg")):
                    if isinstance(node.value, (ast.List, ast.Set, ast.Tuple)):
                        for elt in node.value.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                if elt.value.lower() == "none":
                                    findings.append(Finding(
                                        rule="TB-040",
                                        path=path,
                                        line=elt.lineno,
                                        col=elt.col_offset,
                                        message="JWT algorithm allowlist contains 'none' -- unsigned tokens accepted",
                                        severity=Severity.CRITICAL,
                                        fix=Fix.SIMPLIFY,
                                        detail="An algorithm list containing 'none' allows unsigned JWT tokens "
                                               "to bypass signature verification entirely. Remove 'none' from "
                                               "the allowlist.",
                                    ))
    return findings


# ============================================================================
# TB-041: Unrestricted importlib.import_module
# CVE-2026-61536 (Banks): Tool.import_path resolved via importlib
# ============================================================================

def _check_unrestricted_import(tree: ast.Module, path: str) -> List[Finding]:
    """TB-041: importlib.import_module() called with a variable argument.

    Pattern: importlib.import_module(user_string)
    Enables importing and executing arbitrary Python modules.
    """
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            is_import_module = False
            if isinstance(func, ast.Attribute) and func.attr == "import_module":
                if isinstance(func.value, ast.Name) and func.value.id == "importlib":
                    is_import_module = True
                elif isinstance(func.value, ast.Attribute):
                    # importlib.import_module or __import__
                    is_import_module = True

            if is_import_module and node.args:
                arg = node.args[0]
                if isinstance(arg, (ast.Name, ast.Attribute, ast.Subscript, ast.JoinedStr)):
                    findings.append(Finding(
                        rule="TB-041",
                        path=path,
                        line=node.lineno,
                        col=node.col_offset,
                        message="importlib.import_module() with variable argument -- unrestricted dynamic import",
                        severity=Severity.CRITICAL,
                        fix=Fix.RECALIBRATE,
                        detail="importlib.import_module(variable) imports and executes arbitrary "
                               "Python modules if the variable is attacker-controlled. Use an "
                               "explicit allowlist of permitted module names instead.",
                    ))
    return findings


# ============================================================================
# MR-008: Unbounded thread creation
# CVE-2026-34824 (mesop): Thread() per WebSocket message without pool
# ============================================================================

def _check_unbounded_thread_creation(tree: ast.Module, path: str) -> List[Finding]:
    """MR-008: threading.Thread() creation without a pool or semaphore guard.

    Pattern: Thread(target=handler).start() or thread = Thread(...); thread.start()
    Creates unbounded threads that exhaust system resources.
    """
    findings: List[Finding] = []

    # Strategy 1: detect threading.Thread(...) constructor calls directly
    # (catches both chained .start() and separate variable assignment)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            is_thread_ctor = False
            if isinstance(func, ast.Name) and func.id == "Thread":
                is_thread_ctor = True
            elif isinstance(func, ast.Attribute) and func.attr == "Thread":
                if isinstance(func.value, ast.Name) and func.value.id == "threading":
                    is_thread_ctor = True

            if is_thread_ctor:
                findings.append(Finding(
                    rule="MR-008",
                    path=path,
                    line=node.lineno,
                    col=node.col_offset,
                    message="threading.Thread() created without pool -- unbounded thread creation risk",
                    severity=Severity.HIGH,
                    fix=Fix.RECALIBRATE,
                    detail="threading.Thread() creates a new OS thread per call. "
                           "If called in a request handler or event loop, attacker-controlled "
                           "messages can exhaust threads and cause denial of service. "
                           "Use ThreadPoolExecutor with a bounded max_workers instead.",
                ))
    return findings


# ============================================================================
# MR-009: Recursive function without depth guard
# CVE-2026-30922 (pyasn1): decodeFun calls without nesting limit
# ============================================================================

def _check_recursive_no_depth(tree: ast.Module, source: str, path: str) -> List[Finding]:
    """MR-009: Function that calls itself without a depth/limit parameter.

    Pattern: def decode(data): ... decode(data[n:]) ... with no depth guard.
    Deeply nested input causes stack overflow.
    """
    findings: List[Finding] = []

    # Build a map of function names to their AST nodes
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_name = node.name
            # Check if this function has a depth/limit parameter
            arg_names = [a.arg for a in node.args.args]
            has_depth = any(
                kw in name.lower()
                for name in arg_names
                for kw in ("depth", "limit", "max_depth", "level", "recursion", "max_level", "max_nesting")
            )

            if has_depth:
                continue

            # Check if the function calls itself
            calls_self = False
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    if isinstance(child.func, ast.Name) and child.func.id == func_name:
                        calls_self = True
                        break
                    elif isinstance(child.func, ast.Attribute) and child.func.attr == func_name:
                        calls_self = True
                        break

            if calls_self:
                findings.append(Finding(
                    rule="MR-009",
                    path=path,
                    line=node.lineno,
                    col=node.col_offset,
                    message=f"Recursive function '{func_name}' without depth guard parameter",
                    severity=Severity.MEDIUM,
                    fix=Fix.ENRICH,
                    detail=f"Function '{func_name}' calls itself recursively but has no "
                           "depth/limit parameter. Deeply nested input can cause stack overflow "
                           "(denial of service). Add a max_depth parameter and raise an error "
                           "when the limit is exceeded.",
                ))
    return findings


# Bismillah ir-Rahman ir-Rahim
