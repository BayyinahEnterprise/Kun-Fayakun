# Bismillah ir-Rahman ir-Rahim
"""
INJECTION checks: shell injection, SQL injection, template injection.

Trust-boundary violations where untrusted input reaches a dangerous
sink without sanitization or parameterization.

Rules:
    TB-015  subprocess with shell=True
    TB-016  os.system / os.popen call
    TB-017  subprocess with partial executable path
    TB-018  SQL injection via string formatting
    TB-019  Jinja2 autoescape disabled
    TB-020  Django mark_safe / MarkupSafe Markup on variable input
    TB-027  XML parsing without defused-xml (XXE risk)
    TB-028  Django ORM .extra() or RawSQL with variable input
"""

from __future__ import annotations

import ast
from typing import List

from kun_fayakun.furqan.checks.finding import Finding, Fix, Severity


def check_injection(tree: ast.Module, path: str) -> List[Finding]:
    """Run all injection checks."""
    findings: List[Finding] = []
    findings.extend(_check_shell_true(tree, path))
    findings.extend(_check_os_system(tree, path))
    findings.extend(_check_partial_path(tree, path))
    findings.extend(_check_sql_injection(tree, path))
    findings.extend(_check_jinja2_autoescape(tree, path))
    findings.extend(_check_mark_safe(tree, path))
    findings.extend(_check_xxe(tree, path))
    findings.extend(_check_django_orm_injection(tree, path))
    return findings


def _check_shell_true(tree: ast.Module, path: str) -> List[Finding]:
    """TB-015: subprocess call with shell=True."""
    findings: List[Finding] = []
    _subprocess_funcs = {"call", "check_call", "check_output", "run", "Popen"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name = _get_call_name(node)
        if func_name and func_name.split(".")[-1] in _subprocess_funcs:
            for kw in node.keywords:
                if kw.arg == "shell":
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        findings.append(Finding(
                            rule="TB-015",
                            path=path,
                            line=node.lineno,
                            col=node.col_offset,
                            message=f"`{func_name}` called with shell=True -- shell injection risk",
                            severity=Severity.HIGH,
                            fix=Fix.RECALIBRATE,
                            detail="Pass a list of arguments instead of a shell string. "
                                   "shell=True passes the command through the system shell, "
                                   "which interprets metacharacters and enables injection.",
                        ))
    return findings


def _check_os_system(tree: ast.Module, path: str) -> List[Finding]:
    """TB-016: os.system or os.popen call."""
    findings: List[Finding] = []
    _dangerous = {"os.system", "os.popen", "os.popen2", "os.popen3", "os.popen4"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name = _get_call_name(node)
        if func_name in _dangerous:
            findings.append(Finding(
                rule="TB-016",
                path=path,
                line=node.lineno,
                col=node.col_offset,
                message=f"`{func_name}()` invokes the system shell -- use subprocess with a list",
                severity=Severity.HIGH,
                fix=Fix.RECALIBRATE,
                detail="os.system and os.popen pass commands through the shell. "
                       "Use subprocess.run() with a list of arguments instead.",
            ))
    return findings


def _check_partial_path(tree: ast.Module, path: str) -> List[Finding]:
    """TB-017: subprocess call with a partial executable path."""
    findings: List[Finding] = []
    _subprocess_funcs = {"call", "check_call", "check_output", "run", "Popen"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name = _get_call_name(node)
        if not func_name or func_name.split(".")[-1] not in _subprocess_funcs:
            continue
        # Check if shell=True -- already covered by TB-015
        has_shell = False
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                has_shell = True
        if has_shell:
            continue
        # Check the first positional arg (the command)
        if not node.args:
            continue
        first_arg = node.args[0]
        # If it's a list literal, check first element
        if isinstance(first_arg, ast.List) and first_arg.elts:
            cmd = first_arg.elts[0]
        elif isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
            cmd = first_arg
        else:
            continue
        if isinstance(cmd, ast.Constant) and isinstance(cmd.value, str):
            val = cmd.value
            # Partial path: no slash, not empty
            if val and "/" not in val and "\\" not in val:
                findings.append(Finding(
                    rule="TB-017",
                    path=path,
                    line=node.lineno,
                    col=node.col_offset,
                    message=f"Partial executable path `{val}` -- relies on $PATH resolution",
                    severity=Severity.LOW,
                    fix=Fix.RECALIBRATE,
                    detail="Using a partial path means the executable is found via $PATH, "
                           "which an attacker who controls $PATH can exploit. Use an "
                           "absolute path or validate the resolved path.",
                ))
    return findings


def _check_sql_injection(tree: ast.Module, path: str) -> List[Finding]:
    """TB-018: SQL injection via string formatting."""
    findings: List[Finding] = []
    _sql_keywords = {"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE",
                     "ALTER", "EXECUTE", "EXEC", "MERGE", "REPLACE"}

    for node in ast.walk(tree):
        sql_str = None
        line = 0
        col = 0

        # f-string with SQL
        if isinstance(node, ast.JoinedStr):
            # Check if any string parts contain SQL keywords
            for value in node.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    upper = value.value.upper().strip()
                    if any(upper.startswith(kw) or f" {kw} " in f" {upper} " for kw in _sql_keywords):
                        sql_str = "f-string"
                        line = node.lineno
                        col = node.col_offset
                        break

        # % formatting: "SELECT ... %s" % (val,)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                upper = node.left.value.upper()
                if any(kw in upper for kw in _sql_keywords):
                    sql_str = "% formatting"
                    line = node.lineno
                    col = node.col_offset

        # .format(): "SELECT ... {}".format(val)
        if isinstance(node, ast.Call):
            if (isinstance(node.func, ast.Attribute) and node.func.attr == "format"
                    and isinstance(node.func.value, ast.Constant)
                    and isinstance(node.func.value.value, str)):
                upper = node.func.value.value.upper()
                if any(kw in upper for kw in _sql_keywords):
                    sql_str = ".format()"
                    line = node.lineno
                    col = node.col_offset

        # String concatenation with SQL: "SELECT " + var
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                upper = node.left.value.upper().strip()
                if any(upper.startswith(kw) or upper.endswith(kw) or f" {kw} " in f" {upper} " for kw in _sql_keywords):
                    sql_str = "string concatenation"
                    line = node.lineno
                    col = node.col_offset

        if sql_str:
            findings.append(Finding(
                rule="TB-018",
                path=path,
                line=line,
                col=col,
                message=f"Possible SQL injection via {sql_str}",
                severity=Severity.HIGH,
                fix=Fix.RECALIBRATE,
                detail="Use parameterized queries (? or %s placeholders with a "
                       "parameter tuple) instead of string formatting to build SQL. "
                       "String-formatted SQL is the single most common injection vector.",
            ))
    return findings


def _check_jinja2_autoescape(tree: ast.Module, path: str) -> List[Finding]:
    """TB-019: Jinja2 Environment with autoescape=False."""
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name = _get_call_name(node)
        if func_name and func_name.split(".")[-1] == "Environment":
            for kw in node.keywords:
                if kw.arg == "autoescape":
                    if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        findings.append(Finding(
                            rule="TB-019",
                            path=path,
                            line=node.lineno,
                            col=node.col_offset,
                            message="Jinja2 Environment with autoescape=False -- XSS risk",
                            severity=Severity.HIGH,
                            fix=Fix.RECALIBRATE,
                            detail="Set autoescape=True or use select_autoescape(). "
                                   "Without autoescaping, any user input rendered in "
                                   "a template can execute arbitrary JavaScript.",
                        ))
    return findings


def _check_mark_safe(tree: ast.Module, path: str) -> List[Finding]:
    """TB-020: Django mark_safe or MarkupSafe Markup called on a variable."""
    findings: List[Finding] = []
    _unsafe_funcs = {"mark_safe", "Markup"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name = _get_call_name(node)
        if func_name and func_name.split(".")[-1] in _unsafe_funcs:
            if node.args:
                arg = node.args[0]
                # Only flag if the argument is NOT a string literal
                if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
                    label = func_name.split(".")[-1]
                    findings.append(Finding(
                        rule="TB-020",
                        path=path,
                        line=node.lineno,
                        col=node.col_offset,
                        message=f"{label}() called on non-literal input -- XSS risk",
                        severity=Severity.HIGH,
                        fix=Fix.RECALIBRATE,
                        detail=f"{label}() marks content as safe HTML, bypassing auto-escaping. "
                               "Calling it on anything other than a known-safe string literal "
                               "risks cross-site scripting. Use format_html() or Markup.escape() instead.",
                    ))
    return findings


def _check_xxe(tree: ast.Module, path: str) -> List[Finding]:
    """TB-027: XML parsing with stdlib modules vulnerable to XXE."""
    findings: List[Finding] = []
    # Dangerous XML parse calls from the stdlib
    _xxe_funcs = {
        "parse", "parseString", "Parse", "ParserCreate",
        "iterparse", "fromstring", "XMLParser",
    }
    # Module prefixes that indicate stdlib XML (not defusedxml)
    _xml_modules = {
        "xml.etree.ElementTree", "xml.dom.minidom", "xml.dom.pulldom",
        "xml.sax", "xml.parsers.expat", "ET",
        # Also catch direct imports
        "minidom", "pulldom", "sax", "expat",
    }

    # First pass: collect bare-name imports from xml.* modules
    # e.g. "from xml.dom.minidom import parseString"
    _xml_bare_imports: set = set()
    for node_item in ast.walk(tree):
        if isinstance(node_item, ast.ImportFrom) and node_item.module:
            mod = node_item.module
            if mod.startswith("xml.") and node_item.names:
                for alias in node_item.names:
                    name = alias.asname if alias.asname else alias.name
                    if alias.name in _xxe_funcs:
                        _xml_bare_imports.add(name)

    for node_item in ast.walk(tree):
        if not isinstance(node_item, ast.Call):
            continue
        func_name = _get_call_name(node_item)
        if not func_name:
            continue

        # Case 1: dotted call like minidom.parseString()
        parts = func_name.rsplit(".", 1)
        if len(parts) == 2:
            module_part, func_part = parts
            if func_part in _xxe_funcs and any(
                module_part == m or module_part.endswith("." + m.split(".")[-1])
                for m in _xml_modules
            ):
                findings.append(Finding(
                    rule="TB-027",
                    path=path,
                    line=node_item.lineno,
                    col=node_item.col_offset,
                    message=f"`{func_name}()` -- stdlib XML parser vulnerable to XXE attacks",
                    severity=Severity.HIGH,
                    fix=Fix.RECALIBRATE,
                    detail="Python's built-in XML parsers do not disable external entity "
                           "resolution by default. Use `defusedxml` (drop-in replacement) "
                           "or explicitly disable external entities on the parser.",
                ))

        # Case 2: bare-name call like parseString() imported from xml.*
        if len(parts) == 1 and func_name in _xml_bare_imports:
            findings.append(Finding(
                rule="TB-027",
                path=path,
                line=node_item.lineno,
                col=node_item.col_offset,
                message=f"`{func_name}()` -- stdlib XML parser vulnerable to XXE attacks",
                severity=Severity.HIGH,
                fix=Fix.RECALIBRATE,
                detail="Python's built-in XML parsers do not disable external entity "
                       "resolution by default. Use `defusedxml` (drop-in replacement) "
                       "or explicitly disable external entities on the parser.",
            ))
    return findings


def _check_django_orm_injection(tree: ast.Module, path: str) -> List[Finding]:
    """TB-028: Django ORM .extra() or RawSQL() with non-literal input."""
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name = _get_call_name(node)
        if not func_name:
            continue
        last = func_name.split(".")[-1]

        # .extra() call -- always risky, takes raw SQL fragments
        if last == "extra":
            # Check if any keyword arg is select, where, tables (the SQL ones)
            sql_kwargs = {"select", "where", "tables", "select_params", "params"}
            for kw in node.keywords:
                if kw.arg in sql_kwargs:
                    findings.append(Finding(
                        rule="TB-028",
                        path=path,
                        line=node.lineno,
                        col=node.col_offset,
                        message="Django `.extra()` accepts raw SQL fragments -- injection risk",
                        severity=Severity.HIGH,
                        fix=Fix.RECALIBRATE,
                        detail="QuerySet.extra() passes SQL fragments directly to the database. "
                               "Prefer ORM expressions (F(), Q(), annotate(), Subquery) or, "
                               "if raw SQL is unavoidable, use parameterized RawSQL with %s.",
                    ))
                    break

        # RawSQL() call
        if last == "RawSQL":
            if node.args:
                arg = node.args[0]
                # Flag if the first arg (the SQL) is not a string literal
                if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
                    findings.append(Finding(
                        rule="TB-028",
                        path=path,
                        line=node.lineno,
                        col=node.col_offset,
                        message="Django `RawSQL()` with non-literal SQL -- injection risk",
                        severity=Severity.HIGH,
                        fix=Fix.RECALIBRATE,
                        detail="RawSQL() sends SQL directly to the database. If the SQL string "
                               "is built from variables, it is vulnerable to injection. Use a "
                               "literal string with %s placeholders and pass parameters separately.",
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
