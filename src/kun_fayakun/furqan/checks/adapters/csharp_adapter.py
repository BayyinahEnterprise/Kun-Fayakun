# Bismillah ir-Rahman ir-Rahim
"""
C# language adapter for furqan-lint.

Catches structural honesty violations in C# code -- the language behind
medical device software (FDA 21 CFR Part 11), financial trading platforms,
enterprise healthcare systems, and Azure-based safety-critical backends.

Rules implemented:
    RC-001  IDisposable not in using statement
    MR-001  catch(Exception) / catch without type, no rethrow
    MR-005  Empty catch block
    MR-007  catch-continue in loop
    TB-010  Hardcoded password/secret in string assignment
    TB-015  Process.Start command injection
    TB-018  SQL injection via string concatenation
    TB-020  Html.Raw() on non-literal (XSS)
    TB-026  System.Random for security (use RNGCryptoServiceProvider)
    TB-027  XML parsing without DTD prohibition
    SI-004  TODO/FIXME/HACK/XXX
    SI-006  Debug.Assert / Trace.Assert for runtime validation
"""

from __future__ import annotations

from typing import List

import tree_sitter_c_sharp as tscs
from tree_sitter import Language, Node

from kun_fayakun.furqan.checks.finding import Finding, Fix, Severity
from kun_fayakun.furqan.checks.adapters.base import (
    BaseAdapter, register, walk_tree, find_nodes,
    node_text, string_value, contains_sql,
    SECRET_NAMES, PLACEHOLDER,
)


@register("csharp", [".cs"])
class CSharpAdapter(BaseAdapter):

    def language_name(self) -> str:
        return "C#"

    def get_language(self) -> Language:
        return Language(tscs.language())

    def check(self, source: bytes, path: str) -> List[Finding]:
        findings = super().check(source, path)
        tree = self.parse(source, path)
        if tree:
            root = tree.root_node
            findings.extend(self._check_catch_blocks(root, path))
            findings.extend(self._check_disposable_leak(root, path))
            findings.extend(self._check_weak_random(root, path))
            findings.extend(self._check_debug_assert(root, path))
            findings.extend(self._check_process_start(root, path))
            findings.extend(self._check_html_raw(root, path))
        return findings

    # ── Universal checks, C#-specific implementation ──

    def check_hardcoded_secrets(self, root: Node, path: str) -> List[Finding]:
        findings: List[Finding] = []
        for node in find_nodes(root, "variable_declarator"):
            name_node = _first_child_of_type(node, "identifier")
            # In C# tree-sitter, the string_literal is a direct child of
            # variable_declarator (after the = sign), not inside equals_value_clause
            value_node = _first_child_of_type(node, "string_literal")
            if name_node and value_node:
                name = node_text(name_node)
                if SECRET_NAMES.search(name):
                    # C# string_literal has children: " content "
                    # Extract the content
                    val = _cs_string_value(value_node)
                    if val and not PLACEHOLDER.match(val):
                        findings.append(Finding(
                            rule="TB-010",
                            path=path,
                            line=node.start_point[0] + 1,
                            col=node.start_point[1],
                            message=f"Hardcoded secret in `{name}` -- move to configuration or environment",
                            severity=Severity.HIGH,
                            fix=Fix.RECALIBRATE,
                            detail="Secrets in source code are visible in the repository and "
                                   "in compiled assemblies. Use IConfiguration, environment "
                                   "variables, or Azure Key Vault.",
                        ))
        return findings

    def check_empty_catch(self, root: Node, path: str) -> List[Finding]:
        # Handled by _check_catch_blocks below
        return []

    def check_sql_injection(self, root: Node, path: str) -> List[Finding]:
        findings: List[Finding] = []
        # Look for string concatenation in SQL-like method calls
        # SqlCommand, ExecuteNonQuery, ExecuteReader, ExecuteScalar
        _sql_methods = {"ExecuteNonQuery", "ExecuteReader", "ExecuteScalar",
                        "Execute", "ExecuteSqlRaw", "FromSqlRaw"}
        for node in find_nodes(root, "invocation_expression"):
            func_node = _get_member_name(node)
            if func_node and node_text(func_node) in _sql_methods:
                args = node.child_by_field_name("arguments") or _first_child_of_type(node, "argument_list")
                if args:
                    for arg in walk_tree(args):
                        if arg.type == "binary_expression":
                            op = arg.child_by_field_name("operator") or _first_child_of_type(arg, "+")
                            left = arg.child_by_field_name("left")
                            if left and left.type == "string_literal":
                                val = string_value(left)
                                if val and contains_sql(val):
                                    findings.append(Finding(
                                        rule="TB-018",
                                        path=path,
                                        line=node.start_point[0] + 1,
                                        col=node.start_point[1],
                                        message="SQL injection via string concatenation -- use SqlParameter",
                                        severity=Severity.HIGH,
                                        fix=Fix.RECALIBRATE,
                                        detail="Use SqlCommand with SqlParameter or parameterized "
                                               "queries in Entity Framework. String-concatenated SQL "
                                               "is vulnerable to injection.",
                                    ))
                                    break

        # Also catch: new SqlCommand("SELECT..." + var)
        for node in find_nodes(root, "object_creation_expression"):
            type_node = _first_child_of_type(node, "identifier") or _first_child_of_type(node, "qualified_name")
            if type_node and "SqlCommand" in node_text(type_node):
                args = _first_child_of_type(node, "argument_list")
                if args:
                    for arg in walk_tree(args):
                        if arg.type == "binary_expression":
                            for child in walk_tree(arg):
                                if child.type == "string_literal":
                                    val = string_value(child)
                                    if val and contains_sql(val):
                                        findings.append(Finding(
                                            rule="TB-018",
                                            path=path,
                                            line=node.start_point[0] + 1,
                                            col=node.start_point[1],
                                            message="new SqlCommand() with concatenated SQL -- use parameters",
                                            severity=Severity.HIGH,
                                            fix=Fix.RECALIBRATE,
                                            detail="Use SqlParameter to parameterize queries. "
                                                   "Never build SQL by string concatenation.",
                                        ))
                                        break
        return findings

    def check_resource_leak(self, root: Node, path: str) -> List[Finding]:
        # Handled by _check_disposable_leak below
        return []

    def check_command_injection(self, root: Node, path: str) -> List[Finding]:
        # Handled by _check_process_start below
        return []

    # ── C#-specific checks ──

    def _check_catch_blocks(self, root: Node, path: str) -> List[Finding]:
        """MR-001/005/007: Catch block analysis."""
        findings: List[Finding] = []
        for node in find_nodes(root, "catch_clause"):
            body = _first_child_of_type(node, "block")
            if not body:
                continue

            stmts = [c for c in body.children
                     if c.type not in ("{", "}", "comment")]

            # MR-005: Empty catch
            if not stmts:
                # Get exception type
                catch_decl = _first_child_of_type(node, "catch_declaration")
                exc_type = ""
                if catch_decl:
                    for child in walk_tree(catch_decl):
                        if child.type == "identifier":
                            exc_type = node_text(child)
                            break
                findings.append(Finding(
                    rule="MR-005",
                    path=path,
                    line=node.start_point[0] + 1,
                    col=node.start_point[1],
                    message=f"Empty catch block{' for `' + exc_type + '`' if exc_type else ''} -- failure silenced",
                    severity=Severity.HIGH,
                    fix=Fix.ENRICH,
                    detail="An empty catch block swallows the exception. Log it "
                           "or rethrow. In medical/financial C#, silent failures "
                           "violate audit trail requirements.",
                ))
                continue

            # MR-007: catch with only continue
            if len(stmts) == 1 and stmts[0].type == "continue_statement":
                findings.append(Finding(
                    rule="MR-007",
                    path=path,
                    line=node.start_point[0] + 1,
                    col=node.start_point[1],
                    message="catch with bare `continue` -- loop errors silently skipped",
                    severity=Severity.MEDIUM,
                    fix=Fix.ENRICH,
                    detail="Catching and continuing means every loop iteration failure "
                           "is invisible. Log before continuing.",
                ))
                continue

            # MR-001: catch(Exception) or bare catch without rethrow
            catch_decl = _first_child_of_type(node, "catch_declaration")
            is_broad = False
            exc_name = ""
            if catch_decl:
                for child in walk_tree(catch_decl):
                    if child.type == "identifier":
                        name = node_text(child)
                        if name in ("Exception", "SystemException"):
                            is_broad = True
                            exc_name = name
                        break
            else:
                # Bare catch (no declaration) -- catches everything
                is_broad = True
                exc_name = "(bare catch)"

            if is_broad:
                has_throw = False
                for stmt in walk_tree(body):
                    if stmt.type == "throw_statement":
                        has_throw = True
                        break
                if not has_throw:
                    findings.append(Finding(
                        rule="MR-001",
                        path=path,
                        line=node.start_point[0] + 1,
                        col=node.start_point[1],
                        message=f"catch({exc_name}) without rethrow -- swallows all exceptions",
                        severity=Severity.HIGH,
                        fix=Fix.RECALIBRATE,
                        detail="Catching Exception or using a bare catch without rethrowing "
                               "claims to handle every failure. Narrow to specific types "
                               "or rethrow after logging.",
                    ))
        return findings

    def _check_disposable_leak(self, root: Node, path: str) -> List[Finding]:
        """RC-001: IDisposable created outside of using statement."""
        findings: List[Finding] = []
        _disposable_types = {
            "SqlConnection", "SqlCommand", "SqlDataReader",
            "FileStream", "StreamReader", "StreamWriter",
            "HttpClient", "TcpClient", "NetworkStream",
            "MemoryStream", "BinaryReader", "BinaryWriter",
            "Process", "Timer",
        }
        for node in find_nodes(root, "object_creation_expression"):
            type_node = _first_child_of_type(node, "identifier") or _first_child_of_type(node, "qualified_name")
            if not type_node:
                continue
            type_name = node_text(type_node)
            if type_name not in _disposable_types:
                continue
            # Check if inside a using statement
            if _is_in_using(node):
                continue
            # Check if Dispose() is called in the enclosing method
            method_body = _enclosing_block(node)
            if method_body:
                body_text = node_text(method_body)
                if ".Dispose()" not in body_text and ".Close()" not in body_text:
                    findings.append(Finding(
                        rule="RC-001",
                        path=path,
                        line=node.start_point[0] + 1,
                        col=node.start_point[1],
                        message=f"`new {type_name}()` not in `using` and no Dispose() -- resource leak",
                        severity=Severity.HIGH,
                        fix=Fix.RECALIBRATE,
                        detail="IDisposable objects must be wrapped in a using statement "
                               "or explicitly disposed. Without it, the finalizer may never "
                               "run, leaking connections, handles, or memory.",
                    ))
        return findings

    def _check_weak_random(self, root: Node, path: str) -> List[Finding]:
        """TB-026: System.Random instead of cryptographic RNG."""
        findings: List[Finding] = []
        for node in find_nodes(root, "object_creation_expression"):
            type_node = _first_child_of_type(node, "identifier") or _first_child_of_type(node, "qualified_name")
            if type_node and node_text(type_node) == "Random":
                findings.append(Finding(
                    rule="TB-026",
                    path=path,
                    line=node.start_point[0] + 1,
                    col=node.start_point[1],
                    message="`new Random()` is not cryptographically secure",
                    severity=Severity.MEDIUM,
                    fix=Fix.RECALIBRATE,
                    detail="System.Random is predictable. For tokens, keys, or any "
                           "security-sensitive value, use RandomNumberGenerator.Create() "
                           "or RandomNumberGenerator.GetBytes().",
                ))
        return findings

    def _check_debug_assert(self, root: Node, path: str) -> List[Finding]:
        """SI-006: Debug.Assert / Trace.Assert stripped in release builds."""
        findings: List[Finding] = []
        for node in find_nodes(root, "invocation_expression"):
            func_node = _get_member_access_text(node)
            if func_node in ("Debug.Assert", "Trace.Assert"):
                findings.append(Finding(
                    rule="SI-006",
                    path=path,
                    line=node.start_point[0] + 1,
                    col=node.start_point[1],
                    message=f"`{func_node}()` stripped in Release builds -- not for runtime validation",
                    severity=Severity.HIGH,
                    fix=Fix.RECALIBRATE,
                    detail="Debug.Assert and Trace.Assert are compiled out in Release "
                           "configuration. For runtime checks, throw an explicit exception.",
                ))
        return findings

    def _check_process_start(self, root: Node, path: str) -> List[Finding]:
        """TB-015: Process.Start command injection."""
        findings: List[Finding] = []
        for node in find_nodes(root, "invocation_expression"):
            func_text = _get_member_access_text(node)
            if func_text and "Process.Start" in func_text:
                findings.append(Finding(
                    rule="TB-015",
                    path=path,
                    line=node.start_point[0] + 1,
                    col=node.start_point[1],
                    message="Process.Start() -- validate arguments against command injection",
                    severity=Severity.HIGH,
                    fix=Fix.RECALIBRATE,
                    detail="Process.Start can execute arbitrary commands. Validate all "
                           "arguments. Prefer ProcessStartInfo with UseShellExecute=false "
                           "and explicit argument separation.",
                ))
        return findings

    def _check_html_raw(self, root: Node, path: str) -> List[Finding]:
        """TB-020: Html.Raw() on non-literal (XSS risk)."""
        findings: List[Finding] = []
        for node in find_nodes(root, "invocation_expression"):
            func_text = _get_member_access_text(node)
            if func_text and func_text.endswith("Html.Raw"):
                args = _first_child_of_type(node, "argument_list")
                if args:
                    for arg in args.children:
                        if arg.type == "argument":
                            expr = arg.children[0] if arg.children else None
                            if expr and expr.type != "string_literal":
                                findings.append(Finding(
                                    rule="TB-020",
                                    path=path,
                                    line=node.start_point[0] + 1,
                                    col=node.start_point[1],
                                    message="Html.Raw() on non-literal -- XSS risk",
                                    severity=Severity.HIGH,
                                    fix=Fix.RECALIBRATE,
                                    detail="Html.Raw() bypasses Razor's HTML encoding. "
                                           "Only pass known-safe literal strings. For user "
                                           "content, use standard Razor output (@variable).",
                                ))
                            break
        return findings


# ── Helpers ──

def _cs_string_value(node: Node) -> str:
    """Extract string content from a C# string_literal node.

    C# tree-sitter parses string literals as: " content "
    where content is a string_literal_content child.
    """
    for child in node.children:
        if child.type == "string_literal_content":
            return node_text(child)
    # Fallback: strip quotes from the full text
    text = node_text(node)
    if len(text) >= 2 and text.startswith('"') and text.endswith('"'):
        return text[1:-1]
    return text


def _first_child_of_type(node: Node, type_name: str) -> Node | None:
    for child in node.children:
        if child.type == type_name:
            return child
    return None


def _get_member_name(node: Node) -> Node | None:
    """Get the method name node from an invocation_expression."""
    func = node.child_by_field_name("function")
    if func and func.type == "member_access_expression":
        name = func.child_by_field_name("name")
        return name
    return func


def _get_member_access_text(node: Node) -> str:
    """Get dotted text like 'Debug.Assert' from an invocation_expression."""
    for child in node.children:
        if child.type == "member_access_expression":
            return node_text(child)
        if child.type == "identifier":
            return node_text(child)
    return ""


def _is_in_using(node: Node) -> bool:
    """Check if node is inside a using statement."""
    current = node.parent
    while current:
        if current.type in ("using_statement", "using_declaration"):
            return True
        current = current.parent
    return False


def _enclosing_block(node: Node) -> Node | None:
    """Find the nearest enclosing method body block."""
    current = node.parent
    while current:
        if current.type == "method_declaration":
            for child in current.children:
                if child.type == "block":
                    return child
        current = current.parent
    return None


# Bismillah ir-Rahman ir-Rahim
