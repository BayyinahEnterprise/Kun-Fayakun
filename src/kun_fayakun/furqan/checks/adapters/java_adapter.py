# Bismillah ir-Rahman ir-Rahim
"""
Java language adapter for furqan-lint.

Catches structural honesty violations in Java code -- the language that runs
financial transaction systems, medical records (HL7/FHIR), and enterprise
backends where data integrity is paramount.

Rules implemented:
    RC-001  Resource opened without close / try-with-resources
    MR-001  Bare catch(Exception/Throwable) without rethrow
    MR-005  Empty catch block
    MR-007  catch-continue in loop
    TB-010  Hardcoded password/secret in string assignment
    TB-015  Runtime.exec() / ProcessBuilder command injection
    TB-018  SQL via Statement instead of PreparedStatement
    TB-021  Insecure hash (MD5/SHA1)
    TB-026  java.util.Random for security (use SecureRandom)
    TB-027  XXE -- XML parsing without disabling external entities
    TB-031  Serializable without serialVersionUID
    SI-004  TODO/FIXME/HACK/XXX
    SI-006  assert for runtime validation (disabled by default in JVM)
"""

from __future__ import annotations

from typing import List

import tree_sitter_java as tsj
from tree_sitter import Language, Node

from kun_fayakun.furqan.checks.finding import Finding, Fix, Severity
from kun_fayakun.furqan.checks.adapters.base import (
    BaseAdapter, register, walk_tree, find_nodes,
    node_text, string_value, contains_sql,
    SECRET_NAMES, PLACEHOLDER,
)


@register("java", [".java"])
class JavaAdapter(BaseAdapter):

    def language_name(self) -> str:
        return "Java"

    def get_language(self) -> Language:
        return Language(tsj.language())

    def check(self, source: bytes, path: str) -> List[Finding]:
        findings = super().check(source, path)
        tree = self.parse(source, path)
        if tree:
            root = tree.root_node
            findings.extend(self._check_weak_random(root, path))
            findings.extend(self._check_assert_validation(root, path))
            findings.extend(self._check_resource_not_autoclosed(root, path))
        return findings

    def check_hardcoded_secrets(self, root: Node, path: str) -> List[Finding]:
        findings: List[Finding] = []
        for node in find_nodes(root, "variable_declarator"):
            name_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")
            if name_node and value_node:
                name = node_text(name_node)
                if SECRET_NAMES.search(name) and value_node.type == "string_literal":
                    val = string_value(value_node)
                    if val and not PLACEHOLDER.match(val):
                        findings.append(Finding(
                            rule="TB-010",
                            path=path,
                            line=node.start_point[0] + 1,
                            col=node.start_point[1],
                            message=f"Hardcoded secret in `{name}` -- move to environment or config",
                            severity=Severity.HIGH,
                            fix=Fix.RECALIBRATE,
                            detail="Secrets in source code are readable by anyone with "
                                   "access to the repository or decompiled bytecode.",
                        ))
        return findings

    def check_empty_catch(self, root: Node, path: str) -> List[Finding]:
        findings: List[Finding] = []
        for node in find_nodes(root, "catch_clause"):
            body = node.child_by_field_name("body")
            # tree-sitter-java names the catch parameter node "catch_formal_parameter"
            catch_param = None
            for child in node.children:
                if child.type == "catch_formal_parameter":
                    catch_param = child
                    break
            if body:
                # Count non-whitespace children in the block
                stmts = [c for c in body.children
                         if c.type not in ("{", "}", "comment", "line_comment")]
                if not stmts:
                    # Empty catch block
                    exc_type = ""
                    if catch_param:
                        for child in walk_tree(catch_param):
                            if child.type == "type_identifier":
                                exc_type = node_text(child)
                                break
                    findings.append(Finding(
                        rule="MR-005",
                        path=path,
                        line=node.start_point[0] + 1,
                        col=node.start_point[1],
                        message=f"Empty catch block for `{exc_type or 'Exception'}` -- failure silenced",
                        severity=Severity.HIGH,
                        fix=Fix.ENRICH,
                        detail="An empty catch block silences the exception entirely. "
                               "At minimum, log the exception. In safety-critical code, "
                               "consider whether the exception should propagate.",
                    ))
                # Check for catch(Exception e) or catch(Throwable t) without rethrow
                if catch_param:
                    for child in walk_tree(catch_param):
                        if child.type == "type_identifier" and node_text(child) in ("Exception", "Throwable"):
                            has_throw = False
                            for stmt in walk_tree(body):
                                if stmt.type == "throw_statement":
                                    has_throw = True
                                    break
                            if not has_throw and stmts:
                                findings.append(Finding(
                                    rule="MR-001",
                                    path=path,
                                    line=node.start_point[0] + 1,
                                    col=node.start_point[1],
                                    message=f"catch({node_text(child)}) without rethrow -- swallows all exceptions",
                                    severity=Severity.HIGH,
                                    fix=Fix.RECALIBRATE,
                                    detail="Catching Exception or Throwable without rethrowing claims to "
                                           "handle every failure mode. Narrow to specific exceptions "
                                           "or rethrow after logging.",
                                ))
                            break
        return findings

    def check_sql_injection(self, root: Node, path: str) -> List[Finding]:
        findings: List[Finding] = []
        for node in find_nodes(root, "method_invocation"):
            method_node = node.child_by_field_name("name")
            if not method_node:
                continue
            method_name = node_text(method_node)
            # Statement.execute/executeQuery/executeUpdate with string concat
            if method_name in ("execute", "executeQuery", "executeUpdate"):
                args = node.child_by_field_name("arguments")
                if args:
                    for arg in walk_tree(args):
                        if arg.type == "binary_expression":
                            # String concatenation in SQL
                            left = arg.child_by_field_name("left")
                            if left and left.type == "string_literal":
                                val = string_value(left)
                                if val and contains_sql(val):
                                    findings.append(Finding(
                                        rule="TB-018",
                                        path=path,
                                        line=node.start_point[0] + 1,
                                        col=node.start_point[1],
                                        message=f"SQL injection via string concatenation in `{method_name}()`",
                                        severity=Severity.HIGH,
                                        fix=Fix.RECALIBRATE,
                                        detail="Use PreparedStatement with ? placeholders instead of "
                                               "building SQL by string concatenation. This is the Java "
                                               "equivalent of parameterized queries.",
                                    ))
                                    break
        return findings

    def check_resource_leak(self, root: Node, path: str) -> List[Finding]:
        findings: List[Finding] = []
        _resource_types = {
            "FileInputStream", "FileOutputStream", "BufferedReader",
            "BufferedWriter", "Connection", "Statement", "ResultSet",
            "Socket", "ServerSocket", "InputStream", "OutputStream",
        }
        for node in find_nodes(root, "object_creation_expression"):
            type_node = node.child_by_field_name("type")
            if type_node:
                type_name = node_text(type_node)
                # Strip generics
                if "<" in type_name:
                    type_name = type_name[:type_name.index("<")]
                if type_name in _resource_types:
                    # Check if this is inside a try-with-resources
                    in_twr = _is_in_try_with_resources(node)
                    if not in_twr:
                        # Check if close() is called in the enclosing method
                        method_body = _enclosing_block(node)
                        if method_body:
                            body_text = node_text(method_body)
                            if ".close()" not in body_text:
                                findings.append(Finding(
                                    rule="RC-001",
                                    path=path,
                                    line=node.start_point[0] + 1,
                                    col=node.start_point[1],
                                    message=f"`new {type_name}()` not in try-with-resources and no close()",
                                    severity=Severity.HIGH,
                                    fix=Fix.RECALIBRATE,
                                    detail="Use try-with-resources (try (var x = new ...)) to "
                                           "guarantee the resource is closed on all paths, "
                                           "including exception paths.",
                                ))
        return findings

    def check_command_injection(self, root: Node, path: str) -> List[Finding]:
        findings: List[Finding] = []
        for node in find_nodes(root, "method_invocation"):
            method_node = node.child_by_field_name("name")
            obj_node = node.child_by_field_name("object")
            if not method_node:
                continue
            method_name = node_text(method_node)
            # Runtime.exec()
            if method_name == "exec" and obj_node:
                obj_text = node_text(obj_node)
                if "Runtime" in obj_text or "runtime" in obj_text:
                    findings.append(Finding(
                        rule="TB-015",
                        path=path,
                        line=node.start_point[0] + 1,
                        col=node.start_point[1],
                        message="Runtime.exec() -- command injection risk if input is unvalidated",
                        severity=Severity.HIGH,
                        fix=Fix.RECALIBRATE,
                        detail="Runtime.exec() with a single string argument passes "
                               "the command to the OS shell. Use ProcessBuilder with "
                               "an explicit argument list instead.",
                    ))
        # ProcessBuilder with string concat
        for node in find_nodes(root, "object_creation_expression"):
            type_node = node.child_by_field_name("type")
            if type_node and node_text(type_node) == "ProcessBuilder":
                findings.append(Finding(
                    rule="TB-015",
                    path=path,
                    line=node.start_point[0] + 1,
                    col=node.start_point[1],
                    message="ProcessBuilder -- validate command arguments against injection",
                    severity=Severity.MEDIUM,
                    fix=Fix.RECALIBRATE,
                    detail="ProcessBuilder is safer than Runtime.exec() but still "
                           "executes arbitrary commands. Validate all arguments.",
                ))
        return findings

    def _check_weak_random(self, root: Node, path: str) -> List[Finding]:
        """TB-026: java.util.Random instead of SecureRandom."""
        findings: List[Finding] = []
        for node in find_nodes(root, "object_creation_expression"):
            type_node = node.child_by_field_name("type")
            if type_node:
                type_name = node_text(type_node)
                if type_name in ("Random", "java.util.Random"):
                    findings.append(Finding(
                        rule="TB-026",
                        path=path,
                        line=node.start_point[0] + 1,
                        col=node.start_point[1],
                        message="`new Random()` is not cryptographically secure",
                        severity=Severity.MEDIUM,
                        fix=Fix.RECALIBRATE,
                        detail="java.util.Random uses a linear congruential generator. "
                               "For tokens, keys, or security-sensitive values, use "
                               "java.security.SecureRandom instead.",
                    ))
        return findings

    def _check_assert_validation(self, root: Node, path: str) -> List[Finding]:
        """SI-006: Java assert disabled by default in the JVM."""
        findings: List[Finding] = []
        for node in find_nodes(root, "assert_statement"):
            findings.append(Finding(
                rule="SI-006",
                path=path,
                line=node.start_point[0] + 1,
                col=node.start_point[1],
                message="`assert` disabled by default in the JVM -- not for runtime validation",
                severity=Severity.HIGH,
                fix=Fix.RECALIBRATE,
                detail="Java assert statements are disabled unless the JVM is started "
                       "with -ea. For runtime validation, use an explicit if-throw.",
            ))
        return findings

    def _check_resource_not_autoclosed(self, root: Node, path: str) -> List[Finding]:
        """Additional resource leak check: new FileWriter/etc outside try-with-resources."""
        # Covered by check_resource_leak above
        return []


def _is_in_try_with_resources(node: Node) -> bool:
    """Check if a node is inside a try-with-resources statement."""
    current = node.parent
    while current:
        if current.type == "try_with_resources_statement":
            return True
        if current.type == "resource_specification":
            return True
        current = current.parent
    return False


def _enclosing_block(node: Node) -> Node | None:
    """Find the nearest enclosing block (method body, etc)."""
    current = node.parent
    while current:
        if current.type in ("method_declaration", "constructor_declaration"):
            for child in current.children:
                if child.type == "block":
                    return child
        current = current.parent
    return None


# Bismillah ir-Rahman ir-Rahim
