# Bismillah ir-Rahman ir-Rahim
"""
C++ language adapter for furqan-lint.

Extends the C adapter with C++-specific structural honesty checks.
C++ runs automotive control systems (AUTOSAR), aerospace avionics,
high-frequency trading engines, and medical imaging software.

Inherits all C rules, plus:
    MR-001  catch(...) without rethrow -- swallows everything
    MR-005  Empty catch block
    RC-001  new without delete / RAII violation
    TB-031  const_cast removing const -- type safety bypass
    TB-032  reinterpret_cast -- unsafe memory reinterpretation
    TB-033  C-style cast in C++ code
    SI-008  dynamic_cast without null check
"""

from __future__ import annotations

from typing import List

import tree_sitter_cpp as tscpp
from tree_sitter import Language, Node

from kun_fayakun.furqan.checks.finding import Finding, Fix, Severity
from kun_fayakun.furqan.checks.adapters.base import (
    register, walk_tree, find_nodes, node_text,
)
from kun_fayakun.furqan.checks.adapters.c_adapter import CAdapter


@register("cpp", [".cpp", ".cxx", ".cc", ".hpp", ".hxx", ".hh"])
class CppAdapter(CAdapter):
    """C++ adapter -- inherits all C checks and adds C++-specific ones."""

    def language_name(self) -> str:
        return "C++"

    def get_language(self) -> Language:
        return Language(tscpp.language())

    def check(self, source: bytes, path: str) -> List[Finding]:
        findings = super().check(source, path)
        tree = self.parse(source, path)
        if tree:
            root = tree.root_node
            findings.extend(self._check_catch_all(root, path))
            findings.extend(self._check_empty_catch(root, path))
            findings.extend(self._check_unsafe_casts(root, path))
            findings.extend(self._check_new_without_smart_ptr(root, path))
            findings.extend(self._check_dynamic_cast_unchecked(root, path))
        return findings

    def _check_catch_all(self, root: Node, path: str) -> List[Finding]:
        """MR-001: catch(...) without rethrow."""
        findings: List[Finding] = []
        for node in find_nodes(root, "catch_clause"):
            # Check for catch(...)
            params = None
            for child in node.children:
                if child.type == "parameter_list":
                    params = child
                    break
            if params:
                params_text = node_text(params).strip()
                if params_text == "(...)":
                    # Check for rethrow
                    body = None
                    for child in node.children:
                        if child.type == "compound_statement":
                            body = child
                            break
                    has_throw = False
                    if body:
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
                            message="catch(...) without rethrow -- swallows all exceptions including std::bad_alloc",
                            severity=Severity.CRITICAL,
                            fix=Fix.RECALIBRATE,
                            detail="catch(...) catches everything including memory failures and "
                                   "stack unwinding exceptions. Either catch specific types or "
                                   "rethrow after logging. In AUTOSAR C++14, MISRA C++ forbids "
                                   "catch(...) without rethrow.",
                        ))
        return findings

    def _check_empty_catch(self, root: Node, path: str) -> List[Finding]:
        """MR-005: Empty catch block in C++."""
        findings: List[Finding] = []
        for node in find_nodes(root, "catch_clause"):
            body = None
            for child in node.children:
                if child.type == "compound_statement":
                    body = child
                    break
            if body:
                stmts = [c for c in body.children
                         if c.type not in ("{", "}", "comment")]
                if not stmts:
                    findings.append(Finding(
                        rule="MR-005",
                        path=path,
                        line=node.start_point[0] + 1,
                        col=node.start_point[1],
                        message="Empty catch block -- exception silenced entirely",
                        severity=Severity.HIGH,
                        fix=Fix.ENRICH,
                        detail="An empty catch block discards all diagnostic information. "
                               "At minimum, log the exception or rethrow it.",
                    ))
        return findings

    def _check_unsafe_casts(self, root: Node, path: str) -> List[Finding]:
        """TB-031/032/033: Unsafe cast operations."""
        findings: List[Finding] = []
        _cast_rules = {
            "const_cast": ("TB-031", "const_cast removes const -- type safety bypass",
                           Severity.HIGH,
                           "const_cast strips const qualification, which can lead to "
                           "undefined behavior if the underlying object was declared const. "
                           "Redesign to avoid the need to cast away const."),
            "reinterpret_cast": ("TB-032", "reinterpret_cast -- unsafe memory reinterpretation",
                                 Severity.HIGH,
                                 "reinterpret_cast converts between unrelated types by "
                                 "reinterpreting the bit pattern. This bypasses the type system "
                                 "entirely. Use static_cast or redesign the interface."),
        }
        for node in walk_tree(root):
            # tree-sitter-cpp parses named casts as call_expression with
            # template_function whose identifier is the cast name
            if node.type == "call_expression":
                for child in node.children:
                    if child.type == "template_function":
                        for tc in child.children:
                            if tc.type == "identifier" and node_text(tc) in _cast_rules:
                                rule, msg, sev, detail = _cast_rules[node_text(tc)]
                                findings.append(Finding(
                                    rule=rule,
                                    path=path,
                                    line=node.start_point[0] + 1,
                                    col=node.start_point[1],
                                    message=msg,
                                    severity=sev,
                                    fix=Fix.RECALIBRATE,
                                    detail=detail,
                                ))
            # C-style cast: (Type)expr
            if node.type == "cast_expression":
                findings.append(Finding(
                    rule="TB-033",
                    path=path,
                    line=node.start_point[0] + 1,
                    col=node.start_point[1],
                    message="C-style cast -- use static_cast/dynamic_cast/const_cast explicitly",
                    severity=Severity.MEDIUM,
                    fix=Fix.RECALIBRATE,
                    detail="C-style casts in C++ silently fall through to the most "
                           "permissive cast (including reinterpret_cast). Use named casts "
                           "so the intent is explicit and reviewable.",
                ))
        return findings

    def _check_new_without_smart_ptr(self, root: Node, path: str) -> List[Finding]:
        """RC-001: raw new without matching delete or smart pointer wrapper."""
        findings: List[Finding] = []
        for node in find_nodes(root, "new_expression"):
            # Check if the result flows into a smart pointer
            # Walk up to the declaration/statement level to find smart_ptr context
            is_smart = False
            ancestor = node.parent
            for _ in range(5):  # max 5 levels up
                if ancestor is None:
                    break
                ancestor_text = node_text(ancestor)
                if any(sp in ancestor_text for sp in
                       ("unique_ptr", "shared_ptr", "make_unique", "make_shared")):
                    is_smart = True
                    break
                ancestor = ancestor.parent
            if not is_smart:
                # Check enclosing function for delete
                func_body = _enclosing_compound(node)
                if func_body:
                    body_text = node_text(func_body)
                    if "delete" not in body_text:
                        findings.append(Finding(
                            rule="RC-001",
                            path=path,
                            line=node.start_point[0] + 1,
                            col=node.start_point[1],
                            message="raw `new` without delete or smart pointer -- memory leak risk",
                            severity=Severity.HIGH,
                            fix=Fix.RECALIBRATE,
                            detail="Use std::unique_ptr or std::shared_ptr instead of raw new. "
                                   "Raw new/delete is the leading cause of memory leaks and "
                                   "use-after-free in C++. RAII wrappers close the ring.",
                        ))
        return findings

    def _check_dynamic_cast_unchecked(self, root: Node, path: str) -> List[Finding]:
        """SI-008: dynamic_cast result used without null check."""
        findings: List[Finding] = []
        for node in walk_tree(root):
            if node.type == "dynamic_cast_expression":
                # Check if the cast target is a pointer type (could return nullptr)
                type_node = None
                for child in node.children:
                    if child.type == "type_descriptor":
                        type_node = child
                        break
                if type_node and "*" in node_text(type_node):
                    # Pointer dynamic_cast -- check if result is tested for null
                    parent = node.parent
                    if parent and parent.type not in ("if_statement", "condition_clause",
                                                       "binary_expression"):
                        findings.append(Finding(
                            rule="SI-008",
                            path=path,
                            line=node.start_point[0] + 1,
                            col=node.start_point[1],
                            message="dynamic_cast to pointer without null check",
                            severity=Severity.MEDIUM,
                            fix=Fix.ENRICH,
                            detail="dynamic_cast<T*> returns nullptr on failure. Using the "
                                   "result without checking is an incomplete scan -- the cast "
                                   "failure path is invisible.",
                        ))
        return findings


def _enclosing_compound(node: Node) -> Node | None:
    """Walk up to the nearest compound_statement (function body)."""
    current = node.parent
    while current:
        if current.type == "function_definition":
            for child in current.children:
                if child.type == "compound_statement":
                    return child
        current = current.parent
    return None


# Bismillah ir-Rahman ir-Rahim
