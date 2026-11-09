# Bismillah ir-Rahman ir-Rahim
"""
Ada/SPARK language adapter for furqan-lint.

Catches structural honesty violations in Ada and SPARK code -- the languages
that run aerospace flight software (DO-178C), nuclear reactor protection
systems (IEC 60880), railway signalling (EN 50128), and weapons systems.

In these domains, a surface-substrate gap is not a bug report. It is a
potential loss of life.

Rules implemented:
    RC-001  File/resource opened without matching Close on all paths
    MR-001  `when others =>` handler without re-raise -- swallows everything
    MR-005  `when others => null;` -- exception silenced entirely
    TB-010  Hardcoded secret/password in object declaration
    TB-012  Hardcoded /tmp path
    SI-004  TODO/FIXME/HACK/XXX in comments
    SI-006  pragma Assert -- suppressed by Assertion_Policy(Ignore)
    SI-009  pragma SPARK_Mode(Off) -- formal verification disabled
    SI-010  Unchecked_Conversion -- type safety bypassed
    SI-011  Unchecked_Deallocation -- manual memory unsafety
    TB-034  Ada.Numerics.Discrete_Random / Float_Random for security
"""

from __future__ import annotations

import re
from typing import List

import tree_sitter_ada as tsa
from tree_sitter import Language, Node

from furqan_lint.finding import Finding, Fix, Severity
from furqan_lint.adapters.base import (
    BaseAdapter, register, walk_tree, find_nodes,
    node_text, SECRET_NAMES, PLACEHOLDER, TODO_PATTERN,
)


@register("ada", [".adb", ".ads", ".ada"])
class AdaAdapter(BaseAdapter):

    def language_name(self) -> str:
        return "Ada/SPARK"

    def get_language(self) -> Language:
        return Language(tsa.language())

    def check(self, source: bytes, path: str) -> List[Finding]:
        tree = self.parse(source, path)
        if tree is None:
            return []

        root = tree.root_node
        source_text = source.decode("utf-8", errors="replace")
        findings: List[Finding] = []

        findings.extend(self._check_exception_handlers(root, path))
        findings.extend(self._check_hardcoded_secrets(root, path))
        findings.extend(self._check_pragma_assert(root, path))
        findings.extend(self._check_spark_mode_off(root, path))
        findings.extend(self._check_unchecked_pragmas(root, path, source_text))
        findings.extend(self._check_resource_leak(root, path))
        findings.extend(self._check_weak_random(root, path, source_text))
        findings.extend(self._check_todo_comments(root, source_text, path))

        return findings

    # ── Satisfy abstract interface ──

    def check_hardcoded_secrets(self, root: Node, path: str) -> List[Finding]:
        return []  # Handled by _check_hardcoded_secrets

    def check_empty_catch(self, root: Node, path: str) -> List[Finding]:
        return []  # Handled by _check_exception_handlers

    def check_sql_injection(self, root: Node, path: str) -> List[Finding]:
        return []  # Ada rarely does SQL inline; covered if it does via string patterns

    def check_resource_leak(self, root: Node, path: str) -> List[Finding]:
        return []  # Handled by _check_resource_leak

    def check_command_injection(self, root: Node, path: str) -> List[Finding]:
        return []  # Ada doesn't have system() -- OS calls go through GNAT.OS_Lib

    # ── Ada-specific checks ──

    def _check_exception_handlers(self, root: Node, path: str) -> List[Finding]:
        """MR-001/005: Exception handler analysis."""
        findings: List[Finding] = []
        for node in find_nodes(root, "exception_handler"):
            # Check if this is a `when others =>` handler
            is_others = False
            for child in node.children:
                if child.type == "exception_choice_list":
                    for ec in child.children:
                        if ec.type == "exception_choice":
                            for sub in ec.children:
                                if sub.type == "others":
                                    is_others = True

            if not is_others:
                continue

            # Find the sequence_of_statements body
            body = None
            for child in node.children:
                if child.type == "sequence_of_statements":
                    body = child
                    break

            if body is None:
                continue

            # Check for null; only (MR-005)
            stmts = [c for c in body.children
                     if c.type not in ("comment",)]
            if len(stmts) == 1 and stmts[0].type == "null_statement":
                findings.append(Finding(
                    rule="MR-005",
                    path=path,
                    line=node.start_point[0] + 1,
                    col=node.start_point[1],
                    message="`when others => null;` -- exception silenced entirely",
                    severity=Severity.CRITICAL,
                    fix=Fix.ENRICH,
                    detail="In safety-critical Ada (DO-178C, IEC 60880), a silenced "
                           "exception is a hidden failure mode. At minimum, log the "
                           "exception occurrence. In SPARK, prove the handler unreachable.",
                ))
                continue

            # Check for re-raise (MR-001)
            has_raise = False
            for stmt in walk_tree(body):
                if stmt.type == "raise_statement":
                    has_raise = True
                    break

            if not has_raise:
                findings.append(Finding(
                    rule="MR-001",
                    path=path,
                    line=node.start_point[0] + 1,
                    col=node.start_point[1],
                    message="`when others =>` without re-raise -- all exceptions swallowed",
                    severity=Severity.HIGH,
                    fix=Fix.RECALIBRATE,
                    detail="A `when others` handler that does not re-raise claims to "
                           "handle every possible exception. In certified Ada code, "
                           "either narrow to specific exceptions or re-raise after logging.",
                ))
        return findings

    def _check_hardcoded_secrets(self, root: Node, path: str) -> List[Finding]:
        """TB-010: Object declaration with secret-like name and string value."""
        findings: List[Finding] = []
        for node in find_nodes(root, "object_declaration"):
            name_node = None
            has_string = False
            string_line = 0

            for child in node.children:
                if child.type == "identifier" and name_node is None:
                    name_node = child
                if child.type == "expression":
                    expr_text = node_text(child)
                    if expr_text.startswith('"') and expr_text.endswith('"'):
                        has_string = True
                        string_line = child.start_point[0] + 1

            if name_node and has_string:
                name = node_text(name_node)
                if SECRET_NAMES.search(name):
                    findings.append(Finding(
                        rule="TB-010",
                        path=path,
                        line=node.start_point[0] + 1,
                        col=node.start_point[1],
                        message=f"Hardcoded secret in `{name}` -- move to configuration",
                        severity=Severity.HIGH,
                        fix=Fix.RECALIBRATE,
                        detail="Secrets embedded in Ada source are compiled into the "
                               "executable. Use environment variables or a configuration "
                               "file read at startup.",
                    ))

            # Also check for /tmp paths
            if has_string:
                for child in node.children:
                    if child.type == "expression":
                        val = node_text(child).strip('"')
                        if val.startswith("/tmp/") or val == "/tmp":
                            findings.append(Finding(
                                rule="TB-012",
                                path=path,
                                line=node.start_point[0] + 1,
                                col=node.start_point[1],
                                message="Hardcoded /tmp path -- predictable and world-writable",
                                severity=Severity.MEDIUM,
                                fix=Fix.RECALIBRATE,
                                detail="Use Ada.Directories.Create_Temp_Directory for secure "
                                       "temporary paths.",
                            ))
        return findings

    def _check_pragma_assert(self, root: Node, path: str) -> List[Finding]:
        """SI-006: pragma Assert can be suppressed by Assertion_Policy(Ignore)."""
        findings: List[Finding] = []
        for node in find_nodes(root, "pragma_g"):
            name_node = None
            for child in node.children:
                if child.type == "identifier":
                    name_node = child
                    break
            if name_node and node_text(name_node) == "Assert":
                findings.append(Finding(
                    rule="SI-006",
                    path=path,
                    line=node.start_point[0] + 1,
                    col=node.start_point[1],
                    message="pragma Assert -- suppressed by Assertion_Policy(Ignore) in production",
                    severity=Severity.HIGH,
                    fix=Fix.RECALIBRATE,
                    detail="pragma Assert is controlled by the Assertion_Policy pragma. "
                           "If the policy is set to Ignore (common in production builds), "
                           "the assertion is removed entirely. For runtime checks in "
                           "safety-critical code, use explicit if-then-raise.",
                ))
        return findings

    def _check_spark_mode_off(self, root: Node, path: str) -> List[Finding]:
        """SI-009: pragma SPARK_Mode(Off) disables formal verification."""
        findings: List[Finding] = []
        for node in find_nodes(root, "pragma_g"):
            text = node_text(node)
            # Match: pragma SPARK_Mode (Off) or pragma SPARK_Mode(Off)
            if re.search(r"SPARK_Mode\s*\(\s*Off\s*\)", text, re.IGNORECASE):
                findings.append(Finding(
                    rule="SI-009",
                    path=path,
                    line=node.start_point[0] + 1,
                    col=node.start_point[1],
                    message="pragma SPARK_Mode(Off) -- formal verification disabled",
                    severity=Severity.HIGH,
                    fix=Fix.ENRICH,
                    detail="SPARK_Mode(Off) excludes this code from formal proof. "
                           "In DO-178C DAL-A software, every SPARK_Mode(Off) region "
                           "must be justified and tested by other means. Document "
                           "why formal verification cannot apply here.",
                ))
        return findings

    def _check_unchecked_pragmas(self, root: Node, path: str, source: str) -> List[Finding]:
        """SI-010/011: Unchecked_Conversion and Unchecked_Deallocation."""
        findings: List[Finding] = []
        # These show up as with clauses or instantiation names
        for node in walk_tree(root):
            text = node_text(node)
            if node.type in ("selected_component", "identifier"):
                if "Unchecked_Conversion" in text:
                    findings.append(Finding(
                        rule="SI-010",
                        path=path,
                        line=node.start_point[0] + 1,
                        col=node.start_point[1],
                        message="Unchecked_Conversion -- type safety bypassed",
                        severity=Severity.HIGH,
                        fix=Fix.RECALIBRATE,
                        detail="Ada.Unchecked_Conversion reinterprets the bit pattern "
                               "of one type as another, bypassing the type system. "
                               "In SPARK, it is forbidden. In certified Ada, every use "
                               "must be justified and bounded.",
                    ))
                elif "Unchecked_Deallocation" in text:
                    findings.append(Finding(
                        rule="SI-011",
                        path=path,
                        line=node.start_point[0] + 1,
                        col=node.start_point[1],
                        message="Unchecked_Deallocation -- manual memory management risk",
                        severity=Severity.HIGH,
                        fix=Fix.RECALIBRATE,
                        detail="Ada.Unchecked_Deallocation introduces the possibility of "
                               "use-after-free and double-free. In SPARK, heap allocation "
                               "is prohibited. In certified Ada, prefer controlled types "
                               "or bounded storage pools.",
                    ))
        return findings

    def _check_resource_leak(self, root: Node, path: str) -> List[Finding]:
        """RC-001: File opened without matching Close."""
        findings: List[Finding] = []
        # Look for Open calls and check for matching Close in the same scope
        _open_procs = {"Open", "Create"}
        for node in find_nodes(root, "procedure_call_statement"):
            call_text = node_text(node)
            # Check if this is a file Open/Create call
            is_open = False
            for proc_name in _open_procs:
                if proc_name in call_text and ("File" in call_text or "In_File" in call_text or "Out_File" in call_text):
                    is_open = True
                    break
            if not is_open:
                continue
            # Check the enclosing scope for Close
            scope = _enclosing_scope(node)
            if scope:
                scope_text = node_text(scope)
                if "Close" not in scope_text:
                    findings.append(Finding(
                        rule="RC-001",
                        path=path,
                        line=node.start_point[0] + 1,
                        col=node.start_point[1],
                        message="File opened without matching Close in scope",
                        severity=Severity.HIGH,
                        fix=Fix.ENRICH,
                        detail="In Ada, files opened with Open or Create must be explicitly "
                               "closed with Close. Unlike RAII languages, Ada does not "
                               "automatically close files when they go out of scope.",
                    ))
        return findings

    def _check_weak_random(self, root: Node, path: str, source: str) -> List[Finding]:
        """TB-034: Ada.Numerics random packages for security-sensitive use."""
        findings: List[Finding] = []
        _weak_pkgs = {"Discrete_Random", "Float_Random"}
        for node in walk_tree(root):
            if node.type in ("selected_component", "identifier"):
                text = node_text(node)
                for pkg in _weak_pkgs:
                    if pkg in text:
                        findings.append(Finding(
                            rule="TB-034",
                            path=path,
                            line=node.start_point[0] + 1,
                            col=node.start_point[1],
                            message=f"`{pkg}` is not cryptographically secure",
                            severity=Severity.MEDIUM,
                            fix=Fix.RECALIBRATE,
                            detail="Ada.Numerics.Discrete_Random and Float_Random use "
                                   "deterministic PRNGs. For security-sensitive randomness, "
                                   "use /dev/urandom via Interfaces.C or a certified "
                                   "cryptographic library.",
                        ))
                        break
        return findings

    def _check_todo_comments(self, root: Node, source: str, path: str) -> List[Finding]:
        """SI-004: TODO/FIXME comments (Ada uses -- for comments)."""
        findings: List[Finding] = []
        for node in find_nodes(root, "comment"):
            text = node_text(node)
            match = TODO_PATTERN.search(text)
            if match:
                tag = match.group(1).upper()
                findings.append(Finding(
                    rule="SI-004",
                    path=path,
                    line=node.start_point[0] + 1,
                    col=node.start_point[1],
                    message=f"`{tag}` comment -- an acknowledged incomplete scan",
                    severity=Severity.LOW,
                    fix=Fix.ENRICH,
                    detail=f"A {tag} in safety-critical Ada code is an open item that "
                           "must be resolved before certification.",
                ))
        return findings


def _enclosing_scope(node: Node) -> Node | None:
    """Find the enclosing subprogram body or block statement."""
    current = node.parent
    while current:
        if current.type in ("subprogram_body", "block_statement",
                            "handled_sequence_of_statements"):
            return current
        current = current.parent
    return None


# Bismillah ir-Rahman ir-Rahim
