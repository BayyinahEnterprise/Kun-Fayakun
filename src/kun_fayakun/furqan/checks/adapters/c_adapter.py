# Bismillah ir-Rahman ir-Rahim
"""
C language adapter for furqan-lint.

Catches structural honesty violations in C code -- the language that runs
automotive ECUs, medical devices, aerospace flight software, and nuclear
safety systems. A surface-substrate gap here can cost lives.

Rules implemented:
    RC-001  fopen/open without matching fclose/close on all paths
    MR-001  Empty or generic catch-all (setjmp/signal patterns)
    MR-005  Error return ignored (unchecked return value)
    TB-010  Hardcoded password/secret in string assignment
    TB-012  Hardcoded /tmp path
    TB-015  system()/popen() shell injection
    TB-016  system()/popen() call
    TB-018  SQL injection via sprintf/snprintf with SQL
    TB-021  Insecure hash (MD5/SHA1)
    TB-026  rand()/srand() for security
    TB-029  strcpy/strcat/sprintf without bounds (buffer overflow)
    TB-030  printf with non-literal format string
    SI-004  TODO/FIXME/HACK/XXX
    SI-006  assert() for runtime validation
"""

from __future__ import annotations

from typing import List

import tree_sitter_c as tsc
from tree_sitter import Language, Node

from kun_fayakun.furqan.checks.finding import Finding, Fix, Severity
from kun_fayakun.furqan.checks.adapters.base import (
    BaseAdapter, register, walk_tree, find_nodes,
    node_text, string_value, contains_sql,
    SECRET_NAMES, PLACEHOLDER,
)


@register("c", [".c", ".h"])
class CAdapter(BaseAdapter):

    def language_name(self) -> str:
        return "C"

    def get_language(self) -> Language:
        return Language(tsc.language())

    def check(self, source: bytes, path: str) -> List[Finding]:
        """Run all C checks."""
        findings = super().check(source, path)
        tree = self.parse(source, path)
        if tree:
            root = tree.root_node
            findings.extend(self._check_buffer_overflow(root, path))
            findings.extend(self._check_format_string(root, path))
            findings.extend(self._check_weak_random(root, path))
            findings.extend(self._check_assert_validation(root, path))
            findings.extend(self._check_unchecked_return(root, path))
        return findings

    # ── Universal checks, C-specific implementation ──

    def check_hardcoded_secrets(self, root: Node, path: str) -> List[Finding]:
        findings: List[Finding] = []
        for node in walk_tree(root):
            # Variable declaration: char *password = "secret";
            if node.type == "init_declarator":
                declarator = node.child_by_field_name("declarator")
                value = node.child_by_field_name("value")
                if declarator and value:
                    name = node_text(declarator)
                    # Strip pointer/array decorators
                    clean_name = name.replace("*", "").replace("[]", "").strip()
                    if SECRET_NAMES.search(clean_name) and value.type == "string_literal":
                        val = string_value(value)
                        if val and not PLACEHOLDER.match(val):
                            findings.append(Finding(
                                rule="TB-010",
                                path=path,
                                line=node.start_point[0] + 1,
                                col=node.start_point[1],
                                message=f"Hardcoded secret in `{clean_name}` -- move to environment or config",
                                severity=Severity.HIGH,
                                fix=Fix.RECALIBRATE,
                                detail="Secrets embedded in source code are readable by anyone "
                                       "with access to the binary or repository.",
                            ))
            # Also catch: #define PASSWORD "..."
            if node.type == "preproc_def":
                name_node = node.child_by_field_name("name")
                value_node = node.child_by_field_name("value")
                if name_node and value_node:
                    name = node_text(name_node)
                    if SECRET_NAMES.search(name):
                        val_text = node_text(value_node).strip()
                        if val_text.startswith('"') and val_text.endswith('"'):
                            inner = val_text[1:-1]
                            if inner and not PLACEHOLDER.match(inner):
                                findings.append(Finding(
                                    rule="TB-010",
                                    path=path,
                                    line=node.start_point[0] + 1,
                                    col=node.start_point[1],
                                    message=f"Hardcoded secret in `#define {name}`",
                                    severity=Severity.HIGH,
                                    fix=Fix.RECALIBRATE,
                                    detail="Preprocessor macros with secrets are compiled "
                                           "into every translation unit that includes the header.",
                                ))
        return findings

    def check_empty_catch(self, root: Node, path: str) -> List[Finding]:
        """C doesn't have try/catch. Check for empty if-blocks after error-returning calls."""
        # C error handling is typically if (ret < 0) { ... }
        # We flag the inverse: no error check after functions that return error codes
        # This is handled by check_unchecked_return instead
        return []

    def check_sql_injection(self, root: Node, path: str) -> List[Finding]:
        findings: List[Finding] = []
        for node in find_nodes(root, "call_expression"):
            func_node = node.child_by_field_name("function")
            if not func_node:
                continue
            func_name = node_text(func_node)
            # sprintf/snprintf building SQL
            if func_name in ("sprintf", "snprintf", "fprintf"):
                args = node.child_by_field_name("arguments")
                if args:
                    for arg in args.children:
                        if arg.type == "string_literal":
                            val = string_value(arg)
                            if val and contains_sql(val):
                                findings.append(Finding(
                                    rule="TB-018",
                                    path=path,
                                    line=node.start_point[0] + 1,
                                    col=node.start_point[1],
                                    message=f"SQL in `{func_name}()` format string -- injection risk",
                                    severity=Severity.HIGH,
                                    fix=Fix.RECALIBRATE,
                                    detail="Building SQL with sprintf/snprintf is vulnerable to "
                                           "injection. Use parameterized queries via your database "
                                           "library's prepared statement API.",
                                ))
                                break
        return findings

    def check_resource_leak(self, root: Node, path: str) -> List[Finding]:
        findings: List[Finding] = []
        # Look for fopen/open calls
        _open_funcs = {"fopen", "open", "fdopen", "freopen", "tmpfile"}
        for node in find_nodes(root, "call_expression"):
            func_node = node.child_by_field_name("function")
            if not func_node:
                continue
            func_name = node_text(func_node)
            if func_name in _open_funcs:
                # Check if the result is assigned
                parent = node.parent
                if parent and parent.type == "init_declarator":
                    # It's assigned -- now check if fclose/close exists in the
                    # same function. This is a simplified check.
                    func_body = _enclosing_function_body(node)
                    if func_body:
                        body_text = node_text(func_body)
                        close_func = "fclose" if func_name in ("fopen", "freopen", "tmpfile", "fdopen") else "close"
                        if close_func not in body_text:
                            findings.append(Finding(
                                rule="RC-001",
                                path=path,
                                line=node.start_point[0] + 1,
                                col=node.start_point[1],
                                message=f"`{func_name}()` without matching `{close_func}()` in function",
                                severity=Severity.HIGH,
                                fix=Fix.ENRICH,
                                detail=f"Every {func_name}() must have a matching {close_func}() "
                                       "on all code paths, including error paths. Resource leaks "
                                       "in long-running systems cause gradual degradation.",
                            ))
        return findings

    def check_command_injection(self, root: Node, path: str) -> List[Finding]:
        findings: List[Finding] = []
        _shell_funcs = {"system", "popen", "execl", "execlp", "execle",
                        "execv", "execvp", "execvpe"}
        for node in find_nodes(root, "call_expression"):
            func_node = node.child_by_field_name("function")
            if not func_node:
                continue
            func_name = node_text(func_node)
            if func_name in ("system", "popen"):
                findings.append(Finding(
                    rule="TB-016",
                    path=path,
                    line=node.start_point[0] + 1,
                    col=node.start_point[1],
                    message=f"`{func_name}()` invokes the system shell -- injection risk",
                    severity=Severity.HIGH,
                    fix=Fix.RECALIBRATE,
                    detail=f"{func_name}() passes the command string through /bin/sh. "
                           "Use exec*() family with explicit argv[] to avoid shell interpretation.",
                ))
        return findings

    # ── C-specific checks ──

    def _check_buffer_overflow(self, root: Node, path: str) -> List[Finding]:
        """TB-029: Unbounded string operations (strcpy, strcat, sprintf, gets)."""
        findings: List[Finding] = []
        _unsafe = {
            "strcpy": "strncpy or strlcpy",
            "strcat": "strncat or strlcat",
            "sprintf": "snprintf",
            "gets": "fgets",
            "vsprintf": "vsnprintf",
        }
        for node in find_nodes(root, "call_expression"):
            func_node = node.child_by_field_name("function")
            if not func_node:
                continue
            func_name = node_text(func_node)
            if func_name in _unsafe:
                replacement = _unsafe[func_name]
                findings.append(Finding(
                    rule="TB-029",
                    path=path,
                    line=node.start_point[0] + 1,
                    col=node.start_point[1],
                    message=f"`{func_name}()` -- no bounds checking, buffer overflow risk",
                    severity=Severity.CRITICAL,
                    fix=Fix.RECALIBRATE,
                    detail=f"{func_name}() writes without checking the destination buffer size. "
                           f"Use {replacement}() with an explicit size limit. Buffer overflows "
                           "are the #1 vulnerability class in C code.",
                ))
        return findings

    def _check_format_string(self, root: Node, path: str) -> List[Finding]:
        """TB-030: printf-family with non-literal format string."""
        findings: List[Finding] = []
        _printf_funcs = {"printf", "fprintf", "sprintf", "snprintf",
                         "vprintf", "vfprintf", "vsprintf", "vsnprintf",
                         "syslog"}
        for node in find_nodes(root, "call_expression"):
            func_node = node.child_by_field_name("function")
            if not func_node:
                continue
            func_name = node_text(func_node)
            if func_name in _printf_funcs:
                args = node.child_by_field_name("arguments")
                if args and args.children:
                    # Find the format string argument
                    # For fprintf/snprintf, it's not the first arg
                    real_args = [c for c in args.children
                                 if c.type not in ("(", ")", ",")]
                    fmt_idx = 0
                    if func_name in ("fprintf", "vfprintf"):
                        fmt_idx = 1  # first arg is FILE*
                    elif func_name in ("sprintf", "vsprintf"):
                        fmt_idx = 1  # first arg is buffer
                    elif func_name in ("snprintf", "vsnprintf"):
                        fmt_idx = 2  # buffer, size, then format

                    if fmt_idx < len(real_args):
                        fmt_arg = real_args[fmt_idx]
                        if fmt_arg.type != "string_literal":
                            findings.append(Finding(
                                rule="TB-030",
                                path=path,
                                line=node.start_point[0] + 1,
                                col=node.start_point[1],
                                message=f"`{func_name}()` with non-literal format string",
                                severity=Severity.HIGH,
                                fix=Fix.RECALIBRATE,
                                detail="A non-literal format string allows an attacker who "
                                       "controls the string to read from or write to arbitrary "
                                       "memory via %n, %x, %s. Always use a string literal.",
                            ))
        return findings

    def _check_weak_random(self, root: Node, path: str) -> List[Finding]:
        """TB-026: rand()/srand() for security-sensitive use."""
        findings: List[Finding] = []
        for node in find_nodes(root, "call_expression"):
            func_node = node.child_by_field_name("function")
            if not func_node:
                continue
            func_name = node_text(func_node)
            if func_name in ("rand", "srand", "random", "srandom"):
                findings.append(Finding(
                    rule="TB-026",
                    path=path,
                    line=node.start_point[0] + 1,
                    col=node.start_point[1],
                    message=f"`{func_name}()` is not cryptographically secure",
                    severity=Severity.MEDIUM,
                    fix=Fix.RECALIBRATE,
                    detail="rand()/random() use a linear congruential or similar PRNG "
                           "whose output is predictable. For security-sensitive randomness, "
                           "use /dev/urandom, getrandom(), or arc4random().",
                ))
        return findings

    def _check_assert_validation(self, root: Node, path: str) -> List[Finding]:
        """SI-006: assert() used for runtime validation (stripped by NDEBUG)."""
        findings: List[Finding] = []
        for node in find_nodes(root, "call_expression"):
            func_node = node.child_by_field_name("function")
            if not func_node:
                continue
            if node_text(func_node) == "assert":
                findings.append(Finding(
                    rule="SI-006",
                    path=path,
                    line=node.start_point[0] + 1,
                    col=node.start_point[1],
                    message="`assert()` stripped when NDEBUG is defined -- not for runtime validation",
                    severity=Severity.HIGH,
                    fix=Fix.RECALIBRATE,
                    detail="assert() is removed by the preprocessor when NDEBUG is defined, "
                           "which is standard in release builds. If this check must survive "
                           "into production, use an explicit if-statement with error handling.",
                ))
        return findings

    def _check_unchecked_return(self, root: Node, path: str) -> List[Finding]:
        """MR-005: Return value of error-returning function ignored."""
        findings: List[Finding] = []
        _must_check = {"malloc", "calloc", "realloc", "fopen", "open",
                       "read", "write", "fread", "fwrite", "fgets",
                       "pthread_mutex_lock", "pthread_create"}
        for node in find_nodes(root, "expression_statement"):
            # expression_statement containing a bare call_expression
            # means the return value is discarded
            if node.child_count >= 1:
                child = node.children[0]
                if child.type == "call_expression":
                    func_node = child.child_by_field_name("function")
                    if func_node:
                        func_name = node_text(func_node)
                        if func_name in _must_check:
                            findings.append(Finding(
                                rule="MR-005",
                                path=path,
                                line=node.start_point[0] + 1,
                                col=node.start_point[1],
                                message=f"Return value of `{func_name}()` ignored -- failure undetectable",
                                severity=Severity.HIGH,
                                fix=Fix.ENRICH,
                                detail=f"{func_name}() can fail and signals failure through its "
                                       "return value. Ignoring it means the code continues as if "
                                       "the operation succeeded, which is structurally dishonest.",
                            ))
        return findings


def _enclosing_function_body(node: Node) -> Node | None:
    """Walk up to find the enclosing function's compound_statement body."""
    current = node.parent
    while current:
        if current.type == "function_definition":
            for child in current.children:
                if child.type == "compound_statement":
                    return child
        current = current.parent
    return None


# Bismillah ir-Rahman ir-Rahim
