# Bismillah ir-Rahman ir-Rahim
"""
Base adapter: defines the interface every language adapter implements,
plus the tree-sitter helper utilities shared across all adapters.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

from tree_sitter import Language, Node, Parser, Tree

from furqan_lint.finding import Finding, Fix, Severity


# ── Language registry ──

_ADAPTERS: dict[str, type[BaseAdapter]] = {}
_EXTENSIONS: dict[str, str] = {}


def register(lang: str, extensions: list[str]):
    """Class decorator: register an adapter for a language and its file extensions."""
    def decorator(cls):
        _ADAPTERS[lang] = cls
        for ext in extensions:
            _EXTENSIONS[ext] = lang
        return cls
    return decorator


def get_adapter(path: str | Path) -> BaseAdapter | None:
    """Return the right adapter for a file path, or None if unsupported."""
    ext = Path(path).suffix.lower()
    lang = _EXTENSIONS.get(ext)
    if lang and lang in _ADAPTERS:
        return _ADAPTERS[lang]()
    return None


def supported_extensions() -> set[str]:
    """All file extensions furqan-lint can check."""
    return set(_EXTENSIONS.keys()) | {".py"}


# ── Shared utilities ──

# Regex patterns reused across adapters
SECRET_NAMES = re.compile(
    r"(password|passwd|pwd|secret|token|api_key|apikey|"
    r"auth_key|authkey|private_key|access_key|secret_key)",
    re.IGNORECASE,
)
PLACEHOLDER = re.compile(
    r"^(|none|null|todo|fixme|changeme|xxx|placeholder|example|test|default)$",
    re.IGNORECASE,
)
SQL_KEYWORDS = {
    "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE",
    "ALTER", "EXECUTE", "EXEC", "MERGE", "REPLACE",
}
TODO_PATTERN = re.compile(r"(TODO|FIXME|HACK|XXX)\b", re.IGNORECASE)


def node_text(node: Node) -> str:
    """Extract the source text of a tree-sitter node."""
    return node.text.decode("utf-8") if node.text else ""


def walk_tree(node: Node):
    """Yield every node in a tree-sitter tree (depth-first)."""
    yield node
    for child in node.children:
        yield from walk_tree(child)


def find_nodes(root: Node, type_name: str):
    """Yield all descendant nodes of a given type."""
    for node in walk_tree(root):
        if node.type == type_name:
            yield node


def string_value(node: Node) -> str | None:
    """Extract the unquoted string value from a string literal node."""
    text = node_text(node)
    if len(text) >= 2 and text[0] in ('"', "'") and text[-1] == text[0]:
        return text[1:-1]
    # Handle L"..." or @"..."
    if len(text) >= 3 and text[1] == '"' and text[-1] == '"':
        return text[2:-1]
    return text


def contains_sql(text: str) -> bool:
    """Check if a string likely contains SQL."""
    upper = text.upper()
    return any(kw in upper for kw in SQL_KEYWORDS)


# ── Base adapter ──

class BaseAdapter(ABC):
    """Interface every language adapter must implement."""

    @abstractmethod
    def language_name(self) -> str:
        """Human-readable language name, e.g. 'C', 'Java'."""
        ...

    @abstractmethod
    def get_language(self) -> Language:
        """Return the tree-sitter Language object."""
        ...

    def parse(self, source: bytes, path: str) -> Tree | None:
        """Parse source bytes into a tree-sitter Tree."""
        parser = Parser(self.get_language())
        tree = parser.parse(source)
        if tree.root_node.has_error:
            # Parse had errors but still produced a partial tree --
            # we work with what we have
            pass
        return tree

    def check(self, source: bytes, path: str) -> List[Finding]:
        """Run all checks on a source file. Override to add language-specific checks."""
        tree = self.parse(source, path)
        if tree is None:
            return []

        root = tree.root_node
        source_text = source.decode("utf-8", errors="replace")
        findings: List[Finding] = []

        # Universal checks that work across all languages
        findings.extend(self.check_hardcoded_secrets(root, path))
        findings.extend(self.check_todo_comments(source_text, path))
        findings.extend(self.check_empty_catch(root, path))
        findings.extend(self.check_sql_injection(root, path))
        findings.extend(self.check_insecure_hash(root, path))
        findings.extend(self.check_resource_leak(root, path))
        findings.extend(self.check_command_injection(root, path))

        return findings

    # ── Universal checks with language-specific node types ──

    @abstractmethod
    def check_hardcoded_secrets(self, root: Node, path: str) -> List[Finding]:
        """TB-010/011: Hardcoded passwords/secrets in assignments and defaults."""
        ...

    @abstractmethod
    def check_empty_catch(self, root: Node, path: str) -> List[Finding]:
        """MR-001/005: Empty or generic catch blocks."""
        ...

    @abstractmethod
    def check_sql_injection(self, root: Node, path: str) -> List[Finding]:
        """TB-018: SQL injection via string concatenation/formatting."""
        ...

    @abstractmethod
    def check_resource_leak(self, root: Node, path: str) -> List[Finding]:
        """RC-001+: Resources opened but not closed."""
        ...

    @abstractmethod
    def check_command_injection(self, root: Node, path: str) -> List[Finding]:
        """TB-015/016: Shell command execution."""
        ...

    def check_todo_comments(self, source: str, path: str) -> List[Finding]:
        """SI-004: TODO/FIXME/HACK/XXX comments (universal -- works on raw text)."""
        findings: List[Finding] = []
        for lineno, line in enumerate(source.splitlines(), 1):
            # Only look in comments
            stripped = line.lstrip()
            if not (stripped.startswith("//") or stripped.startswith("/*")
                    or stripped.startswith("*") or stripped.startswith("#")
                    or stripped.startswith("--")):
                continue
            match = TODO_PATTERN.search(line)
            if match:
                tag = match.group(1).upper()
                findings.append(Finding(
                    rule="SI-004",
                    path=path,
                    line=lineno,
                    col=match.start(),
                    message=f"`{tag}` comment -- an acknowledged incomplete scan",
                    severity=Severity.LOW,
                    fix=Fix.ENRICH,
                    detail=f"A {tag} comment is an honest admission that the scan is "
                           "incomplete. Either complete the work or document why it "
                           "remains open.",
                ))
        return findings

    def check_insecure_hash(self, root: Node, path: str) -> List[Finding]:
        """TB-021: Insecure hash usage (universal pattern matching)."""
        findings: List[Finding] = []
        weak = {"md5", "sha1", "md4", "sha", "MD5", "SHA1", "SHA-1", "MD4"}
        for node in walk_tree(root):
            if node.type == "string_literal" or node.type == "string":
                val = string_value(node)
                if val and val in weak:
                    findings.append(Finding(
                        rule="TB-021",
                        path=path,
                        line=node.start_point[0] + 1,
                        col=node.start_point[1],
                        message=f"Insecure hash algorithm `{val}` referenced",
                        severity=Severity.MEDIUM,
                        fix=Fix.RECALIBRATE,
                        detail="MD5 and SHA1 are broken for security use. "
                               "Use SHA-256 or better.",
                    ))
        return findings


# Bismillah ir-Rahman ir-Rahim
