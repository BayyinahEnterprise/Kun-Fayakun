"""Typed exceptions for the Go adapter.

Defined in a leaf module so ``__init__.py`` can import them without
triggering the lazy parser/translator imports at package load time.
Mirrors the v0.7.0.1 ``RustExtrasNotInstalled`` pattern for the
Rust adapter.
"""

from __future__ import annotations


class GoExtrasNotInstalled(ImportError):
    """Raised when the Go adapter is invoked but the bundled
    ``goast`` binary is not present.

    Subclasses ``ImportError`` so callers that catch ``ImportError``
    broadly still work; the typed name lets the CLI distinguish a
    missing-binary case from an unrelated import bug. The exception
    message is the install hint itself, so the CLI can simply
    ``print(str(exc))`` to stderr.
    """


class GoParseError(Exception):
    """Raised when the bundled ``goast`` binary fails to parse a
    .go source file (Go syntax error). Carries the binary's
    stderr output so the CLI can render a useful message and
    return exit 2 (PARSE ERROR).
    """
