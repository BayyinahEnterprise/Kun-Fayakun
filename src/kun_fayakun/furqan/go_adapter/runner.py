"""Run structural checkers on a translated Go ``Module``.

Wires two checkers (current as of v0.8.0):

* **D24 (all-paths-return)** via upstream
  ``furqan.checker.check_all_paths_return``. Same upstream
  primitive as the Python and Rust runners.
* **D11 (status-coverage with the Go ``(T, error)`` firing
  shape)** via upstream ``check_status_coverage`` with the
  cross-language ``_is_may_fail_producer`` predicate from
  ``furqan_lint.runner``. Shape B per ADR-002 §10 Q3 follow-up:
  the predicate recognises Python ``Optional[T]``, Rust
  ``Option<T>`` / ``Result<T, E>``, AND Go's ``(T, error)``.

Order: D24 -> D11. They are independent of each other.

Out of scope for v0.8.x (potential future-phase candidates):

* R3 (zero-return): Go has no Rust-style ``panic!()`` /
  ``todo!()`` body-shape analogue. The closest equivalent is
  ``log.Fatal()`` / ``os.Exit()`` which is a function call, not
  a body shape. Deferred until a concrete user-reported false
  negative motivates the design.
* Generics, cross-package symbol resolution, ``go/types``: see
  ADR-002.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from furqan.checker.all_paths_return import check_all_paths_return
from furqan.checker.status_coverage import check_status_coverage

from furqan_lint.runner import _is_may_fail_producer

if TYPE_CHECKING:
    from furqan.parser.ast_nodes import Module


def check_go_module(module: Module) -> list[tuple[str, object]]:
    """Run the v0.8.0 Go checker pipeline on a translated Module.

    Pipeline: D24 -> D11. R3 (check_ring_close) is NOT wired
    because Go has no body-shape analogue to Rust's
    annotated-fn-with-empty-body pattern; deferred to whichever
    Phase introduces a Go-specific zero-return checker, if any.

    D11 uses the cross-language ``_is_may_fail_producer``
    predicate from ``furqan_lint.runner`` (Shape B per ADR-002
    §10 Q3 follow-up). The predicate fires on Go's ``(T, error)``
    return shape; a caller declaring a concrete return type and
    calling a ``(T, error)``-returning helper without propagating
    the error union is flagged with D11 status_coverage.
    """
    diagnostics: list[tuple[str, object]] = []
    for d in check_all_paths_return(module):
        diagnostics.append(("all_paths_return", d))
    for d in check_status_coverage(module, producer_predicate=_is_may_fail_producer):
        diagnostics.append(("status_coverage", d))
    return diagnostics
