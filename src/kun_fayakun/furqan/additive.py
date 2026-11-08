"""Additive-only API checker for Python modules.

Phase 2 ships this as a Python-native checker rather than wrapping
Furqan's :func:`check_additive`. The Furqan checker compares
:class:`AdditiveOnlyModuleDecl` blocks with explicit
:class:`VersionLiteral` and :class:`ExportDecl` nodes, which Python
does not have. The Python equivalent is the module's public surface,
defined as:

* if ``__all__`` is set (list or tuple of string literals): exactly
  those names;
* otherwise: every top-level name that does not start with an
  underscore. v0.3.0 collects functions, classes, plain assignments
  (single ``Name`` and tuple-target), and PEP 526 annotated
  assignments (``X: int = 5``).

The contract is one-directional: removing a public name fires a
:class:`Marad`; adding one is silent. Renames are detected as a
remove-and-add pair (the removed name fires; the added name is
ignored). Phase 3+ may add a rename catalog so the user can declare a
rename explicitly the way Furqan's ``major_version_bump`` block does.

If ``__all__`` cannot be statically determined (the value isn't a
list/tuple of string literals), the checker raises
:class:`DynamicAllError`. v0.3.0 chose to refuse rather than fall
back: claiming the surface is clean when we cannot read the surface
is the failure mode this project exists to prevent.
"""

from __future__ import annotations

import ast

from furqan.errors.marad import Marad
from furqan.parser.ast_nodes import SourceSpan


class DynamicAllError(Exception):
    """Raised when a module declares ``__all__`` but the value is not
    a static list/tuple of string literals (for example,
    ``__all__ = list(_NAMES)`` or ``__all__ += [...]``).

    The checker cannot decide what the public surface is in that
    case, and has chosen refusal over fallback: silently treating
    the surface as empty would report every previously-public name
    as removed; silently falling back to top-level non-underscore
    names would mask real removals. Either choice produces dishonest
    output. Refusing is the structurally honest move.
    """

    def __init__(self, where: str = "?", detail: str = "") -> None:
        self.where = where
        self.detail = detail
        message = f"could not statically determine __all__ in the {where} version"
        if detail:
            message = f"{message}: {detail}"
        super().__init__(message)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


# Language-aware re-export hint prose. Each entry is a format
# string with one ``{name}`` placeholder. The Python form preserves
# the v0.3.0 wording (compatibility-alias assignment); the Rust
# form points at ``pub use ... as`` re-exports; the Go form points
# at ``var Name = <new>`` package-level re-exports. Adding a new
# language only needs an entry here plus the call site passing
# ``language=<key>``.
_RENAME_HINT: dict[str, str] = {
    "python": "Restore '{name}' in the current version, or add a compatibility alias: {name} = <new_name>",
    "rust": "Restore '{name}' in the current version, or add a re-export: pub use <new> as {name};",
    "go": "Restore '{name}' in the current version, or add a re-export: var {name} = <new>",
    "onnx": "Restore '{name}' in the model's graph.output, or add a compatibility wrapper that maps the new name to the old name at inference time.",
}


def compare_name_sets(
    previous_names: frozenset[str] | set[str],
    current_names: frozenset[str] | set[str],
    filename: str,
    *,
    language: str = "python",
) -> list[Marad]:
    """Language-agnostic public-name set diff.

    Returns one :class:`Marad` per name present in
    ``previous_names`` and absent from ``current_names``. The
    diagnostic prose's ``minimal_fix`` is language-aware via the
    module-private ``_RENAME_HINT`` map: Python users see
    ``Name = <new_name>`` alias syntax, Rust users see
    ``pub use <new> as Name;``, Go users see
    ``var Name = <new>``.

    The set extraction is the caller's responsibility -- this
    function operates on already-collected name sets so the same
    language-agnostic body serves the Python, Rust (future), and
    Go diff paths. Diagnostics are emitted in sorted name order
    for stability.

    ``language`` defaults to ``"python"`` to preserve the historic
    diagnostic prose for the Python entry point. Unknown
    ``language`` values fall back to the Python hint rather than
    raising; the registered languages are an inventory, not a
    correctness boundary.
    """
    hint_template = _RENAME_HINT.get(language, _RENAME_HINT["python"])
    removed = sorted(set(previous_names) - set(current_names))
    diagnostics: list[Marad] = []
    for name in removed:
        diagnostics.append(
            Marad(
                primitive="additive_only",
                diagnosis=(
                    f"Public name '{name}' was present in the "
                    f"previous version but is absent in the current "
                    f"version. Removing a public name breaks the "
                    f"additive-only contract: you can add to a "
                    f"module's public interface but never remove or "
                    f"rename."
                ),
                location=SourceSpan(file=filename, line=1, column=0),
                minimal_fix=hint_template.format(name=name),
                regression_check=(
                    f"After restoring '{name}', re-run "
                    f"`furqan-lint diff <old> <new>` and confirm "
                    f"PASS."
                ),
            )
        )
    return diagnostics


def check_additive_api(
    current_source: str,
    previous_source: str,
    filename: str = "<module>",
) -> list[Marad]:
    """Python-specific wrapper. Compare two versions of a module's
    public API.

    Returns one :class:`Marad` per public name that was present in
    ``previous_source`` and absent in ``current_source``. The
    diagnostics are emitted in sorted name order so callers (and
    tests) get a stable sequence.

    Raises :class:`DynamicAllError` if either source declares
    ``__all__`` non-statically. The CLI maps this to exit code 2.

    Implementation: extracts both Python public-name sets via
    :func:`_extract_public_names` (which is Python-bound: it walks
    an ``ast.parse`` tree) and delegates to the language-agnostic
    :func:`compare_name_sets`. The signature is preserved for
    backward compatibility -- callers that imported
    ``check_additive_api`` continue to work without changes.
    """
    try:
        current_names = _extract_public_names(current_source)
    except DynamicAllError as e:
        raise DynamicAllError("new", e.detail) from e
    try:
        previous_names = _extract_public_names(previous_source)
    except DynamicAllError as e:
        raise DynamicAllError("old", e.detail) from e
    return compare_name_sets(
        previous_names=frozenset(previous_names),
        current_names=frozenset(current_names),
        filename=filename,
        language="python",
    )


# ---------------------------------------------------------------------------
# Public-surface extraction
# ---------------------------------------------------------------------------


def _extract_public_names(source: str) -> set[str]:
    """Return the set of public names exposed by ``source``.

    Looks for an ``__all__`` assignment first (plain ``Assign`` or
    PEP 526 ``AnnAssign``); if present, returns exactly the names
    listed. Otherwise returns every top-level function, class,
    plain assignment, tuple-target assignment, or annotated
    assignment whose name does not start with an underscore.

    Raises :class:`DynamicAllError` if ``__all__`` is set but its
    value cannot be statically read as a list/tuple of string
    literals.
    """
    tree = ast.parse(source)

    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    return _extract_all_list(node.value)
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "__all__"
            and node.value is not None
        ):
            return _extract_all_list(node.value)

    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            if not node.name.startswith("_"):
                names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if not target.id.startswith("_"):
                        names.add(target.id)
                elif isinstance(target, ast.Tuple):
                    for elt in target.elts:
                        if isinstance(elt, ast.Name) and not elt.id.startswith("_"):
                            names.add(elt.id)
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and not node.target.id.startswith("_")
        ):
            names.add(node.target.id)
    return names


def _extract_all_list(node: ast.expr) -> set[str]:
    """Extract string-literal names from ``__all__ = [...]`` or
    ``__all__ = (...)``.

    Raises :class:`DynamicAllError` when the value isn't a literal
    list/tuple, or when any element isn't a string literal. The
    refusal to silently fall back is deliberate: a partial read of
    a dynamic ``__all__`` produces dishonest output (false positives
    for names that aren't actually removed, false negatives for
    names that are).
    """
    if not isinstance(node, ast.List | ast.Tuple):
        raise DynamicAllError(
            detail=(f"value is a {type(node).__name__}, not a literal list or tuple")
        )
    names: set[str] = set()
    for elt in node.elts:
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            names.add(elt.value)
        else:
            raise DynamicAllError(
                detail=(f"element at index {node.elts.index(elt)} is not a string literal")
            )
    return names
