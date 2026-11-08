"""furqan-lint: structural-honesty checks for Python."""

__version__ = "1.0.2"

# Explicit public surface declaration. The implicit surface (anything
# not starting with an underscore at module level) is fragile: any
# module-level binding leaks. The explicit ``__all__`` is what the
# additive-only discipline needs to track. Per Bayyinah Engineering
# Discipline Framework section 7.6, every shipped minor and patch
# version gets a named frozenset constant in
# ``tests/test_top_level_public_surface_additive.py``; the current
# tuple here is the source of truth that those constants must remain
# subsets of.
__all__ = ("__version__",)
