"""These seven modules import the multi-language adapters, which need the
optional ``furqan`` extra (tree-sitter and its grammars). Without it they
are skipped, not errored, so the rest of the suite still collects."""
import importlib.util

_NEEDS_TREE_SITTER = [
    "test_adapters.py", "test_adapters_ada.py", "test_adapters_cpp_csharp.py",
    "test_bandit_absorption.py", "test_checks_v2.py",
    "test_config_and_output.py", "test_repaired_rules.py",
]
collect_ignore = [] if importlib.util.find_spec("tree_sitter") else _NEEDS_TREE_SITTER
