# Bismillah ir-Rahman ir-Rahim
"""
furqan-lint -- structural honesty verification for code.

Six languages. One command. Catches what other linters miss.

    furqan-lint ./src/

Public API:
    lint_source(source, path, config=None) -> List[Finding]
    lint_file(path, config=None) -> (List[Finding], exit_code)
    lint_directory(directory, config=None) -> (List[Finding], exit_code)
"""

from furqan_lint.finding import Finding, Severity, Fix
from furqan_lint.runner import lint_source, lint_file, lint_directory

__version__ = "2.1.0"

__all__ = [
    "Finding",
    "Severity",
    "Fix",
    "lint_source",
    "lint_file",
    "lint_directory",
]

# Bismillah ir-Rahman ir-Rahim
