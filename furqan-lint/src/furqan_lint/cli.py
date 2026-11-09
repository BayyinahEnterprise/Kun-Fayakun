# Bismillah ir-Rahman ir-Rahim
"""
furqan-lint standalone CLI entry point.

Usage:
    furqan-lint [options] [path ...]
    furqan-lint --help
"""

import sys

from furqan_lint.runner import run


def main():
    """Entry point for `furqan-lint` command."""
    sys.exit(run(sys.argv[1:]) or 0)


if __name__ == "__main__":
    main()

# Bismillah ir-Rahman ir-Rahim
