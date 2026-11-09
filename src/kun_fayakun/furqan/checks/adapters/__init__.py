# Bismillah ir-Rahman ir-Rahim
"""
Multi-language adapters for furqan-lint structural honesty checks.

Each adapter translates the universal rule set into tree-sitter queries
for a specific language. The adapter produces the same Finding objects
as the Python checks, so config, filtering, and output formatting
work identically across all languages.

Supported languages:
    C       via tree-sitter-c
    C++     via tree-sitter-cpp
    Java    via tree-sitter-java
    C#      via tree-sitter-c-sharp
"""

from kun_fayakun.furqan.checks.adapters.base import BaseAdapter, get_adapter

__all__ = ["BaseAdapter", "get_adapter"]

# Bismillah ir-Rahman ir-Rahim
