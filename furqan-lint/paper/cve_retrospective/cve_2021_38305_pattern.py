# Bismillah ir-Rahman ir-Rahim
"""
CVE-2021-38305 pattern: Yamale eval() on untrusted schema input.

Yamale's schema parser passed user-controlled YAML schema strings
to eval(), allowing arbitrary code execution even with restricted
builtins. CVSS 7.5.

furqan-lint rule mapping: TB-005 (eval/exec on potentially untrusted input)
"""
import ast

def parse_schema_vulnerable(schema_string):
    """Vulnerable: eval on user-controlled schema content."""
    safe_builtins = {"True": True, "False": False, "None": None}
    tree = ast.parse(schema_string, mode='eval')
    # BUG: eval with restricted builtins is still exploitable
    # Attacker can use: ().__class__.__bases__[0].__subclasses__()
    return eval(compile(tree, '', 'eval'), {'__builtins__': safe_builtins})

def parse_schema_fixed(schema_string, allowed_types):
    """Fixed: whitelist check instead of eval."""
    tree = ast.parse(schema_string, mode='eval')
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id not in allowed_types:
            raise ValueError(f"Disallowed type in schema: {node.id}")
        if isinstance(node, ast.Attribute):
            raise ValueError("Attribute access not allowed in schema")
    return ast.literal_eval(schema_string)
# Bismillah ir-Rahman ir-Rahim
