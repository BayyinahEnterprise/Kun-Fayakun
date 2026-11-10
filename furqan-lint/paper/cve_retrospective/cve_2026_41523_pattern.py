# Bismillah ir-Rahman ir-Rahim
"""
CVE-2026-41523 pattern: vLLM assert-based security check bypass.

vLLM used assert to restrict which activation functions could be loaded
from untrusted model configs. Python -O strips asserts, allowing
arbitrary module loading and code execution. CVSS 7.5.

Fixed in vLLM 0.22.0.

furqan-lint rule mapping: SI-006 (assert used for validation -- stripped by -O),
SI-007 (hasattr swallows AttributeError)
"""

def load_activation_vulnerable(config):
    """Vulnerable pattern from vLLM (simplified from actual code)."""
    function_name = None
    if hasattr(config, "sentence_transformers") \
       and "activation_fn" in config.sentence_transformers:
        function_name = config.sentence_transformers["activation_fn"]
    elif hasattr(config, "sbert_ce_default_activation_function") \
         and config.sbert_ce_default_activation_function is not None:
        function_name = config.sbert_ce_default_activation_function

    if function_name is not None:
        # BUG: assert is the ONLY security check -- stripped by python -O
        assert function_name.startswith("torch.nn.modules."), (
            "Loading restricted to torch.nn.modules"
        )
        # With -O, attacker can load os.system, subprocess.call, etc.
        fn = resolve_obj_by_qualname(function_name)()
        return fn

def load_activation_fixed(config):
    """Fixed: explicit check that survives optimization."""
    function_name = None
    if getattr(config, "sentence_transformers", None) \
       and "activation_fn" in config.sentence_transformers:
        function_name = config.sentence_transformers["activation_fn"]

    if function_name is not None:
        if not function_name.startswith("torch.nn.modules."):
            raise ValueError(
                f"Unsafe activation function: {function_name}. "
                "Only torch.nn.modules.* is allowed."
            )
        fn = resolve_obj_by_qualname(function_name)()
        return fn

def resolve_obj_by_qualname(name):
    raise NotImplementedError
# Bismillah ir-Rahman ir-Rahim
