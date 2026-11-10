# Bismillah ir-Rahman ir-Rahim
"""
CVE-2020-14343 pattern: PyYAML unsafe deserialization.

yaml.load() without SafeLoader allows arbitrary Python object
instantiation from untrusted YAML. Attacker-crafted YAML can
execute arbitrary code.

CVSS: 9.8 (Critical). Fixed in PyYAML 5.4+.

furqan-lint rule mapping: TB-006 (pickle/yaml deserialization of untrusted data)
"""
import yaml

def load_config_vulnerable(config_path):
    """Vulnerable: yaml.load without safe loader."""
    with open(config_path) as f:
        return yaml.load(f)  # BUG: default Loader allows arbitrary objects
        # Attacker YAML: !!python/object/apply:os.system ['rm -rf /']

def load_user_submitted_yaml_vulnerable(yaml_text):
    """Vulnerable: full_load on untrusted input."""
    return yaml.full_load(yaml_text)  # BUG: FullLoader still allows some objects

def load_config_safe(config_path):
    """Fixed: SafeLoader restricts to plain Python types."""
    with open(config_path) as f:
        return yaml.safe_load(f)
# Bismillah ir-Rahman ir-Rahim
