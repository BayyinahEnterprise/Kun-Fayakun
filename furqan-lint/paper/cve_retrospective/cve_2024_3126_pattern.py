# Bismillah ir-Rahman ir-Rahim
"""
CVE-2024-3126 pattern: command injection via shell=True.

Multiple Python libraries passed user-controlled strings to
subprocess.Popen/call with shell=True, allowing command injection.

furqan-lint rule mapping: TB-019 (subprocess with shell=True)
"""
import subprocess

def run_command_vulnerable(user_input):
    """Vulnerable: shell=True with user-controlled input."""
    cmd = f"echo {user_input}"
    # BUG: user_input can contain: ; rm -rf / or $(malicious)
    result = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    return result.communicate()[0]

def run_command_fixed(user_input):
    """Fixed: no shell, pass args as list."""
    result = subprocess.Popen(
        ["echo", user_input],
        stdout=subprocess.PIPE
    )
    return result.communicate()[0]
# Bismillah ir-Rahman ir-Rahim
