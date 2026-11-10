# Bismillah ir-Rahman ir-Rahim
"""
CVE-2021-23727 pattern: Celery command injection via getattr chain.

exception_to_python() took untrusted module/type strings and
used getattr() to resolve them, allowing arbitrary code execution.

furqan-lint rule mapping: SI-007 (hasattr/getattr swallows errors),
TB-018 (injection via dynamic attribute access in trust boundary context)
"""
import importlib

def exception_to_python_vulnerable(exc_info):
    """Vulnerable pattern from Celery < 5.2.2."""
    exc_module = exc_info.get('exc_module', 'builtins')
    exc_type = exc_info.get('exc_type', 'Exception')
    exc_message = exc_info.get('exc_message', [''])

    try:
        module = importlib.import_module(exc_module)
        cls = module
        for part in exc_type.split('.'):
            cls = getattr(cls, part)  # BUG: unrestricted getattr chain
        if hasattr(cls, '__call__'):  # BUG: hasattr swallows import errors
            return cls(*exc_message)
    except Exception:
        pass  # BUG: swallowed error hides the injection attempt
    return Exception(*exc_message)

ALLOWLIST = {'builtins', 'exceptions'}

def exception_to_python_fixed(exc_info):
    """Fixed: validate module against allowlist."""
    exc_module = exc_info.get('exc_module', 'builtins')
    exc_type = exc_info.get('exc_type', 'Exception')
    exc_message = exc_info.get('exc_message', [''])

    if exc_module not in ALLOWLIST:
        raise ValueError(f"Untrusted module: {exc_module}")
    module = importlib.import_module(exc_module)
    cls = getattr(module, exc_type, None)
    if cls is None or not issubclass(cls, BaseException):
        raise ValueError(f"Not an exception type: {exc_type}")
    return cls(*exc_message)
# Bismillah ir-Rahman ir-Rahim
