# Bismillah ir-Rahman ir-Rahim
"""
CVE-2023-6597 + Issue 21058 pattern: tempfile fd leak.

NamedTemporaryFile leaks the file descriptor when fdopen() fails.
Repeated calls exhaust fd limit (EMFILE / "Too many open files").

CVE-2023-6597 is the broader tempfile.TemporaryDirectory path traversal
on cleanup. Issue 21058 is the specific fd leak.

furqan-lint rule mapping: RC-001 (open without close),
RC-004 (temp resource without cleanup)
"""
import os
import tempfile

def create_temp_vulnerable():
    """Vulnerable: fd leaks if fdopen fails."""
    fd, name = tempfile.mkstemp()
    # BUG: if fdopen raises, fd is never closed
    f = os.fdopen(fd, 'x')  # 'x' mode can raise ValueError
    return f, name

def create_temp_safe():
    """Fixed: close fd on fdopen failure."""
    fd, name = tempfile.mkstemp()
    try:
        f = os.fdopen(fd, 'w')
    except Exception:
        os.close(fd)
        os.unlink(name)
        raise
    return f, name

def loop_create_vulnerable(n):
    """Demonstrates fd exhaustion from the leak."""
    handles = []
    for i in range(n):
        try:
            fd, name = tempfile.mkstemp()
            f = os.fdopen(fd, 'x')  # fails after first iteration
            handles.append((f, name))
        except Exception:
            pass  # BUG: fd leaked AND error swallowed
    return handles
# Bismillah ir-Rahman ir-Rahim
