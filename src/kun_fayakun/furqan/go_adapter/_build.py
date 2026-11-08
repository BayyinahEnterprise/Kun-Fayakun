"""Build hook: compiles the goast binary at wheel build time.

Invoked from ``setup.py``'s ``build_py`` subclass. The
``[go]`` extra documents ``go (1.21+)`` as a build-machine
requirement. If go is absent, we DO NOT fail the wheel build; we
skip the binary build and the runtime ``parser.py`` raises
``GoExtrasNotInstalled`` with the install hint. This matches the
``[rust]`` extra's posture (the wheel installs without
tree-sitter, runtime fires the install hint).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def build_goast() -> None:
    """Build the goast binary if Go toolchain is available; skip
    silently if not. The runtime ``parser.py`` handles the
    missing-binary case via the ``GoExtrasNotInstalled`` typed
    exception.
    """
    cmd_dir = Path(__file__).resolve().parent / "cmd" / "goast"
    bin_dir = Path(__file__).resolve().parent / "bin"
    bin_dir.mkdir(exist_ok=True)
    target = bin_dir / "goast"
    try:
        subprocess.run(
            ["go", "build", "-o", str(target), "."],
            cwd=str(cmd_dir),
            check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        # Go toolchain absent or build failed; defer to runtime
        # hint. Print to stderr so the wheel build log records
        # the skip, but do not fail.
        print(
            f"[furqan-lint] goast binary not built: {e}. "
            "Install Go (1.21+) to enable the Go adapter at runtime.",
            file=sys.stderr,
        )
