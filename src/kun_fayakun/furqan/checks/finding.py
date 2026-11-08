# Bismillah ir-Rahman ir-Rahim
"""
Finding dataclass -- the output of every Furqan check.

Every finding carries:
- rule: the check family and rule code (e.g. "RING-CLOSE-001")
- path: the file path
- line: the line number
- message: what is wrong
- fix: which tawba operation applies (simplify, recalibrate, enrich)
- severity: CRITICAL, HIGH, MEDIUM, LOW
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Fix(Enum):
    SIMPLIFY = "simplify"       # Remove the unauthorized addition
    RECALIBRATE = "recalibrate" # Align surface with substrate (or vice versa)
    ENRICH = "enrich"           # Add what is missing


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    line: int
    col: int
    message: str
    severity: Severity
    fix: Fix
    detail: str = ""

    def __str__(self) -> str:
        return f"{self.path}:{self.line}:{self.col}: {self.rule} [{self.severity.value}] {self.message}"


# Bismillah ir-Rahman ir-Rahim
