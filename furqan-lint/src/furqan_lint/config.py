# Bismillah ir-Rahman ir-Rahim
"""
Configuration for furqan-lint.

Loads settings from .furqan.toml (project root), pyproject.toml
([tool.furqan] section), or CLI arguments. CLI overrides file config.

Example .furqan.toml:

    [furqan]
    select = ["RC", "MR", "TB"]      # run only these families/rules
    ignore = ["TB-001", "SI-004"]     # suppress these rules
    min_severity = "MEDIUM"           # skip LOW findings
    exclude = ["tests/", "vendor/"]   # skip these paths

    [furqan.per_file_ignores]
    "tests/*.py" = ["TB-001", "SI-001"]
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import List, Optional, Set

from furqan_lint.finding import Finding, Severity


SEVERITY_ORDER = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}

SEVERITY_BY_NAME = {
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


@dataclass
class Config:
    """Furqan-lint configuration."""

    select: Set[str] = field(default_factory=set)
    ignore: Set[str] = field(default_factory=set)
    min_severity: Severity = Severity.LOW
    exclude: List[str] = field(default_factory=list)
    per_file_ignores: dict[str, Set[str]] = field(default_factory=dict)
    output_format: str = "text"  # text, json, sarif
    verbose: bool = False

    def should_run_rule(self, rule: str) -> bool:
        """Check if a rule should run based on select/ignore config."""
        # If select is set, only run rules that match
        if self.select:
            family = rule.split("-")[0]  # e.g., "RC" from "RC-001"
            if rule not in self.select and family not in self.select:
                return False

        # Check ignore list
        if rule in self.ignore:
            return False
        family = rule.split("-")[0]
        if family in self.ignore:
            return False

        return True

    def should_report_finding(self, finding: Finding) -> bool:
        """Check if a finding should be reported based on config."""
        # Check rule filter
        if not self.should_run_rule(finding.rule):
            return False

        # Check severity threshold
        if SEVERITY_ORDER[finding.severity] < SEVERITY_ORDER[self.min_severity]:
            return False

        # Check per-file ignores
        for pattern, rules in self.per_file_ignores.items():
            if fnmatch(finding.path, pattern):
                if finding.rule in rules:
                    return False
                family = finding.rule.split("-")[0]
                if family in rules:
                    return False

        return True

    def should_exclude_path(self, path: Path) -> bool:
        """Check if a path should be excluded from scanning."""
        path_str = str(path)
        for pattern in self.exclude:
            if fnmatch(path_str, pattern) or fnmatch(path_str, f"*/{pattern}"):
                return True
            # Also check if any path component matches
            if any(fnmatch(part, pattern.rstrip("/")) for part in path.parts):
                return True
        return False

    def filter_findings(self, findings: List[Finding]) -> List[Finding]:
        """Filter a list of findings according to config."""
        return [f for f in findings if self.should_report_finding(f)]


def load_config(start_dir: Optional[Path] = None) -> Config:
    """Load config from .furqan.toml or pyproject.toml.

    Searches from start_dir upward to find the config file.
    """
    if start_dir is None:
        start_dir = Path.cwd()

    config = Config()

    # Search for .furqan.toml
    furqan_toml = _find_file(start_dir, ".furqan.toml")
    if furqan_toml:
        _apply_toml(config, furqan_toml, section="furqan")
        return config

    # Search for pyproject.toml with [tool.furqan]
    pyproject = _find_file(start_dir, "pyproject.toml")
    if pyproject:
        _apply_toml(config, pyproject, section="tool.furqan")
        return config

    return config


def _find_file(start: Path, name: str) -> Optional[Path]:
    """Search from start upward for a file with the given name."""
    current = start.resolve()
    while True:
        candidate = current / name
        if candidate.is_file():
            return candidate
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None


def _apply_toml(config: Config, path: Path, section: str) -> None:
    """Apply settings from a TOML file to the config."""
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return

    # Navigate to the section
    parts = section.split(".")
    for part in parts:
        if isinstance(data, dict) and part in data:
            data = data[part]
        else:
            return

    if not isinstance(data, dict):
        return

    if "select" in data and isinstance(data["select"], list):
        config.select = set(data["select"])

    if "ignore" in data and isinstance(data["ignore"], list):
        config.ignore = set(data["ignore"])

    if "min_severity" in data and isinstance(data["min_severity"], str):
        sev = data["min_severity"].upper()
        if sev in SEVERITY_BY_NAME:
            config.min_severity = SEVERITY_BY_NAME[sev]

    if "exclude" in data and isinstance(data["exclude"], list):
        config.exclude = data["exclude"]

    if "per_file_ignores" in data and isinstance(data["per_file_ignores"], dict):
        for pattern, rules in data["per_file_ignores"].items():
            if isinstance(rules, list):
                config.per_file_ignores[pattern] = set(rules)


# Bismillah ir-Rahman ir-Rahim
