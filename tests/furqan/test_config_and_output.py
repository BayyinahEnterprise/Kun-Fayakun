# Bismillah ir-Rahman ir-Rahim
"""Tests for furqan-lint config, rule filtering, and output formats."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from kun_fayakun.furqan.checks.config import Config, load_config
from kun_fayakun.furqan.checks.finding import Finding, Fix, Severity
from kun_fayakun.furqan.checks.formatters import format_json, format_sarif, format_text
from kun_fayakun.furqan.checks.runner import lint_source


# ═══════════════════════════════════════════════════════════════
# Config tests
# ═══════════════════════════════════════════════════════════════

class TestConfig:
    def test_default_config_runs_non_informational_rules(self):
        config = Config()
        assert config.should_run_rule("RC-001")
        assert config.should_run_rule("MR-003")
        assert config.should_run_rule("SI-006")
        assert config.should_run_rule("TB-005")
        # Informational rules are off by default
        assert not config.should_run_rule("TB-001")
        assert not config.should_run_rule("TB-002")
        assert not config.should_run_rule("TB-003")

    def test_informational_rules_enabled_by_select(self):
        config = Config(select={"TB-001"})
        assert config.should_run_rule("TB-001")

    def test_select_filters_to_family(self):
        config = Config(select={"RC", "MR"})
        assert config.should_run_rule("RC-001")
        assert config.should_run_rule("MR-003")
        assert not config.should_run_rule("TB-001")
        assert not config.should_run_rule("SI-004")

    def test_select_filters_to_specific_rule(self):
        config = Config(select={"TB-001", "RC-003"})
        assert config.should_run_rule("TB-001")
        assert config.should_run_rule("RC-003")
        assert not config.should_run_rule("TB-002")
        assert not config.should_run_rule("RC-001")

    def test_ignore_suppresses_rule(self):
        config = Config(ignore={"TB-005"})
        assert not config.should_run_rule("TB-005")
        assert config.should_run_rule("TB-004")
        assert config.should_run_rule("RC-001")

    def test_ignore_suppresses_family(self):
        config = Config(ignore={"SI"})
        assert not config.should_run_rule("SI-001")
        assert not config.should_run_rule("SI-006")
        assert config.should_run_rule("RC-001")

    def test_min_severity_filters(self):
        config = Config(min_severity=Severity.HIGH)
        low = Finding(rule="SI-004", path="test.py", line=1, col=0,
                      message="TODO", severity=Severity.LOW, fix=Fix.ENRICH)
        high = Finding(rule="TB-005", path="test.py", line=1, col=0,
                       message="eval", severity=Severity.CRITICAL, fix=Fix.SIMPLIFY)
        assert not config.should_report_finding(low)
        assert config.should_report_finding(high)

    def test_per_file_ignores(self):
        config = Config(per_file_ignores={
            "tests/*.py": {"TB-005", "SI-001"},
        })
        f1 = Finding(rule="TB-005", path="tests/test_foo.py", line=1, col=0,
                     message="eval", severity=Severity.CRITICAL, fix=Fix.SIMPLIFY)
        f2 = Finding(rule="TB-005", path="src/main.py", line=1, col=0,
                     message="eval", severity=Severity.CRITICAL, fix=Fix.SIMPLIFY)
        assert not config.should_report_finding(f1)  # suppressed in tests/
        assert config.should_report_finding(f2)       # not suppressed in src/

    def test_exclude_path(self):
        config = Config(exclude=["vendor/", "tests/"])
        assert config.should_exclude_path(Path("vendor/lib.py"))
        assert config.should_exclude_path(Path("tests/test_foo.py"))
        assert not config.should_exclude_path(Path("src/main.py"))

    def test_filter_findings(self):
        config = Config(ignore={"SI-004"}, min_severity=Severity.MEDIUM)
        findings = [
            Finding(rule="TB-005", path="a.py", line=1, col=0,
                    message="eval", severity=Severity.CRITICAL, fix=Fix.SIMPLIFY),
            Finding(rule="SI-004", path="a.py", line=2, col=0,
                    message="TODO", severity=Severity.LOW, fix=Fix.ENRICH),
            Finding(rule="RC-001", path="a.py", line=3, col=0,
                    message="open", severity=Severity.MEDIUM, fix=Fix.ENRICH),
        ]
        filtered = config.filter_findings(findings)
        rules = [f.rule for f in filtered]
        assert "TB-005" in rules   # CRITICAL, not ignored
        assert "SI-004" not in rules  # ignored
        assert "RC-001" in rules   # MEDIUM >= MEDIUM threshold


class TestConfigLoading:
    def test_load_from_furqan_toml(self, tmp_path):
        toml_content = """
[furqan]
select = ["RC", "MR"]
ignore = ["TB-001"]
min_severity = "HIGH"
exclude = ["vendor/"]
"""
        (tmp_path / ".furqan.toml").write_text(toml_content)
        config = load_config(tmp_path)
        assert config.select == {"RC", "MR"}
        assert "TB-001" in config.ignore
        assert config.min_severity == Severity.HIGH
        assert "vendor/" in config.exclude

    def test_load_from_pyproject_toml(self, tmp_path):
        toml_content = """
[tool.furqan]
ignore = ["SI-004"]
min_severity = "MEDIUM"
"""
        (tmp_path / "pyproject.toml").write_text(toml_content)
        config = load_config(tmp_path)
        assert "SI-004" in config.ignore
        assert config.min_severity == Severity.MEDIUM

    def test_no_config_returns_defaults(self, tmp_path):
        config = load_config(tmp_path)
        assert config.select == set()
        assert config.ignore == set()
        assert config.min_severity == Severity.LOW


# ═══════════════════════════════════════════════════════════════
# Integration: lint_source with config
# ═══════════════════════════════════════════════════════════════

class TestLintSourceWithConfig:
    def test_select_reduces_findings(self):
        source = textwrap.dedent("""
            f = open("test.txt")
            try:
                pass
            except:
                pass
        """)
        # No config: both RC and MR findings
        all_findings = lint_source(source, "<test>")
        all_rules = {f.rule for f in all_findings}
        assert "RC-001" in all_rules
        assert "MR-001" in all_rules

        # Select only RC: no MR findings
        config = Config(select={"RC"})
        rc_only = lint_source(source, "<test>", config)
        rc_rules = {f.rule for f in rc_only}
        assert "RC-001" in rc_rules
        assert "MR-001" not in rc_rules

    def test_ignore_removes_noisy_rules(self):
        source = textwrap.dedent("""
            if isinstance(x, int):
                pass
        """)
        all_findings = lint_source(source, "<test>")
        assert any(f.rule == "TB-001" for f in all_findings)

        config = Config(ignore={"TB-001"})
        filtered = lint_source(source, "<test>", config)
        assert not any(f.rule == "TB-001" for f in filtered)


# ═══════════════════════════════════════════════════════════════
# Output format tests
# ═══════════════════════════════════════════════════════════════

class TestFormatters:
    @pytest.fixture
    def sample_findings(self):
        return [
            Finding(rule="TB-005", path="src/main.py", line=10, col=4,
                    message="eval() executes arbitrary code",
                    severity=Severity.CRITICAL, fix=Fix.SIMPLIFY,
                    detail="Use ast.literal_eval() for data."),
            Finding(rule="RC-001", path="src/main.py", line=20, col=0,
                    message="open() without context manager",
                    severity=Severity.MEDIUM, fix=Fix.ENRICH,
                    detail="Use `with open(...) as f:` instead."),
        ]

    def test_format_json_valid(self, sample_findings):
        output = format_json(sample_findings)
        data = json.loads(output)
        assert len(data) == 2
        assert data[0]["rule"] == "TB-005"
        assert data[0]["severity"] == "CRITICAL"
        assert data[0]["fix"] == "simplify"
        assert data[1]["rule"] == "RC-001"
        assert data[1]["line"] == 20

    def test_format_sarif_valid(self, sample_findings):
        output = format_sarif(sample_findings)
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        run = data["runs"][0]
        assert run["tool"]["driver"]["name"] == "furqan-lint"
        assert len(run["results"]) == 2
        # Check first result
        r0 = run["results"][0]
        assert r0["ruleId"] == "TB-005"
        assert r0["level"] == "error"
        loc = r0["locations"][0]["physicalLocation"]
        assert loc["region"]["startLine"] == 10
        # Check rules list
        rules = run["tool"]["driver"]["rules"]
        assert len(rules) == 2
        assert rules[0]["id"] in ("RC-001", "TB-005")

    def test_format_text_contains_rule_and_message(self, sample_findings):
        output = format_text(sample_findings)
        assert "TB-005" in output
        assert "RC-001" in output
        assert "eval()" in output
        assert "fix: simplify" in output
        assert "fix: enrich" in output

    def test_format_text_verbose_shows_detail(self, sample_findings):
        output = format_text(sample_findings, verbose=True)
        assert "ast.literal_eval()" in output

    def test_format_json_empty(self):
        output = format_json([])
        assert json.loads(output) == []

    def test_format_sarif_empty(self):
        output = format_sarif([])
        data = json.loads(output)
        assert data["runs"][0]["results"] == []


# Bismillah ir-Rahman ir-Rahim
