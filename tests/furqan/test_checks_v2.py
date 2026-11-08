# Bismillah ir-Rahman ir-Rahim
"""
Tests for furqan-lint v2.0 check families.

Each test function exercises one rule with a minimal code snippet.
"""

from __future__ import annotations

import ast
import textwrap

import pytest

from kun_fayakun.furqan.checks.finding import Finding, Fix, Severity
from kun_fayakun.furqan.checks.ring_close import check_ring_close
from kun_fayakun.furqan.checks.marad import check_marad
from kun_fayakun.furqan.checks.trust_boundary import check_trust_boundary
from kun_fayakun.furqan.checks.scan_incomplete import check_scan_incomplete
from kun_fayakun.furqan.checks.runner import lint_source


def _parse(code: str) -> ast.Module:
    return ast.parse(textwrap.dedent(code), filename="<test>")


# ═══════════════════════════════════════════════════════════════
# RING-CLOSE checks
# ═══════════════════════════════════════════════════════════════

class TestRingClose:
    def test_rc001_open_without_with(self):
        tree = _parse("""
            f = open("data.txt")
            data = f.read()
            f.close()
        """)
        findings = check_ring_close(tree, "<test>")
        rules = [f.rule for f in findings]
        assert "RC-001" in rules

    def test_rc001_open_with_with_is_clean(self):
        tree = _parse("""
            with open("data.txt") as f:
                data = f.read()
        """)
        findings = check_ring_close(tree, "<test>")
        rc001 = [f for f in findings if f.rule == "RC-001"]
        assert len(rc001) == 0

    def test_rc002_lock_acquire(self):
        tree = _parse("""
            import threading
            lock = threading.Lock()
            lock.acquire()
            # do work
            lock.release()
        """)
        findings = check_ring_close(tree, "<test>")
        rules = [f.rule for f in findings]
        assert "RC-002" in rules

    def test_rc005_tempfile(self):
        tree = _parse("""
            import tempfile
            f = tempfile.NamedTemporaryFile()
        """)
        findings = check_ring_close(tree, "<test>")
        rules = [f.rule for f in findings]
        assert "RC-005" in rules


# ═══════════════════════════════════════════════════════════════
# MARAD checks
# ═══════════════════════════════════════════════════════════════

class TestMarad:
    def test_mr001_bare_except(self):
        tree = _parse("""
            try:
                risky()
            except:
                pass
        """)
        findings = check_marad(tree, "<test>")
        rules = [f.rule for f in findings]
        assert "MR-001" in rules

    def test_mr001_bare_except_with_reraise_is_clean(self):
        tree = _parse("""
            try:
                risky()
            except:
                log("error")
                raise
        """)
        findings = check_marad(tree, "<test>")
        mr001 = [f for f in findings if f.rule == "MR-001"]
        assert len(mr001) == 0

    def test_mr002_broad_except_swallowed(self):
        tree = _parse("""
            try:
                risky()
            except Exception:
                pass
        """)
        findings = check_marad(tree, "<test>")
        rules = [f.rule for f in findings]
        assert "MR-002" in rules

    def test_mr003_exception_named_but_unused(self):
        tree = _parse("""
            try:
                risky()
            except ValueError as e:
                print("something went wrong")
        """)
        findings = check_marad(tree, "<test>")
        rules = [f.rule for f in findings]
        assert "MR-003" in rules

    def test_mr003_exception_used_is_clean(self):
        tree = _parse("""
            try:
                risky()
            except ValueError as e:
                print(f"Error: {e}")
        """)
        findings = check_marad(tree, "<test>")
        mr003 = [f for f in findings if f.rule == "MR-003"]
        assert len(mr003) == 0

    def test_mr005_empty_except(self):
        tree = _parse("""
            try:
                risky()
            except ValueError:
                pass
        """)
        findings = check_marad(tree, "<test>")
        rules = [f.rule for f in findings]
        assert "MR-005" in rules


# ═══════════════════════════════════════════════════════════════
# TRUST-BOUNDARY checks
# ═══════════════════════════════════════════════════════════════

class TestTrustBoundary:
    def test_tb001_isinstance(self):
        tree = _parse("""
            if isinstance(x, MyType):
                grant_access(x)
        """)
        findings = check_trust_boundary(tree, "<test>")
        rules = [f.rule for f in findings]
        assert "TB-001" in rules

    def test_tb002_deepcopy(self):
        tree = _parse("""
            import copy
            safe = copy.deepcopy(untrusted_input)
        """)
        findings = check_trust_boundary(tree, "<test>")
        rules = [f.rule for f in findings]
        assert "TB-002" in rules

    def test_tb003_type_name(self):
        tree = _parse("""
            name = type(obj).__name__
        """)
        findings = check_trust_boundary(tree, "<test>")
        rules = [f.rule for f in findings]
        assert "TB-003" in rules

    def test_tb004_mutable_default(self):
        tree = _parse("""
            def process(items=[]):
                items.append("new")
                return items
        """)
        findings = check_trust_boundary(tree, "<test>")
        rules = [f.rule for f in findings]
        assert "TB-004" in rules

    def test_tb004_none_default_is_clean(self):
        tree = _parse("""
            def process(items=None):
                if items is None:
                    items = []
                items.append("new")
                return items
        """)
        findings = check_trust_boundary(tree, "<test>")
        tb004 = [f for f in findings if f.rule == "TB-004"]
        assert len(tb004) == 0

    def test_tb005_eval(self):
        tree = _parse("""
            result = eval(user_input)
        """)
        findings = check_trust_boundary(tree, "<test>")
        rules = [f.rule for f in findings]
        assert "TB-005" in rules

    def test_tb006_pickle(self):
        tree = _parse("""
            import pickle
            data = pickle.loads(network_bytes)
        """)
        findings = check_trust_boundary(tree, "<test>")
        rules = [f.rule for f in findings]
        assert "TB-006" in rules

    def test_tb006_yaml_safe_is_clean(self):
        tree = _parse("""
            import yaml
            data = yaml.load(text, Loader=yaml.SafeLoader)
        """)
        findings = check_trust_boundary(tree, "<test>")
        tb006 = [f for f in findings if f.rule == "TB-006"]
        assert len(tb006) == 0

    def test_tb006_yaml_unsafe(self):
        tree = _parse("""
            import yaml
            data = yaml.load(text)
        """)
        findings = check_trust_boundary(tree, "<test>")
        rules = [f.rule for f in findings]
        assert "TB-006" in rules


# ═══════════════════════════════════════════════════════════════
# SCAN-INCOMPLETE checks
# ═══════════════════════════════════════════════════════════════

class TestScanIncomplete:
    def test_si001_any_annotation(self):
        tree = _parse("""
            from typing import Any
            def process(data: Any) -> Any:
                return data
        """)
        findings = check_scan_incomplete("", tree, "<test>")
        rules = [f.rule for f in findings]
        assert "SI-001" in rules

    def test_si002_blanket_type_ignore(self):
        source = "x = foo()  # type: ignore\n"
        tree = _parse(source)
        findings = check_scan_incomplete(source, tree, "<test>")
        rules = [f.rule for f in findings]
        assert "SI-002" in rules

    def test_si002_specific_type_ignore_is_clean(self):
        source = "x = foo()  # type: ignore[assignment]\n"
        tree = _parse(source)
        findings = check_scan_incomplete(source, tree, "<test>")
        si002 = [f for f in findings if f.rule == "SI-002"]
        assert len(si002) == 0

    def test_si003_blanket_noqa(self):
        source = "x = very_long_line  # noqa\n"
        tree = _parse(source)
        findings = check_scan_incomplete(source, tree, "<test>")
        rules = [f.rule for f in findings]
        assert "SI-003" in rules

    def test_si003_specific_noqa_is_clean(self):
        source = "x = very_long_line  # noqa: E501\n"
        tree = _parse(source)
        findings = check_scan_incomplete(source, tree, "<test>")
        si003 = [f for f in findings if f.rule == "SI-003"]
        assert len(si003) == 0

    def test_si004_todo(self):
        source = "# TODO: fix this later\nx = 1\n"
        tree = _parse(source)
        findings = check_scan_incomplete(source, tree, "<test>")
        rules = [f.rule for f in findings]
        assert "SI-004" in rules

    def test_si005_kwargs_passthrough(self):
        tree = _parse("""
            def wrapper(**kwargs):
                return inner(**kwargs)
        """)
        source = textwrap.dedent("""
            def wrapper(**kwargs):
                return inner(**kwargs)
        """)
        findings = check_scan_incomplete(source, tree, "<test>")
        rules = [f.rule for f in findings]
        assert "SI-005" in rules

    def test_si005_kwargs_validated_is_clean(self):
        tree = _parse("""
            def wrapper(**kwargs):
                name = kwargs["name"]
                return inner(**kwargs)
        """)
        source = textwrap.dedent("""
            def wrapper(**kwargs):
                name = kwargs["name"]
                return inner(**kwargs)
        """)
        findings = check_scan_incomplete(source, tree, "<test>")
        si005 = [f for f in findings if f.rule == "SI-005"]
        assert len(si005) == 0

    def test_si006_assert_validation(self):
        tree = _parse("""
            def process(x):
                assert isinstance(x, int)
                return x + 1
        """)
        source = ""
        findings = check_scan_incomplete(source, tree, "<test>")
        rules = [f.rule for f in findings]
        assert "SI-006" in rules


# ═══════════════════════════════════════════════════════════════
# Integration: lint_source
# ═══════════════════════════════════════════════════════════════

class TestLintSource:
    def test_empty_source_is_clean(self):
        findings = lint_source("", "<test>")
        assert len(findings) == 0

    def test_clean_code(self):
        source = textwrap.dedent("""
            def greet(name: str) -> str:
                return f"Hello, {name}"
        """)
        findings = lint_source(source, "<test>")
        # May have some findings for generic patterns but no critical ones
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 0

    def test_multiple_issues(self):
        source = textwrap.dedent("""
            import pickle

            def process(data=[]):
                try:
                    result = pickle.loads(data)
                except:
                    pass
                return result
        """)
        findings = lint_source(source, "<test>")
        rules = {f.rule for f in findings}
        # Should catch: TB-004 (mutable default), TB-006 (pickle),
        # MR-001 (bare except), MR-005 (empty except)
        assert "TB-004" in rules
        assert "TB-006" in rules
        assert "MR-001" in rules

    def test_finding_has_fix_category(self):
        source = "f = open('test.txt')\n"
        findings = lint_source(source, "<test>")
        rc001 = [f for f in findings if f.rule == "RC-001"]
        assert len(rc001) > 0
        assert rc001[0].fix in (Fix.SIMPLIFY, Fix.RECALIBRATE, Fix.ENRICH)

    def test_findings_sorted_by_line(self):
        source = textwrap.dedent("""
            f = open("a.txt")
            try:
                pass
            except:
                pass
            g = open("b.txt")
        """)
        findings = lint_source(source, "<test>")
        lines = [f.line for f in findings]
        assert lines == sorted(lines)


# Bismillah ir-Rahman ir-Rahim
