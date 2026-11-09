# Bismillah ir-Rahman ir-Rahim
"""
Tests for bandit-equivalent rules absorbed into furqan-lint.

Covers:
  secrets.py   TB-010 through TB-014
  injection.py TB-015 through TB-020, TB-027, TB-028
  crypto.py    TB-021 through TB-026
  marad.py     MR-007 (try-except-continue)
  scan_incomplete.py SI-007 (hasattr)
"""

import ast
import textwrap

import pytest

from kun_fayakun.furqan.checks.secrets import check_secrets
from kun_fayakun.furqan.checks.injection import check_injection
from kun_fayakun.furqan.checks.crypto import check_crypto
from kun_fayakun.furqan.checks.marad import check_marad
from kun_fayakun.furqan.checks.scan_incomplete import check_scan_incomplete
from kun_fayakun.furqan.checks.runner import lint_source


def _parse(code: str):
    code = textwrap.dedent(code)
    tree = ast.parse(code)
    return tree, code


# ── SECRETS (TB-010 to TB-014) ──────────────────────────────────

class TestTB010HardcodedPassword:
    def test_detects_password_assignment(self):
        tree, _ = _parse("""
            password = "s3cr3t_p4ss"
        """)
        findings = check_secrets(tree, "test.py")
        assert any(f.rule == "TB-010" for f in findings)

    def test_ignores_placeholder_password(self):
        tree, _ = _parse("""
            password = "changeme"
        """)
        findings = check_secrets(tree, "test.py")
        assert not any(f.rule == "TB-010" for f in findings)

    def test_detects_attribute_assignment(self):
        tree, _ = _parse("""
            self.api_key = "AKIAIOSFODNN7EXAMPLE"
        """)
        findings = check_secrets(tree, "test.py")
        assert any(f.rule == "TB-010" for f in findings)

    def test_ignores_empty_password(self):
        tree, _ = _parse("""
            password = ""
        """)
        findings = check_secrets(tree, "test.py")
        assert not any(f.rule == "TB-010" for f in findings)


class TestTB011PasswordDefault:
    def test_detects_secret_default(self):
        tree, _ = _parse("""
            def connect(host, password="admin123"):
                pass
        """)
        findings = check_secrets(tree, "test.py")
        assert any(f.rule == "TB-011" for f in findings)

    def test_ignores_none_default(self):
        tree, _ = _parse("""
            def connect(host, password=None):
                pass
        """)
        findings = check_secrets(tree, "test.py")
        assert not any(f.rule == "TB-011" for f in findings)


class TestTB012TmpPath:
    def test_detects_tmp_path(self):
        tree, _ = _parse("""
            path = "/tmp/my_app_data"
        """)
        findings = check_secrets(tree, "test.py")
        assert any(f.rule == "TB-012" for f in findings)

    def test_ignores_non_tmp(self):
        tree, _ = _parse("""
            path = "/var/data/myapp"
        """)
        findings = check_secrets(tree, "test.py")
        assert not any(f.rule == "TB-012" for f in findings)


class TestTB013BindAll:
    def test_detects_bind_all(self):
        tree, _ = _parse("""
            host = "0.0.0.0"
        """)
        findings = check_secrets(tree, "test.py")
        assert any(f.rule == "TB-013" for f in findings)

    def test_ignores_localhost(self):
        tree, _ = _parse("""
            host = "127.0.0.1"
        """)
        findings = check_secrets(tree, "test.py")
        assert not any(f.rule == "TB-013" for f in findings)


class TestTB014DebugMode:
    def test_detects_debug_keyword(self):
        tree, _ = _parse("""
            app.run(debug=True)
        """)
        findings = check_secrets(tree, "test.py")
        assert any(f.rule == "TB-014" for f in findings)

    def test_detects_DEBUG_assignment(self):
        tree, _ = _parse("""
            DEBUG = True
        """)
        findings = check_secrets(tree, "test.py")
        assert any(f.rule == "TB-014" for f in findings)

    def test_ignores_debug_false(self):
        tree, _ = _parse("""
            app.run(debug=False)
        """)
        findings = check_secrets(tree, "test.py")
        assert not any(f.rule == "TB-014" for f in findings)


# ── INJECTION (TB-015 to TB-020) ────────────────────────────────

class TestTB015ShellTrue:
    def test_detects_shell_true(self):
        tree, _ = _parse("""
            import subprocess
            subprocess.call("ls -la", shell=True)
        """)
        findings = check_injection(tree, "test.py")
        assert any(f.rule == "TB-015" for f in findings)

    def test_ignores_shell_false(self):
        tree, _ = _parse("""
            import subprocess
            subprocess.call(["ls", "-la"], shell=False)
        """)
        findings = check_injection(tree, "test.py")
        assert not any(f.rule == "TB-015" for f in findings)


class TestTB016OsSystem:
    def test_detects_os_system(self):
        tree, _ = _parse("""
            import os
            os.system("rm -rf /")
        """)
        findings = check_injection(tree, "test.py")
        assert any(f.rule == "TB-016" for f in findings)

    def test_detects_os_popen(self):
        tree, _ = _parse("""
            import os
            os.popen("ls")
        """)
        findings = check_injection(tree, "test.py")
        assert any(f.rule == "TB-016" for f in findings)


class TestTB017PartialPath:
    def test_detects_partial_path(self):
        tree, _ = _parse("""
            import subprocess
            subprocess.call(["gcc", "file.c"])
        """)
        findings = check_injection(tree, "test.py")
        assert any(f.rule == "TB-017" for f in findings)

    def test_ignores_absolute_path(self):
        tree, _ = _parse("""
            import subprocess
            subprocess.call(["/usr/bin/gcc", "file.c"])
        """)
        findings = check_injection(tree, "test.py")
        assert not any(f.rule == "TB-017" for f in findings)


class TestTB018SqlInjection:
    def test_detects_format_string(self):
        tree, _ = _parse("""
            query = "SELECT * FROM users WHERE id = %s" % user_id
        """)
        findings = check_injection(tree, "test.py")
        assert any(f.rule == "TB-018" for f in findings)

    def test_detects_dot_format(self):
        tree, _ = _parse("""
            query = "SELECT * FROM users WHERE name = '{}'".format(name)
        """)
        findings = check_injection(tree, "test.py")
        assert any(f.rule == "TB-018" for f in findings)

    def test_detects_concatenation(self):
        tree, _ = _parse("""
            query = "SELECT * FROM users WHERE name = '" + name + "'"
        """)
        findings = check_injection(tree, "test.py")
        assert any(f.rule == "TB-018" for f in findings)


class TestTB019Jinja2:
    def test_detects_autoescape_false(self):
        tree, _ = _parse("""
            from jinja2 import Environment
            env = Environment(autoescape=False)
        """)
        findings = check_injection(tree, "test.py")
        assert any(f.rule == "TB-019" for f in findings)

    def test_ignores_autoescape_true(self):
        tree, _ = _parse("""
            from jinja2 import Environment
            env = Environment(autoescape=True)
        """)
        findings = check_injection(tree, "test.py")
        assert not any(f.rule == "TB-019" for f in findings)


class TestTB020MarkSafe:
    def test_detects_mark_safe_variable(self):
        tree, _ = _parse("""
            from django.utils.safestring import mark_safe
            mark_safe(user_input)
        """)
        findings = check_injection(tree, "test.py")
        assert any(f.rule == "TB-020" for f in findings)

    def test_ignores_mark_safe_literal(self):
        tree, _ = _parse("""
            from django.utils.safestring import mark_safe
            mark_safe("<br>")
        """)
        findings = check_injection(tree, "test.py")
        assert not any(f.rule == "TB-020" for f in findings)


# ── CRYPTO (TB-021 to TB-025) ───────────────────────────────────

class TestTB021InsecureHash:
    def test_detects_md5(self):
        tree, _ = _parse("""
            import hashlib
            hashlib.md5(data)
        """)
        findings = check_crypto(tree, "test.py")
        assert any(f.rule == "TB-021" for f in findings)

    def test_ignores_md5_usedforsecurity_false(self):
        tree, _ = _parse("""
            import hashlib
            hashlib.md5(data, usedforsecurity=False)
        """)
        findings = check_crypto(tree, "test.py")
        assert not any(f.rule == "TB-021" for f in findings)

    def test_detects_hashlib_new_sha1(self):
        tree, _ = _parse("""
            import hashlib
            hashlib.new("sha1")
        """)
        findings = check_crypto(tree, "test.py")
        assert any(f.rule == "TB-021" for f in findings)


class TestTB022VerifyFalse:
    def test_detects_requests_verify_false(self):
        tree, _ = _parse("""
            import requests
            requests.get("https://example.com", verify=False)
        """)
        findings = check_crypto(tree, "test.py")
        assert any(f.rule == "TB-022" for f in findings)

    def test_ignores_verify_true(self):
        tree, _ = _parse("""
            import requests
            requests.get("https://example.com", verify=True)
        """)
        findings = check_crypto(tree, "test.py")
        assert not any(f.rule == "TB-022" for f in findings)


class TestTB023NoCheckHostname:
    def test_detects_check_hostname_false(self):
        tree, _ = _parse("""
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
        """)
        findings = check_crypto(tree, "test.py")
        assert any(f.rule == "TB-023" for f in findings)


class TestTB024CertNone:
    def test_detects_cert_none(self):
        tree, _ = _parse("""
            import ssl
            ctx = ssl.create_default_context()
            ctx.verify_mode = ssl.CERT_NONE
        """)
        findings = check_crypto(tree, "test.py")
        assert any(f.rule == "TB-024" for f in findings)


class TestTB025InsecureProtocol:
    def test_detects_sslv3(self):
        tree, _ = _parse("""
            import ssl
            ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
        """)
        findings = check_crypto(tree, "test.py")
        assert any(f.rule == "TB-025" for f in findings)

    def test_detects_tlsv1(self):
        tree, _ = _parse("""
            import ssl
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        """)
        findings = check_crypto(tree, "test.py")
        assert any(f.rule == "TB-025" for f in findings)


# ── MARAD MR-007 (try-except-continue) ──────────────────────────

class TestMR007TryExceptContinue:
    def test_detects_except_continue(self):
        tree, _ = _parse("""
            for item in items:
                try:
                    process(item)
                except Exception:
                    continue
        """)
        findings = check_marad(tree, "test.py")
        assert any(f.rule == "MR-007" for f in findings)

    def test_ignores_except_log_continue(self):
        tree, _ = _parse("""
            for item in items:
                try:
                    process(item)
                except Exception as e:
                    log.error(e)
                    continue
        """)
        findings = check_marad(tree, "test.py")
        assert not any(f.rule == "MR-007" for f in findings)


# ── SCAN-INCOMPLETE SI-007 (hasattr) ────────────────────────────

class TestSI007Hasattr:
    def test_detects_hasattr(self):
        tree, src = _parse("""
            if hasattr(obj, "method"):
                obj.method()
        """)
        findings = check_scan_incomplete(src, tree, "test.py")
        assert any(f.rule == "SI-007" for f in findings)


# ── CRYPTO TB-026 (random for security) ─────────────────────────

class TestTB026RandomForSecurity:
    def test_detects_random_random(self):
        tree, _ = _parse("""
            import random
            token = random.random()
        """)
        findings = check_crypto(tree, "test.py")
        assert any(f.rule == "TB-026" for f in findings)

    def test_detects_random_choice(self):
        tree, _ = _parse("""
            import random
            char = random.choice("abcdef0123456789")
        """)
        findings = check_crypto(tree, "test.py")
        assert any(f.rule == "TB-026" for f in findings)

    def test_detects_random_getrandbits(self):
        tree, _ = _parse("""
            import random
            bits = random.getrandbits(128)
        """)
        findings = check_crypto(tree, "test.py")
        assert any(f.rule == "TB-026" for f in findings)


# ── INJECTION TB-027 (XXE) ──────────────────────────────────────

class TestTB027XXE:
    def test_detects_etree_parse(self):
        tree, _ = _parse("""
            import xml.etree.ElementTree as ET
            ET.parse("data.xml")
        """)
        findings = check_injection(tree, "test.py")
        assert any(f.rule == "TB-027" for f in findings)

    def test_detects_minidom_parseString(self):
        tree, _ = _parse("""
            from xml.dom import minidom
            minidom.parseString(data)
        """)
        findings = check_injection(tree, "test.py")
        assert any(f.rule == "TB-027" for f in findings)

    def test_detects_sax_parse(self):
        tree, _ = _parse("""
            from xml import sax
            sax.parse("data.xml", handler)
        """)
        findings = check_injection(tree, "test.py")
        assert any(f.rule == "TB-027" for f in findings)

    def test_detects_bare_import_parseString(self):
        tree, _ = _parse("""
            from xml.dom.minidom import parseString
            parseString(data)
        """)
        findings = check_injection(tree, "test.py")
        assert any(f.rule == "TB-027" for f in findings)


# ── INJECTION TB-028 (Django ORM injection) ─────────────────────

class TestTB028DjangoORM:
    def test_detects_extra_with_where(self):
        tree, _ = _parse("""
            qs.extra(where=["name = %s"])
        """)
        findings = check_injection(tree, "test.py")
        assert any(f.rule == "TB-028" for f in findings)

    def test_detects_extra_with_select(self):
        tree, _ = _parse("""
            qs.extra(select={"val": "col + 1"})
        """)
        findings = check_injection(tree, "test.py")
        assert any(f.rule == "TB-028" for f in findings)

    def test_detects_rawsql_variable(self):
        tree, _ = _parse("""
            RawSQL(query, params)
        """)
        findings = check_injection(tree, "test.py")
        assert any(f.rule == "TB-028" for f in findings)

    def test_ignores_rawsql_literal(self):
        tree, _ = _parse("""
            RawSQL("SELECT col FROM tbl WHERE id = %s", [pk])
        """)
        findings = check_injection(tree, "test.py")
        assert not any(f.rule == "TB-028" for f in findings)


# ── Integration: lint_source picks up new rules ─────────────────

class TestIntegration:
    def test_lint_source_finds_new_rules(self):
        code = textwrap.dedent("""
            import subprocess
            import hashlib

            password = "hunter2"
            subprocess.call("ls", shell=True)
            hashlib.md5(b"data")
        """)
        findings = lint_source(code, "test.py")
        rules = {f.rule for f in findings}
        assert "TB-010" in rules, "Should detect hardcoded password"
        assert "TB-015" in rules, "Should detect shell=True"
        assert "TB-021" in rules, "Should detect insecure hash"

    def test_all_rule_families_active(self):
        """Verify all 7 check families run through lint_source."""
        code = textwrap.dedent("""
            import subprocess
            import hashlib
            from typing import Any

            # RC family: unclosed file
            f = open("test.txt")

            # MR family: bare except
            try:
                x = 1
            except:
                pass

            # TB family (original): eval
            eval(input())

            # SI family: Any annotation
            x: Any = 1

            # Secrets family: hardcoded password
            secret_key = "mysupersecretkey123"

            # Injection family: os.system
            import os
            os.system("echo hello")

            # Crypto family: md5
            hashlib.md5(b"test")
        """)
        findings = lint_source(code, "test.py")
        rules = {f.rule for f in findings}
        # At least one finding from each family
        assert any(r.startswith("RC-") for r in rules), f"Missing RC rules. Got: {rules}"
        assert any(r.startswith("MR-") for r in rules), f"Missing MR rules. Got: {rules}"
        assert any(r == "TB-005" for r in rules), f"Missing TB-005. Got: {rules}"
        assert any(r.startswith("SI-") for r in rules), f"Missing SI rules. Got: {rules}"
        assert any(r == "TB-010" for r in rules), f"Missing TB-010 (secrets). Got: {rules}"
        assert any(r == "TB-016" for r in rules), f"Missing TB-016 (injection). Got: {rules}"
        assert any(r == "TB-021" for r in rules), f"Missing TB-021 (crypto). Got: {rules}"


# Bismillah ir-Rahman ir-Rahim
