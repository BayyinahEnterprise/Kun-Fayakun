# Bismillah ir-Rahman ir-Rahim
"""
Tests for multi-language adapters (C and Java).

Each test feeds real-world-like code through the adapter and verifies
the expected findings are produced.
"""

import textwrap

import pytest

from kun_fayakun.furqan.checks.adapters.base import get_adapter, supported_extensions
from kun_fayakun.furqan.checks.adapters.c_adapter import CAdapter
from kun_fayakun.furqan.checks.adapters.java_adapter import JavaAdapter


# ── Adapter registration ────────────────────────────────────────

class TestAdapterRegistration:
    def test_c_extension(self):
        adapter = get_adapter("main.c")
        assert adapter is not None
        assert adapter.language_name() == "C"

    def test_h_extension(self):
        adapter = get_adapter("header.h")
        assert adapter is not None
        assert adapter.language_name() == "C"

    def test_java_extension(self):
        adapter = get_adapter("App.java")
        assert adapter is not None
        assert adapter.language_name() == "Java"

    def test_unknown_extension(self):
        adapter = get_adapter("script.rb")
        assert adapter is None

    def test_supported_extensions(self):
        exts = supported_extensions()
        assert ".c" in exts
        assert ".h" in exts
        assert ".java" in exts
        assert ".py" in exts


# ── C Adapter ───────────────────────────────────────────────────

class TestCBufferOverflow:
    def test_strcpy(self):
        code = b'void f() { char buf[10]; strcpy(buf, src); }'
        adapter = CAdapter()
        findings = adapter.check(code, "test.c")
        assert any(f.rule == "TB-029" for f in findings)

    def test_gets(self):
        code = b'void f() { char buf[256]; gets(buf); }'
        adapter = CAdapter()
        findings = adapter.check(code, "test.c")
        assert any(f.rule == "TB-029" for f in findings)

    def test_sprintf(self):
        code = b'void f() { char buf[64]; sprintf(buf, "%s=%s", key, val); }'
        adapter = CAdapter()
        findings = adapter.check(code, "test.c")
        assert any(f.rule == "TB-029" for f in findings)

    def test_snprintf_is_clean(self):
        code = b'void f() { char buf[64]; snprintf(buf, sizeof(buf), "%s", src); }'
        adapter = CAdapter()
        findings = adapter.check(code, "test.c")
        assert not any(f.rule == "TB-029" for f in findings)


class TestCFormatString:
    def test_printf_variable_format(self):
        code = b'void f(char *fmt) { printf(fmt); }'
        adapter = CAdapter()
        findings = adapter.check(code, "test.c")
        assert any(f.rule == "TB-030" for f in findings)

    def test_printf_literal_is_clean(self):
        code = b'void f() { printf("hello %s", name); }'
        adapter = CAdapter()
        findings = adapter.check(code, "test.c")
        assert not any(f.rule == "TB-030" for f in findings)


class TestCCommandInjection:
    def test_system_call(self):
        code = b'void f() { system("rm -rf /"); }'
        adapter = CAdapter()
        findings = adapter.check(code, "test.c")
        assert any(f.rule == "TB-016" for f in findings)

    def test_popen_call(self):
        code = b'void f() { FILE *p = popen("ls", "r"); }'
        adapter = CAdapter()
        findings = adapter.check(code, "test.c")
        assert any(f.rule == "TB-016" for f in findings)


class TestCResourceLeak:
    def test_fopen_without_fclose(self):
        code = b'''
void f() {
    FILE *fp = fopen("data.txt", "r");
    read_data(fp);
    return;
}
'''
        adapter = CAdapter()
        findings = adapter.check(code, "test.c")
        assert any(f.rule == "RC-001" for f in findings)

    def test_fopen_with_fclose_is_clean(self):
        code = b'''
void f() {
    FILE *fp = fopen("data.txt", "r");
    read_data(fp);
    fclose(fp);
}
'''
        adapter = CAdapter()
        findings = adapter.check(code, "test.c")
        assert not any(f.rule == "RC-001" for f in findings)


class TestCHardcodedSecret:
    def test_password_variable(self):
        code = b'char *password = "s3cr3t123";'
        adapter = CAdapter()
        findings = adapter.check(code, "test.c")
        assert any(f.rule == "TB-010" for f in findings)

    def test_define_secret(self):
        code = b'#define API_KEY "AKIAIOSFODNN7EXAMPLE"'
        adapter = CAdapter()
        findings = adapter.check(code, "test.c")
        assert any(f.rule == "TB-010" for f in findings)


class TestCWeakRandom:
    def test_rand(self):
        code = b'void f() { int x = rand(); }'
        adapter = CAdapter()
        findings = adapter.check(code, "test.c")
        assert any(f.rule == "TB-026" for f in findings)


class TestCAssert:
    def test_assert(self):
        code = b'void f(int x) { assert(x > 0); }'
        adapter = CAdapter()
        findings = adapter.check(code, "test.c")
        assert any(f.rule == "SI-006" for f in findings)


class TestCUncheckedReturn:
    def test_malloc_unchecked(self):
        code = b'void f() { malloc(1024); }'
        adapter = CAdapter()
        findings = adapter.check(code, "test.c")
        assert any(f.rule == "MR-005" for f in findings)

    def test_malloc_checked_is_clean(self):
        code = b'void f() { void *p = malloc(1024); }'
        adapter = CAdapter()
        findings = adapter.check(code, "test.c")
        assert not any(f.rule == "MR-005" for f in findings)


class TestCTodo:
    def test_todo_comment(self):
        code = b'// TODO: fix this buffer overflow\nvoid f() {}'
        adapter = CAdapter()
        findings = adapter.check(code, "test.c")
        assert any(f.rule == "SI-004" for f in findings)


# ── Java Adapter ────────────────────────────────────────────────

class TestJavaEmptyCatch:
    def test_empty_catch(self):
        code = b'''
class App {
    void f() {
        try { riskyOp(); }
        catch (IOException e) { }
    }
}
'''
        adapter = JavaAdapter()
        findings = adapter.check(code, "App.java")
        assert any(f.rule == "MR-005" for f in findings)

    def test_broad_catch_no_rethrow(self):
        code = b'''
class App {
    void f() {
        try { riskyOp(); }
        catch (Exception e) { log.error(e); }
    }
}
'''
        adapter = JavaAdapter()
        findings = adapter.check(code, "App.java")
        assert any(f.rule == "MR-001" for f in findings)


class TestJavaSqlInjection:
    def test_statement_concat(self):
        code = b'''
class App {
    void query(String input) {
        stmt.executeQuery("SELECT * FROM users WHERE id=" + input);
    }
}
'''
        adapter = JavaAdapter()
        findings = adapter.check(code, "App.java")
        assert any(f.rule == "TB-018" for f in findings)


class TestJavaResourceLeak:
    def test_stream_not_closed(self):
        code = b'''
class App {
    void read() {
        FileInputStream fis = new FileInputStream("data.txt");
        fis.read();
    }
}
'''
        adapter = JavaAdapter()
        findings = adapter.check(code, "App.java")
        assert any(f.rule == "RC-001" for f in findings)


class TestJavaHardcodedSecret:
    def test_password_field(self):
        code = b'''
class Config {
    String password = "admin123";
}
'''
        adapter = JavaAdapter()
        findings = adapter.check(code, "Config.java")
        assert any(f.rule == "TB-010" for f in findings)


class TestJavaWeakRandom:
    def test_new_random(self):
        code = b'''
class App {
    void genToken() { Random rng = new Random(); }
}
'''
        adapter = JavaAdapter()
        findings = adapter.check(code, "App.java")
        assert any(f.rule == "TB-026" for f in findings)


class TestJavaAssert:
    def test_assert_statement(self):
        code = b'''
class App {
    void validate(int x) { assert x > 0 : "must be positive"; }
}
'''
        adapter = JavaAdapter()
        findings = adapter.check(code, "App.java")
        assert any(f.rule == "SI-006" for f in findings)


class TestJavaCommandInjection:
    def test_runtime_exec(self):
        code = b'''
class App {
    void run() { Runtime.getRuntime().exec("ls -la"); }
}
'''
        adapter = JavaAdapter()
        findings = adapter.check(code, "App.java")
        assert any(f.rule == "TB-015" for f in findings)


# ── Cross-adapter integration ──────────────────────────────────

class TestCrossLanguageConsistency:
    """Same structural issue, same rule code, different languages."""

    def test_hardcoded_secret_same_rule(self):
        c_code = b'char *api_key = "AKIAIOSFODNN7EXAMPLE";'
        java_code = b'class C { String apiKey = "AKIAIOSFODNN7EXAMPLE"; }'

        c_findings = CAdapter().check(c_code, "test.c")
        java_findings = JavaAdapter().check(java_code, "Test.java")

        c_rules = {f.rule for f in c_findings if f.rule == "TB-010"}
        java_rules = {f.rule for f in java_findings if f.rule == "TB-010"}
        assert c_rules == java_rules == {"TB-010"}

    def test_todo_same_rule(self):
        c_code = b'// TODO: implement\nvoid f() {}'
        java_code = b'class C {\n    // TODO: implement\n    void f() {}\n}'

        c_findings = CAdapter().check(c_code, "test.c")
        java_findings = JavaAdapter().check(java_code, "Test.java")

        assert any(f.rule == "SI-004" for f in c_findings)
        assert any(f.rule == "SI-004" for f in java_findings)


# Bismillah ir-Rahman ir-Rahim
