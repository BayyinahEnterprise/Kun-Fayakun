# Bismillah ir-Rahman ir-Rahim
"""
Tests for C++ and C# language adapters.
"""

import pytest

from kun_fayakun.furqan.checks.adapters.base import get_adapter, supported_extensions
from kun_fayakun.furqan.checks.adapters.cpp_adapter import CppAdapter
from kun_fayakun.furqan.checks.adapters.csharp_adapter import CSharpAdapter


# ── Registration ────────────────────────────────────────────────

class TestRegistration:
    def test_cpp_extensions(self):
        for ext in [".cpp", ".cxx", ".cc", ".hpp", ".hxx", ".hh"]:
            adapter = get_adapter(f"file{ext}")
            assert adapter is not None, f"No adapter for {ext}"
            assert adapter.language_name() == "C++"

    def test_csharp_extension(self):
        adapter = get_adapter("Program.cs")
        assert adapter is not None
        assert adapter.language_name() == "C#"

    def test_all_extensions_registered(self):
        exts = supported_extensions()
        for e in [".c", ".h", ".cpp", ".cc", ".java", ".cs", ".py"]:
            assert e in exts, f"{e} not in supported_extensions()"


# ── C++ Adapter ─────────────────────────────────────────────────

class TestCppCatchAll:
    def test_catch_ellipsis_no_rethrow(self):
        code = b'''
void f() {
    try { risky(); }
    catch (...) { log("oops"); }
}
'''
        findings = CppAdapter().check(code, "test.cpp")
        assert any(f.rule == "MR-001" for f in findings)

    def test_catch_ellipsis_with_rethrow_is_clean(self):
        code = b'''
void f() {
    try { risky(); }
    catch (...) { log("oops"); throw; }
}
'''
        findings = CppAdapter().check(code, "test.cpp")
        assert not any(f.rule == "MR-001" for f in findings)


class TestCppEmptyCatch:
    def test_empty_catch(self):
        code = b'''
void f() {
    try { risky(); }
    catch (std::exception& e) {}
}
'''
        findings = CppAdapter().check(code, "test.cpp")
        assert any(f.rule == "MR-005" for f in findings)


class TestCppUnsafeCasts:
    def test_const_cast(self):
        code = b'void f(const int* p) { int* q = const_cast<int*>(p); }'
        findings = CppAdapter().check(code, "test.cpp")
        assert any(f.rule == "TB-031" for f in findings)

    def test_reinterpret_cast(self):
        code = b'void f(int* p) { char* q = reinterpret_cast<char*>(p); }'
        findings = CppAdapter().check(code, "test.cpp")
        assert any(f.rule == "TB-032" for f in findings)

    def test_c_style_cast(self):
        code = b'void f(void* p) { int* q = (int*)p; }'
        findings = CppAdapter().check(code, "test.cpp")
        assert any(f.rule == "TB-033" for f in findings)


class TestCppNewWithoutSmartPtr:
    def test_raw_new_no_delete(self):
        code = b'''
void f() {
    int* p = new int[100];
    use(p);
}
'''
        findings = CppAdapter().check(code, "test.cpp")
        assert any(f.rule == "RC-001" and "new" in f.message for f in findings)

    def test_unique_ptr_is_clean(self):
        code = b'''
void f() {
    auto p = std::unique_ptr<int>(new int(42));
}
'''
        findings = CppAdapter().check(code, "test.cpp")
        assert not any(f.rule == "RC-001" and "new" in f.message for f in findings)


class TestCppInheritsC:
    """C++ adapter inherits all C checks."""

    def test_strcpy_detected(self):
        code = b'void f() { char buf[10]; strcpy(buf, src); }'
        findings = CppAdapter().check(code, "test.cpp")
        assert any(f.rule == "TB-029" for f in findings)

    def test_system_detected(self):
        code = b'void f() { system("rm -rf /"); }'
        findings = CppAdapter().check(code, "test.cpp")
        assert any(f.rule == "TB-016" for f in findings)

    def test_hardcoded_secret(self):
        code = b'char* api_key = "AKIAIOSFODNN7EXAMPLE";'
        findings = CppAdapter().check(code, "test.cpp")
        assert any(f.rule == "TB-010" for f in findings)


# ── C# Adapter ──────────────────────────────────────────────────

class TestCSharpEmptyCatch:
    def test_empty_catch(self):
        code = b'''
class App {
    void F() {
        try { Risky(); }
        catch (IOException e) { }
    }
}
'''
        findings = CSharpAdapter().check(code, "App.cs")
        assert any(f.rule == "MR-005" for f in findings)


class TestCSharpBroadCatch:
    def test_catch_exception_no_rethrow(self):
        code = b'''
class App {
    void F() {
        try { Risky(); }
        catch (Exception e) { Console.WriteLine(e); }
    }
}
'''
        findings = CSharpAdapter().check(code, "App.cs")
        assert any(f.rule == "MR-001" for f in findings)

    def test_bare_catch_no_rethrow(self):
        code = b'''
class App {
    void F() {
        try { Risky(); }
        catch { Console.WriteLine("error"); }
    }
}
'''
        findings = CSharpAdapter().check(code, "App.cs")
        assert any(f.rule == "MR-001" for f in findings)


class TestCSharpDisposable:
    def test_sqlconnection_no_using(self):
        code = b'''
class App {
    void Query() {
        SqlConnection conn = new SqlConnection("...");
        conn.Open();
    }
}
'''
        findings = CSharpAdapter().check(code, "App.cs")
        assert any(f.rule == "RC-001" for f in findings)


class TestCSharpHardcodedSecret:
    def test_password_field(self):
        code = b'''
class Config {
    string password = "admin123";
}
'''
        findings = CSharpAdapter().check(code, "Config.cs")
        assert any(f.rule == "TB-010" for f in findings)


class TestCSharpWeakRandom:
    def test_new_random(self):
        code = b'''
class App {
    void GenToken() { Random rng = new Random(); }
}
'''
        findings = CSharpAdapter().check(code, "App.cs")
        assert any(f.rule == "TB-026" for f in findings)


class TestCSharpDebugAssert:
    def test_debug_assert(self):
        code = b'''
class App {
    void Validate(int x) { Debug.Assert(x > 0); }
}
'''
        findings = CSharpAdapter().check(code, "App.cs")
        assert any(f.rule == "SI-006" for f in findings)


class TestCSharpProcessStart:
    def test_process_start(self):
        code = b'''
class App {
    void Run(string cmd) { Process.Start(cmd); }
}
'''
        findings = CSharpAdapter().check(code, "App.cs")
        assert any(f.rule == "TB-015" for f in findings)


class TestCSharpTodo:
    def test_todo_comment(self):
        code = b'''
class App {
    // TODO: fix security issue
    void F() {}
}
'''
        findings = CSharpAdapter().check(code, "App.cs")
        assert any(f.rule == "SI-004" for f in findings)


# ── End-to-end: mixed project scan ─────────────────────────────

class TestMixedProject:
    """Scan a mix of C++, C#, and verify adapters don't interfere."""

    def test_cpp_and_csharp_same_rule(self):
        cpp_code = b'char* secret_key = "s3cr3t";'
        cs_code = b'class C { string secretKey = "s3cr3t"; }'

        cpp_findings = CppAdapter().check(cpp_code, "test.cpp")
        cs_findings = CSharpAdapter().check(cs_code, "Test.cs")

        assert any(f.rule == "TB-010" for f in cpp_findings)
        assert any(f.rule == "TB-010" for f in cs_findings)


# Bismillah ir-Rahman ir-Rahim
