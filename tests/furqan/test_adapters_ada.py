# Bismillah ir-Rahman ir-Rahim
"""
Tests for Ada/SPARK language adapter.
"""

import pytest

from kun_fayakun.furqan.checks.adapters.base import get_adapter, supported_extensions
from kun_fayakun.furqan.checks.adapters.ada_adapter import AdaAdapter


class TestRegistration:
    def test_adb_extension(self):
        adapter = get_adapter("main.adb")
        assert adapter is not None
        assert adapter.language_name() == "Ada/SPARK"

    def test_ads_extension(self):
        adapter = get_adapter("spec.ads")
        assert adapter is not None
        assert adapter.language_name() == "Ada/SPARK"

    def test_ada_extension(self):
        adapter = get_adapter("legacy.ada")
        assert adapter is not None

    def test_extensions_in_supported(self):
        exts = supported_extensions()
        assert ".adb" in exts
        assert ".ads" in exts
        assert ".ada" in exts


class TestExceptionHandlerNull:
    def test_when_others_null(self):
        code = b'''
procedure Main is
begin
   begin
      Risky;
   exception
      when others =>
         null;
   end;
end Main;
'''
        findings = AdaAdapter().check(code, "main.adb")
        assert any(f.rule == "MR-005" for f in findings)
        assert any("silenced" in f.message for f in findings if f.rule == "MR-005")

    def test_when_others_no_reraise(self):
        code = b'''
procedure Main is
begin
   begin
      Risky;
   exception
      when others =>
         Log_Error("something failed");
   end;
end Main;
'''
        findings = AdaAdapter().check(code, "main.adb")
        assert any(f.rule == "MR-001" for f in findings)

    def test_when_others_with_raise_is_clean(self):
        code = b'''
procedure Main is
begin
   begin
      Risky;
   exception
      when others =>
         Log_Error("failed");
         raise;
   end;
end Main;
'''
        findings = AdaAdapter().check(code, "main.adb")
        assert not any(f.rule == "MR-001" for f in findings)
        assert not any(f.rule == "MR-005" for f in findings)

    def test_specific_exception_not_flagged(self):
        code = b'''
procedure Main is
begin
   begin
      Risky;
   exception
      when Constraint_Error =>
         null;
   end;
end Main;
'''
        findings = AdaAdapter().check(code, "main.adb")
        # Specific exception handler -- MR-001 only fires on `others`
        assert not any(f.rule == "MR-001" for f in findings)


class TestHardcodedSecrets:
    def test_password_constant(self):
        code = b'''
procedure Main is
   Password : constant String := "s3cr3t123";
begin
   null;
end Main;
'''
        findings = AdaAdapter().check(code, "main.adb")
        assert any(f.rule == "TB-010" for f in findings)

    def test_api_key(self):
        code = b'''
procedure Main is
   API_Key : String := "AKIAIOSFODNN7EXAMPLE";
begin
   null;
end Main;
'''
        findings = AdaAdapter().check(code, "main.adb")
        assert any(f.rule == "TB-010" for f in findings)

    def test_tmp_path(self):
        code = b'''
procedure Main is
   Log_Path : constant String := "/tmp/myapp.log";
begin
   null;
end Main;
'''
        findings = AdaAdapter().check(code, "main.adb")
        assert any(f.rule == "TB-012" for f in findings)


class TestPragmaAssert:
    def test_pragma_assert(self):
        code = b'''
procedure Main is
   X : Integer := 5;
begin
   pragma Assert (X > 0);
end Main;
'''
        findings = AdaAdapter().check(code, "main.adb")
        assert any(f.rule == "SI-006" for f in findings)


class TestSparkModeOff:
    def test_spark_mode_off(self):
        code = b'''
procedure Unsafe_Region is
   pragma SPARK_Mode (Off);
begin
   null;
end Unsafe_Region;
'''
        findings = AdaAdapter().check(code, "unsafe.adb")
        assert any(f.rule == "SI-009" for f in findings)

    def test_spark_mode_on_is_clean(self):
        code = b'''
procedure Safe_Region is
   pragma SPARK_Mode (On);
begin
   null;
end Safe_Region;
'''
        findings = AdaAdapter().check(code, "safe.adb")
        assert not any(f.rule == "SI-009" for f in findings)


class TestUncheckedOps:
    def test_unchecked_conversion(self):
        code = b'''
with Ada.Unchecked_Conversion;
procedure Main is
begin
   null;
end Main;
'''
        findings = AdaAdapter().check(code, "main.adb")
        assert any(f.rule == "SI-010" for f in findings)

    def test_unchecked_deallocation(self):
        code = b'''
with Ada.Unchecked_Deallocation;
procedure Main is
begin
   null;
end Main;
'''
        findings = AdaAdapter().check(code, "main.adb")
        assert any(f.rule == "SI-011" for f in findings)


class TestResourceLeak:
    def test_open_without_close(self):
        code = b'''
with Ada.Text_IO; use Ada.Text_IO;
procedure Main is
   F : File_Type;
begin
   Open(F, In_File, "data.txt");
   Get(F, X);
end Main;
'''
        findings = AdaAdapter().check(code, "main.adb")
        assert any(f.rule == "RC-001" for f in findings)

    def test_open_with_close_is_clean(self):
        code = b'''
with Ada.Text_IO; use Ada.Text_IO;
procedure Main is
   F : File_Type;
begin
   Open(F, In_File, "data.txt");
   Get(F, X);
   Close(F);
end Main;
'''
        findings = AdaAdapter().check(code, "main.adb")
        assert not any(f.rule == "RC-001" for f in findings)


class TestWeakRandom:
    def test_discrete_random(self):
        code = b'''
with Ada.Numerics.Discrete_Random;
procedure Main is
begin
   null;
end Main;
'''
        findings = AdaAdapter().check(code, "main.adb")
        assert any(f.rule == "TB-034" for f in findings)


class TestTodoComments:
    def test_todo_in_ada_comment(self):
        code = b'''
procedure Main is
begin
   -- TODO: implement safety check
   null;
end Main;
'''
        findings = AdaAdapter().check(code, "main.adb")
        assert any(f.rule == "SI-004" for f in findings)


class TestFullSafetyAudit:
    """Integration: a realistic unsafe Ada file."""

    def test_multiple_findings(self):
        code = b'''
with Ada.Text_IO; use Ada.Text_IO;
with Ada.Unchecked_Conversion;

procedure Controller is
   Secret_Key : constant String := "reactor_key_2024";
   F : File_Type;
   -- TODO: add proper error handling
begin
   pragma Assert (True);
   Open(F, In_File, "config.dat");

   begin
      Process_Command;
   exception
      when others =>
         null;
   end;
end Controller;
'''
        findings = AdaAdapter().check(code, "controller.adb")
        rules = {f.rule for f in findings}
        assert "TB-010" in rules, "Should detect hardcoded secret"
        assert "SI-004" in rules, "Should detect TODO"
        assert "SI-006" in rules, "Should detect pragma Assert"
        assert "SI-010" in rules, "Should detect Unchecked_Conversion"
        assert "RC-001" in rules, "Should detect file not closed"
        assert "MR-005" in rules, "Should detect when others => null"
        assert len(findings) >= 6


# Bismillah ir-Rahman ir-Rahim
