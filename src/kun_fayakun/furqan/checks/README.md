# furqan-lint

Structural honesty verification for code. Six languages, one command.

```
kun furqan lint ./src/
```

## What it catches that other linters miss

On **Django** (281,000 lines):

| Linter | Findings |
|--------|----------|
| ruff | 0 (codebase is ruff-clean) |
| bandit | 281 |
| **furqan-lint** | **3,389** |

furqan-lint finds **12x more** than bandit on an already-clean codebase, because it checks a class of patterns no other tool looks for: structural honesty -- whether what the code *claims* to do matches what it *actually* does.

## One-line install

```bash
pip install kun-fayakun
```

## Quick start

```bash
# Scan a Python project
kun furqan lint ./myproject/

# Scan a mixed C/Java/Python codebase
kun furqan lint ./src/

# JSON output for CI
kun furqan lint --format json ./src/

# SARIF for GitHub Code Scanning / VS Code
kun furqan lint --format sarif ./src/ > results.sarif

# Only CRITICAL and HIGH
kun furqan lint --min-severity HIGH ./src/

# Only security rules
kun furqan lint --select TB ./src/
```

## Example output

```
vulnerable.c:13:4: TB-029 [CRITICAL] `strcpy()` -- no bounds checking, buffer overflow risk
    fix: recalibrate

App.java:12:8: TB-018 [HIGH] SQL injection via string concatenation in `executeQuery()`
    fix: recalibrate

controller.adb:18:6: MR-005 [CRITICAL] `when others => null;` -- exception silenced entirely
    fix: enrich

service.py:44:0: RC-001 [HIGH] `open()` without context manager -- resource leak
    fix: enrich
```

Every finding tells you three things: what is wrong, how severe it is, and which **repair operation** (tawba) fixes it:

- **simplify** -- remove what should not be there
- **recalibrate** -- align the surface (what it says) with the substrate (what it does)
- **enrich** -- add what is missing

## Supported languages

| Language | Extensions | Rules | Safety domain |
|----------|-----------|-------|---------------|
| Python | .py | 40 | General, web, ML, automation |
| C | .c .h | 14 | Automotive (MISRA), medical devices, aerospace, nuclear |
| C++ | .cpp .cc .cxx .hpp .hxx .hh | 21 | AUTOSAR C++14, aerospace, trading, medical imaging |
| Java | .java | 10 | Financial services, medical records, enterprise |
| C# | .cs | 12 | FDA 21 CFR Part 11, financial, enterprise .NET |
| Ada/SPARK | .adb .ads .ada | 11 | DO-178C aerospace, IEC 60880 nuclear, EN 50128 railway |

All languages produce the same Finding format, use the same config system, and output to the same formats (text, JSON, SARIF).

## Real-world comparison (Python)

Tested against real open-source libraries:

| Codebase | furqan-lint | bandit | ruff | Ratio |
|----------|-----------|--------|------|-------|
| Django | 3,389 | 281 | 0 | 12x bandit |
| Celery | 1,176 | 49 | 0 | 24x bandit |
| Paramiko | 309 | 21 | 0 | 15x bandit |
| Boto3 | 80 | 0 | 0 | -- |
| Requests | 214 | 16 | 0 | 13x bandit |
| Flask | 135 | 12 | 0 | 11x bandit |

98% of bandit's non-noise findings are covered. The remaining 2% are import-level warnings (e.g. "you imported subprocess") that furqan-lint correctly skips in favor of catching actual *usage*.

## Rule families

### RING-CLOSE (RC-*) -- Unclosed resources

What opens must close. Files, locks, sockets, connections, temp files.

### MARAD (MR-*) -- Silent failure

When something is wrong, the code must signal it. Bare `except:` with no re-raise, empty catch blocks, ignored return values, catch-continue loops.

### TRUST-BOUNDARY (TB-*) -- Security and trust violations

Where untrusted input meets trusted execution: hardcoded secrets, shell injection, SQL injection, buffer overflows, format strings, insecure crypto, SSL bypass, unsafe casts, XXE, weak random.

### SCAN-INCOMPLETE (SI-*) -- Incomplete verification

What has not been examined cannot be trusted: `Any` annotations, blanket `# type: ignore`, stale TODOs, `assert` for runtime validation, `hasattr` masking errors, SPARK_Mode(Off), Unchecked_Conversion.

## Configuration

Create `.furqan.toml` in your project root:

```toml
# Run only security-related rules
select = ["TB"]

# Suppress noisy rules
ignore = ["SI-004", "SI-007"]

# Skip findings below this severity
min_severity = "MEDIUM"

# Exclude paths
exclude = ["tests/", "vendor/"]

# Per-file rule suppression
[per_file_ignores]
"tests/*.py" = ["SI-004"]
"migrations/*.py" = ["TB-001"]
```

Or add to `pyproject.toml`:

```toml
[tool.furqan]
select = ["TB", "MR"]
min_severity = "HIGH"
```

## Output formats

### Text (default)
Human-readable, colored terminal output with severity and fix category.

### JSON (`--format json`)
Machine-readable array of finding objects for CI pipelines.

### SARIF (`--format sarif`)
SARIF v2.1.0 for GitHub Code Scanning integration and VS Code SARIF Viewer.

## What is structural honesty?

A system is structurally honest when its surface (what it claims to do) matches its substrate (what it actually does). The gap between the two is where bugs, vulnerabilities, and failures hide.

- A function that catches `Exception` and passes claims to handle errors. It doesn't.
- A variable named `password` with the value `"admin123"` claims to be secret. It isn't.
- `strcpy(buf, input)` claims the buffer is big enough. It has no way to know.
- `when others => null;` in Ada claims the exception is handled. It's deleted.

furqan-lint finds these gaps. Every other linter checks style or known vulnerability patterns. furqan-lint checks whether the code is *honest about what it does*.

## License

Apache-2.0

---

*Bismillah ir-Rahman ir-Rahim*
