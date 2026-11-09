# furqan-lint

Structural honesty verification for code. Six languages, one command.

```
kun furqan lint ./src/
```

## What it checks

furqan-lint checks whether code's surface behavior (what it claims to do) matches its substrate behavior (what it actually does). It produces findings from 42 Python rules and 8 adapter-only rules across six languages (50 rule IDs total, 39 active by default).

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

## Benchmark (v2.1.0)

Compared against bandit 1.9.4 on 25 open-source Python packages (2.3M lines). With symmetric test-path exclusion, furqan-lint produces more findings in all 25 packages:

| Condition | furqan total | bandit total | Pooled ratio | furqan > bandit |
|-----------|:-----------:|:-----------:|:-----------:|:---------------:|
| Both exclude test paths | 22,888 | 3,615 | 6.3x | 25 / 25 |
| As run (SI-006 exempts tests, B101 does not) | 24,933 | 29,959 | 0.83x | 22 / 25 |

**Caveat.** Two rules (SI-001: Any annotation, SI-006: assert) account for 58.6% of furqan-lint's output. SI-001 duplicates ruff's ANN401. The false positive rate is not measured. See the paper in `paper/` for full methodology and data.

Selected packages:

| Package | furqan | bandit | Ratio |
|---------|-------:|-------:|------:|
| django | 1,605 | 281 | 5.7x |
| sqlalchemy | 8,496 | 866 | 9.8x |
| pydantic | 2,099 | 86 | 24.4x |
| celery | 703 | 49 | 14.3x |
| numpy | 1,018 | 3,597 | 0.3x |
| pandas | 2,657 | 17,701 | 0.2x |

Full CSV: `paper/benchmark_v2.1.0.csv`. Raw JSON from both tools: `paper/raw_json/`, `paper/bandit_json/`.

## Supported languages

| Language | Extensions | Rules | Safety domain |
|----------|-----------|-------|---------------|
| Python | .py | 42 (39 active) | General, web, ML, automation |
| C | .c .h | 9 | Automotive (MISRA), medical, aerospace |
| C++ | .cpp .cc .cxx .hpp .hxx .hh | 5 additional | AUTOSAR, aerospace, trading |
| Java | .java | 8 | Financial, medical, enterprise |
| C# | .cs | 10 | FDA, financial, .NET |
| Ada/SPARK | .adb .ads .ada | 11 | DO-178C, IEC 60880, EN 50128 |

All languages produce the same Finding format, use the same config system, and output to text, JSON, or SARIF.

## Rule families

### RING-CLOSE (RC-*) -- Unclosed resources

What opens must close. Files, locks, sockets, connections, temp files.

### MARAD (MR-*) -- Silent failure

When something is wrong, the code must signal it. Bare `except:` with no re-raise, empty catch blocks, ignored return values, catch-continue loops.

### TRUST-BOUNDARY (TB-*) -- Security and trust violations

Where untrusted input meets trusted execution: hardcoded secrets, shell injection, SQL injection, buffer overflows, format strings, insecure crypto, SSL bypass, unsafe casts, XXE, weak random. Three informational rules (TB-001/002/003) flag language features and are off by default.

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

## License

Apache-2.0

---

*Bismillah ir-Rahman ir-Rahim*
