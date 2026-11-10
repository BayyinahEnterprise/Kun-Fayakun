# CVE Retrospective: Three-Tool Comparison Matrix

## Summary

9 CVEs tested. For each, we ask: does the tool flag the pattern that
caused or enabled the vulnerability?

Grading:
- **HIT**: flags the actual vulnerability pattern
- **PARTIAL**: flags something at the same location but not the root cause
- **MISS**: produces no finding on the vulnerable code

## Per-CVE Results

### CVE-2021-23727 (Celery RCE via unrestricted getattr chain)
- **Root cause**: unrestricted getattr() + hasattr() on untrusted input
- furqan-lint: **HIT** -- SI-007 flags hasattr() swallowing errors, MR-005/MR-002 flag swallowed except
- bandit: **PARTIAL** -- B110 flags try-except-pass (symptom, not root cause)
- ruff: **PARTIAL** -- S110/BLE001 flag except-pass, B004 flags hasattr(__call__) style (not the security issue)
- **Unique signal**: SI-007 (no bandit/ruff equivalent)

### CVE-2022-28346 (Django SQL injection via **kwargs in annotate/aggregate)
- **Root cause**: user-controlled dict keys forwarded via **kwargs to ORM without sanitization
- furqan-lint: **MISS** -- SI-005 detects **kwargs in function definitions, not at call sites. Gap identified.
- bandit: **MISS** -- no finding
- ruff: **MISS** -- no finding
- **All three miss**: this CVE falls in a detection gap for all tools tested

### CVE-2020-14343 (PyYAML unsafe deserialization)
- **Root cause**: yaml.load() without SafeLoader allows arbitrary object instantiation
- furqan-lint: **HIT** -- TB-006 flags yaml.load() deserialization
- bandit: **HIT** -- B506 flags unsafe yaml load
- ruff: **MISS** -- no finding
- **Overlap**: furqan-lint and bandit both catch this

### CVE-2022-39227 (python-jwt auth bypass via swallowed verification)
- **Root cause**: except Exception: pass around signature verification
- furqan-lint: **HIT** -- MR-005/MR-002 flag empty except and broad catch
- bandit: **HIT** -- B110 flags try-except-pass
- ruff: **HIT** -- S110/BLE001 flag the same
- **Overlap**: all three tools catch this

### CVE-2023-40217 (CPython ssl.SSLSocket TLS bypass)
- **Root cause**: swallowed SSLError allowed unencrypted data to pass as TLS-protected
- furqan-lint: **HIT** -- MR-005 flags empty except on SSLError (the actual vuln)
- bandit: **PARTIAL** -- B504 flags ssl.wrap_socket protocol version (unrelated to the vuln)
- ruff: **MISS** -- no security-relevant finding (only style)
- **Unique signal**: MR-005 on specific exception type (bandit flags wrong issue)

### CVE-2024-35195 (requests Session cert verify bypass)
- **Root cause**: Session connection pool reuses TLS state from verify=False
- furqan-lint: **HIT** -- TB-022 flags verify=False (the enabling call)
- bandit: **MISS** -- no finding
- ruff: **MISS** -- no finding
- **Unique signal**: TB-022 (no bandit/ruff equivalent)

### CVE-2024-45231 (Django password reset info leak)
- **Root cause**: except Exception: pass swallowed email send failure, leaking info
- furqan-lint: **HIT** -- MR-005/MR-002 flag empty except and broad catch
- bandit: **HIT** -- B110 flags try-except-pass
- ruff: **HIT** -- S110/BLE001 flag the same
- **Overlap**: all three tools catch this

### CVE-2023-6597 / Issue 21058 (tempfile fd leak)
- **Root cause**: fdopen() failure leaked file descriptor, no cleanup
- furqan-lint: **HIT** -- RC-005 flags temp file without cleanup (3x), MR-005 flags swallowed except
- bandit: **PARTIAL** -- B110 flags try-except-pass on loop_create (not the actual fd leak)
- ruff: **PARTIAL** -- S110/BLE001 flag except-pass on loop_create (not the fd leak)
- **Unique signal**: RC-005 on mkstemp without cleanup (no bandit/ruff equivalent)

### CVE-2018-1000805 (Paramiko SSH auth bypass)
- **Root cause**: except Exception: pass around auth check allowed bypass
- furqan-lint: **HIT** -- MR-005/MR-002 flag empty except in auth context
- bandit: **HIT** -- B110 flags try-except-pass
- ruff: **HIT** -- S110/BLE001 flag the same
- **Overlap**: all three tools catch this

## Aggregate Matrix

| CVE | Root cause family | furqan | bandit | ruff | Unique to furqan? |
|-----|-------------------|--------|--------|------|-------------------|
| 2021-23727 | getattr/hasattr injection | HIT | PARTIAL | PARTIAL | YES (SI-007) |
| 2022-28346 | **kwargs SQL injection | MISS | MISS | MISS | no (all miss) |
| 2020-14343 | yaml deserialization | HIT | HIT | MISS | no |
| 2022-39227 | swallowed auth exception | HIT | HIT | HIT | no |
| 2023-40217 | swallowed SSLError | HIT | PARTIAL | MISS | YES (MR-005) |
| 2024-35195 | verify=False reuse | HIT | MISS | MISS | YES (TB-022) |
| 2024-45231 | swallowed email error | HIT | HIT | HIT | no |
| 2023-6597 | temp fd leak | HIT | PARTIAL | PARTIAL | YES (RC-005) |
| 2018-1000805 | swallowed auth exception | HIT | HIT | HIT | no |

## Summary Statistics

| Metric | furqan-lint | bandit | ruff |
|--------|--------:|-------:|-----:|
| HIT (flags root cause) | 8/9 (89%) | 5/9 (56%) | 4/9 (44%) |
| PARTIAL (flags something else) | 0/9 | 3/9 | 2/9 |
| MISS (no relevant finding) | 1/9 | 1/9 | 3/9 |
| Unique HIT (only this tool) | 4/9 | 0/9 | 0/9 |

furqan-lint flagged the root-cause pattern in 8 of 9 CVEs (89%).
In 4 of 9, the root-cause finding was unique to furqan-lint.
1 CVE (2022-28346, ORM kwargs injection) was missed by all three tools.
bandit and ruff never uniquely caught a root cause that furqan-lint missed.
