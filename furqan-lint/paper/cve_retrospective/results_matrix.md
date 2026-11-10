# CVE Retrospective: Three-Tool Comparison Matrix

## Summary

15 CVEs tested across 5 vulnerability families. For each, we ask: does the
tool flag the pattern that caused or enabled the vulnerability?

Grading:
- **HIT**: flags the actual vulnerability pattern (root cause or enabling condition)
- **PARTIAL**: flags something at the same location but not the root cause
- **MISS**: produces no finding on the vulnerable code

## Aggregate Matrix

| # | CVE | Year | CVSS | Root cause family | furqan | bandit | ruff | Unique furqan? |
|---|-----|------|------|-------------------|--------|--------|------|----------------|
| 1 | 2017-1000433 | 2017 | 8.1 | assert as auth check | HIT (SI-006) | HIT (B101) | MISS | no |
| 2 | 2018-1000805 | 2018 | -- | swallowed auth exception | HIT (MR-005/002) | HIT (B110) | HIT (S110/BLE001) | no |
| 3 | 2020-14343 | 2020 | 9.8 | yaml deserialization | HIT (TB-006) | HIT (B506) | MISS | no |
| 4 | 2020-27619 | 2020 | 9.8 | eval on HTTP content | HIT (TB-005) | HIT (B307/B310) | MISS | no |
| 5 | 2021-23727 | 2021 | -- | getattr/hasattr injection | HIT (SI-007) | PARTIAL (B110) | PARTIAL (S110/B004) | **YES** (SI-007) |
| 6 | 2021-38305 | 2021 | 7.5 | eval on schema input | HIT (TB-005) | HIT (B307) | MISS | no |
| 7 | 2022-28346 | 2022 | 9.8 | ORM kwargs injection | MISS | MISS | MISS | no (all miss) |
| 8 | 2022-39227 | 2022 | -- | swallowed auth exception | HIT (MR-005/002) | HIT (B110) | HIT (S110/BLE001) | no |
| 9 | 2023-40217 | 2023 | 5.3 | swallowed SSLError | HIT (MR-005) | PARTIAL (B504) | MISS | **YES** (MR-005) |
| 10 | 2023-43791 | 2023 | 9.8 | hardcoded SECRET_KEY | HIT (TB-010) | HIT (B105) | MISS | no |
| 11 | 2023-6597 | 2023 | 7.4 | temp fd leak | HIT (RC-005) | PARTIAL (B110) | PARTIAL (S110) | **YES** (RC-005) |
| 12 | 2024-3126 | 2024 | -- | shell injection | HIT (TB-015) | HIT (B602) | MISS | no |
| 13 | 2024-35195 | 2024 | 5.6 | verify=False reuse | HIT (TB-022) | MISS | MISS | **YES** (TB-022) |
| 14 | 2024-45231 | 2024 | 5.3 | swallowed email error | HIT (MR-005/002) | HIT (B110) | HIT (S110/BLE001) | no |
| 15 | 2026-41523 | 2026 | 7.5 | assert + hasattr bypass | HIT (SI-006/SI-007) | HIT (B101) | MISS | **PARTIAL** (SI-007 unique) |

## Summary Statistics

| Metric | furqan-lint | bandit | ruff |
|--------|--------:|-------:|-----:|
| HIT (flags root cause) | 14/15 (93%) | 11/15 (73%) | 4/15 (27%) |
| PARTIAL (flags something else) | 0/15 | 3/15 | 2/15 |
| MISS (no relevant finding) | 1/15 | 1/15 | 9/15 |
| CVEs with unique furqan HIT | 4/15 | 0/15 | 0/15 |
| CVEs with unique furqan signal | 5/15 | 0/15 | 0/15 |

## Key Observations

### 1. furqan-lint's unique catches (no bandit or ruff root-cause signal)

**CVE-2021-23727 (Celery RCE):** SI-007 flags the hasattr() that enabled the
unrestricted getattr chain. Bandit and ruff only flag the except:pass symptom.

**CVE-2023-40217 (CPython TLS bypass):** MR-005 flags the swallowed SSLError
that was the actual vulnerability. Bandit flags ssl.wrap_socket protocol version
(unrelated). Ruff has no finding.

**CVE-2023-6597 (tempfile fd leak):** RC-005 flags mkstemp without cleanup --
the pattern that leaked file descriptors. Bandit/ruff only see the except:pass
in the loop variant, not the fd leak itself.

**CVE-2024-35195 (requests cert bypass):** TB-022 flags verify=False. Neither
bandit nor ruff has a finding on this pattern.

**CVE-2026-41523 (vLLM assert bypass):** SI-006 flags assert (overlap with
bandit B101), but SI-007 also flags both hasattr() calls -- the code that reads
attacker-controlled config fields. Ruff misses entirely.

### 2. Overlap (all tools catch)

3 CVEs (2018-1000805, 2022-39227, 2024-45231) involve except:pass in auth/security
contexts. All three tools catch these through their try-except-pass rules.

### 3. Shared with bandit only

5 CVEs (2017-1000433, 2020-14343, 2020-27619, 2021-38305, 2023-43791) are caught
by both furqan-lint and bandit but missed by ruff. These are traditional security
patterns (yaml.load, eval, hardcoded secrets, assert, shell injection).

### 4. The honest miss

**CVE-2022-28346 (Django ORM kwargs injection):** All three tools miss this.
SI-005 detects **kwargs in function definitions, not at call sites where user
data flows into ORM methods. This is a detection gap for furqan-lint.

### 5. Rule families that drove unique catches

| Rule | CVEs uniquely caught | Pattern family |
|------|---------------------|----------------|
| SI-007 | 2021-23727, 2026-41523 (partial) | hasattr/getattr masking |
| MR-005 | 2023-40217 | Swallowed typed exception |
| RC-005 | 2023-6597 | Resource lifecycle (temp file) |
| TB-022 | 2024-35195 | SSL verification disabled |

These are exactly the rule families identified as genuinely novel in Paper 2
(the three-way overlap decomposition).

## Threats to Validity

1. **Reconstructed patterns, not original code.** The CVE pattern files are
   simplified reconstructions of the vulnerable patterns described in advisories,
   not verbatim copies of the original vulnerable code. The actual vulnerable
   functions may have additional context that affects tool behavior.

2. **Small sample.** 15 CVEs is exploratory, not exhaustive.

3. **Selection bias.** CVEs were selected by searching for patterns matching
   furqan-lint rule families. A random sample of Python CVEs would produce
   different hit rates.

4. **Grading is judgment.** "HIT" vs "PARTIAL" depends on whether we consider
   the tool's finding to target the root cause. Reasonable people may disagree
   on CVE-2023-40217 (bandit's B504 vs furqan-lint's MR-005).

5. **Tool versions fixed.** Results may differ with other versions.

6. **COI.** Author develops furqan-lint.
