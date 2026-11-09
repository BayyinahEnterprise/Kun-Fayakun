# Structural Honesty Verification as a Complementary Static Analysis Class: An Empirical Benchmark of furqan-lint Across 25 Open-Source Python Codebases

**Bilal Syed Arfeen**
BayyinahEnterprise
November 2026

---

## Abstract

We present an empirical evaluation of furqan-lint v2.1.0, a multi-language static analysis tool that checks for *structural honesty* -- whether a program's surface behavior (what it claims to do) matches its substrate behavior (what it actually does). We benchmark furqan-lint against bandit across 25 widely-used open-source Python packages totaling 2,327,868 lines of code and 5,252 files. furqan-lint produces more findings than bandit in 22 of 25 packages (median per-package ratio 5.0x; pooled ratio 0.83x, pulled below 1.0 by three scientific computing packages where bandit's assert-usage rule dominates). Two rules -- SI-001 (Any type annotation) and SI-006 (assert in non-test code) -- account for 58.6% of furqan-lint's output. We argue that structural honesty verification occupies a region of the analysis space that existing linters leave unexamined, but we do not decompose the overlap between tools in this study. We provide the full dataset, including raw JSON output from both tools, for reproducibility.

**Note on terminology.** Throughout this paper, *finding* means a pattern flagged by a tool's rule. Some findings are true positives (genuine problems); others are intentional design choices that happen to match a pattern. The false positive rate is not measured in this study. We present the results as evidence that structural honesty verification produces different counts from different rules, not as a claim that every finding represents a defect.

---

## 1. Introduction

Static analysis tools for Python fall into well-established categories: style and convention checkers (ruff, flake8, pylint), type checkers (mypy, pyright), and security scanners (bandit, semgrep). Each category targets a specific finding class: formatting inconsistencies, type errors, and known vulnerability patterns, respectively.

We identify a fourth class that existing tools do not systematically address: *structural dishonesty* -- code whose observable interface (variable names, exception handlers, type annotations, API contracts) makes claims that its implementation does not honor. Examples include:

- An `except Exception` block that catches everything but re-raises nothing, claiming to handle errors while silencing them.
- A parameter named `password` assigned the literal string `"admin123"`, claiming secrecy while embedding the secret in source.
- A function accepting `**kwargs` and passing them through to another call without validation, claiming a bounded interface while providing an unbounded one.

These patterns are not style violations, not type errors, and not entries in vulnerability databases. They are gaps between what code says and what code does. We call their detection *structural honesty verification* (SHV).

furqan-lint v2.1.0 implements SHV as 42 Python rules organized into four families:

- **RING-CLOSE (RC)**: resources that open but do not close (5 rules)
- **MARAD (MR)**: failures that occur but produce no signal (5 rules: MR-001, 002, 003, 005, 007)
- **TRUST-BOUNDARY (TB)**: security-relevant boundaries that can be crossed (25 active rules + 3 informational, off by default)
- **SCAN-INCOMPLETE (SI)**: regions where analysis has been explicitly abandoned (7 rules)

Three rules (TB-001, TB-002, TB-003) are classified as *informational* and disabled by default because they flag language features (isinstance, deepcopy, type().__name__) rather than likely problems. All benchmark results use the default configuration: 39 active Python rules.

The tool additionally implements 10 rules for non-Python languages (C, C++, Java, C#, Ada/SPARK) via tree-sitter adapters, bringing the total to 52 unique rule IDs across six languages. Only the 39 active Python rules are exercised in this benchmark.

---

## 2. Method

### 2.1 Package selection

We selected 25 packages from the Python Package Index (PyPI) to maximize diversity across domain (web frameworks, HTTP clients, data science, ORMs, task queues, templating, cryptography, SSH, scraping, CLIs, cloud SDKs, image processing), size (from 6,385 lines to 635,499 lines), and maturity (all widely used in production). No package was excluded based on preliminary results.

### 2.2 Tools compared

| Tool | Version | Configuration |
|------|---------|---------------|
| furqan-lint | v2.1.0 (commit 131ab8b) | Default (39 active Python rules; TB-001/002/003 off) |
| bandit | 1.9.4 | Default (all rules, no exclusions) |

### 2.3 Procedure

Each package was scanned in its installed form from PyPI (site-packages). Both tools were run with default configuration. We recorded per-package finding counts for each tool and computed the ratio of furqan-lint to bandit findings, finding density per 1,000 lines, and furqan-lint's severity distribution.

**Asymmetry note.** furqan-lint's SI-006 (assert usage) exempts test files (paths containing a `test_` prefix, `_test.py` suffix, `conftest.py`, or a `tests/` or `test/` directory component). bandit's B101 (assert_used) does not. Both rules fire on the same pattern, but their test-file treatment differs. Installed packages from PyPI include test files; approximately 36% of total scanned lines are in test paths. This asymmetry is the primary driver of the 0.3x--0.6x ratios in numpy, pandas, and scipy: bandit's B101 fires on test assertions that SI-006 skips.

### 2.4 Threats to validity

1. **Overlap.** furqan-lint includes rules that detect patterns bandit also detects (hardcoded secrets, insecure hashing, etc.). We do not decompose findings into overlapping and unique categories. Higher furqan-lint counts in 22/25 packages do not establish that the *additional* findings are unique; some may duplicate bandit's coverage.

2. **Precision.** Neither tool's false positive rate is measured. Two rules -- SI-001 (Any annotation, 47.1% of output) and SI-006 (assert, 11.5%) -- dominate furqan-lint's finding count. Whether these represent problems or acceptable patterns varies by codebase.

3. **Test-file asymmetry.** See the note above. SI-006 and B101 treat test files differently, which strongly affects the three scientific computing packages.

4. **Installed packages include test files.** Scanning site-packages rather than excluding test directories means both tools encounter test code. This inflates assert-related findings.

5. **Single bandit version and configuration.** Results may differ with other versions or configurations.

---

## 3. Results

### 3.1 Aggregate findings

| Metric | Value |
|--------|-------|
| Packages scanned | 25 |
| Total Python files | 5,252 |
| Total lines of code | 2,327,868 |
| Total furqan-lint findings | 24,933 |
| Total bandit findings | 29,959 |
| Pooled ratio (furqan / bandit) | 0.83x |
| Packages where furqan > bandit | 22 of 25 |
| Packages where bandit > furqan | 3 of 25 |

The pooled ratio is below 1.0 because three large scientific computing packages (numpy, pandas, scipy -- 62% of total lines) have bandit counts dominated by B101 (assert_used) on test files.

### 3.2 Per-package results

| Package | Domain | Files | Lines | furqan | bandit | Ratio |
|---------|--------|------:|------:|-------:|-------:|------:|
| django | Web framework | 909 | 165,634 | 1,605 | 281 | 5.7x |
| flask | Micro web framework | 24 | 9,199 | 76 | 13 | 5.8x |
| fastapi | Async web framework | 52 | 22,748 | 688 | 70 | 9.8x |
| tornado | Async networking | 76 | 50,586 | 947 | 285 | 3.3x |
| starlette | ASGI framework | 36 | 6,947 | 313 | 73 | 4.3x |
| requests | HTTP library | 19 | 6,385 | 149 | 16 | 9.3x |
| httpx | Async HTTP client | 23 | 8,828 | 84 | 29 | 2.9x |
| urllib3 | HTTP client | 36 | 11,914 | 99 | 10 | 9.9x |
| aiohttp | Async HTTP | 54 | 28,467 | 662 | 178 | 3.7x |
| sqlalchemy | SQL ORM | 258 | 253,997 | 8,496 | 866 | 9.8x |
| celery | Task queue | 161 | 47,496 | 703 | 49 | 14.3x |
| jinja2 | Template engine | 25 | 14,425 | 239 | 62 | 3.9x |
| pydantic | Data validation | 105 | 45,762 | 2,099 | 86 | 24.4x |
| cryptography | Crypto library | 78 | 13,868 | 52 | 18 | 2.9x |
| paramiko | SSH library | 42 | 18,621 | 204 | 21 | 9.7x |
| scrapy | Web scraping | 199 | 38,503 | 1,361 | 241 | 5.6x |
| click | CLI framework | 17 | 12,674 | 94 | 36 | 2.6x |
| rich | Rich terminal | 100 | 38,515 | 200 | 58 | 3.4x |
| typer | CLI builder | 32 | 13,911 | 486 | 60 | 8.1x |
| boto3 | AWS SDK | 39 | 8,558 | 38 | 0 | -- |
| PIL | Image processing | 98 | 35,149 | 652 | 288 | 2.3x |
| werkzeug | WSGI utilities | 52 | 21,687 | 184 | 28 | 6.6x |
| numpy | Numerical computing | 407 | 243,710 | 1,018 | 3,597 | 0.3x |
| pandas | Data analysis | 1,422 | 635,499 | 2,657 | 17,701 | 0.2x |
| scipy | Scientific computing | 988 | 574,785 | 1,827 | 5,893 | 0.3x |

### 3.3 Per-package ratio distribution

| Metric | Value |
|--------|-------|
| Mean ratio (n=24, excluding boto3) | 6.2x |
| Median ratio | 5.0x |
| Standard deviation | 5.5 |
| Minimum ratio | 0.2x (pandas) |
| Maximum ratio | 24.4x (pydantic) |

### 3.4 Severity distribution

| Severity | Count | Percentage |
|----------|------:|----------:|
| CRITICAL | 331 | 1.3% |
| HIGH | 1,918 | 7.7% |
| MEDIUM | 17,800 | 71.4% |
| LOW | 4,884 | 19.6% |
| **Total** | **24,933** | **100%** |

CRITICAL findings (1.3%) include TB-006 (pickle/yaml deserialization, 153 findings), TB-005 (eval/exec, 115), MR-001 (bare except without re-raise, 29), and TB-029 (C buffer overflow functions in numpy's bundled C code, 34). The TB-029 hits are from tree-sitter scanning .c files inside numpy's site-packages; they are legitimate C-language findings but come from the non-Python adapter, not the 39 Python rules benchmarked here.

### 3.5 Per-rule concentration

| Rule | Count | % of total | Description |
|------|------:|----------:|----|
| SI-001 | 11,742 | 47.1% | `Any` type annotation |
| SI-006 | 2,872 | 11.5% | `assert` in non-test code |
| SI-005 | 2,794 | 11.2% | `**kwargs` passthrough |
| SI-007 | 2,017 | 8.1% | `hasattr()` swallows AttributeError |
| SI-004 | 1,894 | 7.6% | TODO/FIXME comment |
| MR-005 | 964 | 3.9% | Empty except block |
| All other (35 rules) | 2,650 | 10.6% | |

Two rules (SI-001 and SI-006) produce 58.6% of all findings. The top 6 rules produce 89.4%.

---

## 4. Discussion

### 4.1 Rule concentration

The single largest contributor to furqan-lint's output is SI-001 (Any type annotation, 47.1%). This rule fires on every use of `typing.Any`, which is common in packages with gradual typing. Whether a given `Any` annotation is a genuine structural gap or an acceptable transitional choice depends on the project's typing maturity. ruff's ANN401 detects the same pattern, so SI-001 findings are not unique to structural honesty analysis.

SI-006 (assert in non-test code, 11.5%) fires on assert statements outside test paths. This overlaps with bandit's B101, though with different test-file treatment. The remaining rules (SI-005, SI-007, MR-005, etc.) each contribute under 12%.

### 4.2 Why the ratio varies

The furqan-to-bandit ratio ranges from 0.2x to 24.4x. The primary drivers:

**High-ratio packages** (pydantic 24.4x, celery 14.3x): These have few bandit findings (low security-vulnerability density) but many SI-001/SI-005/SI-007 hits from furqan-lint's structural checks.

**Low-ratio packages** (pandas 0.2x, numpy 0.3x, scipy 0.3x): bandit's B101 fires on every assert in test code. These packages include extensive test suites in their installed form, and B101 is not test-aware. furqan-lint's SI-006 fires on the same pattern but exempts test paths, producing far fewer findings.

### 4.3 Complementarity

The comparison between furqan-lint and bandit is not a competition. The tools address different analysis dimensions. Many furqan-lint rules have no bandit equivalent (error handling analysis, resource lifecycle, kwargs passthrough). Conversely, bandit checks for import-level patterns that furqan-lint omits. Whether the *additional* findings are truly unique requires an overlap decomposition we have not performed.

### 4.4 Limitations

1. **Finding count is not defect count.** The false positive rate is not measured. SI-001 alone (47.1% of output) may have a high false-positive rate in gradually-typed codebases.

2. **No overlap decomposition.** We do not determine how many furqan-lint findings duplicate bandit's coverage. The claim of complementarity rests on the existence of rules with no bandit equivalent, not on quantified uniqueness.

3. **Rule concentration.** Two rules produce 58.6% of output. The tool's apparent breadth is narrower than the rule count suggests.

4. **Test-file asymmetry.** SI-006 exempts test files; B101 does not. This is documented but not corrected.

5. **Installed packages include test files.** Scanning site-packages means test assertions inflate both tools' counts, particularly bandit's.

6. **SI-001 overlaps with ruff ANN401.** The largest single rule detects a pattern that an existing convention checker already flags.

7. **Single bandit version (1.9.4).** Results may differ with other versions or configurations.

8. **No ruff baseline.** We did not verify ruff findings on these packages.

---

## 5. Conclusion

furqan-lint v2.1.0 produces more findings than bandit in 22 of 25 packages (median per-package ratio 5.0x). The pooled ratio across all packages is 0.83x, pulled below 1.0 by three scientific computing packages where bandit's test-aware B101 rule dominates. Two furqan-lint rules (SI-001 and SI-006) account for 58.6% of output.

These results show that furqan-lint produces different finding counts from different rules than bandit. Whether the additional findings represent a genuinely complementary analysis class -- one that occupies space existing tools leave unexamined -- requires an overlap decomposition and precision measurement we have not performed. The evidence is suggestive but not conclusive.

The tool is open-source under Apache-2.0:
**https://github.com/BayyinahEnterprise/Kun-Fayakun**

---

## Data availability

The complete benchmark dataset is included: `benchmark_v2.1.0.csv` (25 packages, per-package counts), `raw_json/` (furqan-lint findings per package), `bandit_json/` (bandit findings per package), `benchmark.py` (harness script), and `test_output_v2.1.0.txt` (183 tests passing). All code is at tag `v2.1.0` in the public repository. The benchmark was run with bandit 1.9.4 and Python 3.13.18.

---

## References

[1] B. S. Arfeen, "Structural Honesty Verification: On Surface-Substrate Divergence Across Systems," 2026.

[2] PyCQA, "Bandit: Security linter for Python," https://bandit.readthedocs.io/

[3] M. Brunsfeld et al., "Tree-sitter: An incremental parsing system for programming tools," https://tree-sitter.github.io/tree-sitter/

[4] OASIS, "Static Analysis Results Interchange Format (SARIF) Version 2.1.0," 2020.
