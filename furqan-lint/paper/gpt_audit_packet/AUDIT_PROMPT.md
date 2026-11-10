# FRESH AUDIT DISPATCH: Paper 2 -- Three-Tool Overlap Decomposition

You are an independent auditor. You have never seen this paper or its data before. Your task is to audit it for honesty, correctness, and internal consistency. You have no loyalty to the tool or the author. Your job is to find what is wrong.

**Paper title:** "Three-Tool Overlap Decomposition of furqan-lint Findings Across 25 Python Codebases"
**Author:** Bilal Syed Arfeen, BayyinahEnterprise, November 2026

**Prior audit:** This paper was previously audited by a Claude Fable instance which returned HALT with 2 CRITICAL / 9 HIGH / 9 MEDIUM / 3 LOW / 1 INFO. The producer (Claude Opus 4.6) repaired all 24 findings. You are a fresh auditor verifying the repairs and looking for anything Fable missed.

**Your audit is independent of Fable's.** Do not defer to or repeat Fable's findings. Read the paper and data fresh.

## Files in this packet

| File | Purpose |
|------|---------|
| `paper2_three_way.md` | The full paper text (primary audit target) |
| `three_way_summary.json` | Aggregate overlap counts (verify against paper's tables) |
| `three_way_by_package.csv` | Per-package breakdown (verify per-package claims) |
| `precision_v2_summary.json` | Classifier output summary (verify against Section 3.3) |
| `precision_v2_classified.json` | All 585 classified findings with source context |
| `three_way_decomposition.py` | The overlap decomposition script |
| `precision_study_v2.py` | The keyword classifier script |
| `run_ruff.py` | The ruff runner with 30-rule selection |
| `versions.json` | Python and package versions |
| `rule_manifest.json` | All 50 furqan-lint rule IDs with language/activation |

## Report format

For each finding:

```
FINDING [N]
Severity: CRITICAL / HIGH / MEDIUM / LOW / INFO
Section: [section number and title]
Claim: [exact quote or paraphrase of the claim]
Problem: [what is wrong]
Evidence: [how you know]
Repair: [what should change]
```

## Audit dimensions

1. **Arithmetic.** Do the numbers add up? Do percentages match their numerators and denominators? Cross-check every table against the JSON/CSV data.

2. **Internal consistency.** Does the abstract match the results? Do claims in the discussion contradict the method? Are the same numbers reported the same way everywhere?

3. **Honesty of framing.** Does the paper overclaim? Does it use causal language for correlational evidence? Does it present limitations prominently? Are withdrawn claims actually withdrawn, or do traces remain?

4. **Repair verification.** The prior audit found: (a) 35.3% safety was a raw sample proportion, not stratum-weighted; (b) 99.3% precision was assumed, not measured; (c) the rater was a keyword function misidentified as an LLM; (d) missing ruff rules inflated uniqueness. Verify these were actually fixed and no traces of the old claims survive.

5. **Omissions.** What should the paper say that it doesn't?

6. **Terminology.** Is "not co-located" used consistently? Is it clearly distinguished from "unique"? Is "precision" correctly disclaimed?

## Standing rules (author conventions)

- No em-dash character U+2014 (use `--` instead). Count: `grep -c` of em-dash must return 0.
- No use of "prevents", "mitigates", "ensures", "guarantees".
- No mention of "Unified Analytical Framework" / "UAF" or "Golden Thread".

## Verdict

End with one of:
- **PASS** -- no CRITICAL or HIGH findings remaining
- **PASS WITH REVISIONS** -- no CRITICAL, some HIGH that are repairable without restructuring
- **HALT** -- CRITICAL findings remain, return to producer
