# Bismillah ir-Rahman ir-Rahim

# HABL -- Honesty-Attested Binding Ledger

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Part of EESS](https://img.shields.io/badge/EESS-instrument-blueviolet.svg)](#the-entourage-effect-software-safety-suite)

> *From* حبل *(habl, "rope") -- "And hold firmly to the rope of Allah all together and do not become divided." (Ali 'Imran 3:103)*

HABL is the shared finding protocol and append-only journal for the **Entourage Effect Software Safety Suite (EESS)**. It is the mycorrhizal network -- the connective tissue through which [furqan-lint](https://github.com/bismillahbilalarfeenbismillah/furqan-lint), [FATIMA](https://github.com/bismillahbilalarfeenbismillah/FATIMA), [Bayyinah](https://github.com/bismillahbilalarfeenbismillah/bayyinah-integrity-scanner), and [Shahid](https://github.com/bismillahbilalarfeenbismillah/FATIMA) exchange structural-honesty findings in a common, append-only format.

## What it does

Every tool in the suite emits **findings** -- structured envelopes that record what was checked, what was found, and where. HABL defines:

- **The Finding envelope** -- a validated dataclass with source_tool, severity, category, location, summary, and correlation/provenance fields (`Location` is frozen; `Finding` is not)
- **The append-only ledger** -- `.habl/findings.jsonl`, one JSON object per line, append-only by contract. Appends are locked (POSIX `flock`) so concurrent writers do not interleave
- **Correlation and provenance** -- `correlation_id` groups related findings across tools; `parent_id` chains cause-and-effect
- **Query helpers** -- read by source, by correlation, or walk the full provenance chain. A walk that meets a cycle or a duplicated `finding_id` raises a typed `LedgerIntegrityError` instead of looping or silently picking one

## HABL in the EESS Prototype

The HABL journal is the core data structure of the [EESS non-authorizing prototype](https://github.com/bismillahbilalarfeenbismillah/eess-prototype), where it implements a full decision lifecycle with **14 typed event APIs** (J0 through J12):

- **J0** -- Decision reservation with canonical payload (cycle-aware, depth-bounded, node-counted, byte-budgeted canonicalization)
- **J1/J2** -- Atomic dispatch claim (eligibility + epoch CAS + capability binding under one lock)
- **J3-J6** -- Effect confirmation, rejection, unknown outcome, human review
- **J7-J9** -- Lease expiration, authorization revocation/expiry
- **J10-J12** -- Close-without-send, reconciliation evidence, evidence conflict

The prototype has been hardened through **21 independent adversarial audit rounds** (P5 through P21) with GPT-6 as independent reviewer, discovering and closing **18 defect families** (DF-01 through DF-18) across Python's full trust-boundary attack surface. Current state: **330 tests, 56 invariants, all passing**.

### Evidence Receipt and Normative Verifier

Built on the HABL journal, the EESS includes:
- **Evidence Receipt v0.2** -- a structured claim envelope with five evidence lanes (SRC/CODE/MEAS/PLAN/HYP), independence provenance, and typed revision history
- **Normative Verifier v0.2** -- 21 checks (NV-01 through NV-21) with three-level outcome (CONFORMANT/ASSURED/AUTHORIZED) and fail-closed execution gate

## The Entourage Effect Software Safety Suite

HABL is one of six instruments that work together like cannabinoids in a landrace sativa:

| Instrument | Role | Analogy |
|------------|------|---------|
| **Furqan** | Programming language | THC -- primary cannabinoid |
| **FATIMA** | Encoder/sealer | CBD -- balancing cannabinoid |
| **furqan-lint** | Structural linter | Myrcene -- dominant terpene |
| **Bayyinah** | Anomaly detector | Limonene -- secondary terpene |
| **HABL** | Finding protocol + journal | Cannaflavin A -- the mycorrhizae |
| **Shahid** | Weight-holder transparency | Beta-caryophyllene -- the accountability terpene |

No single tool is the safety story. The entourage effect is.

## Install

```bash
pip install -e .
```

Requires Python 3.10+.

## Usage

```python
from habl import Finding, Severity, Category, Location
from habl import append_finding, read_ledger, new_correlation_id

# Create a finding
finding = Finding(
    source_tool="furqan-lint",
    severity=Severity.HIGH,
    category=Category.STRUCTURAL,
    summary="Function declares int return but path at line 42 returns None",
    location=Location(file="app.py", line=42, function="process")
)

# Append to the ledger (project_root is the directory that holds .habl/)
append_finding(finding, ".")

# Query
for f in read_ledger("."):
    print(f.summary)
```

## Command line

```bash
habl stats                                   # counts + ledger health
habl query --min-severity high               # filter findings
habl query --source fatima --format jsonl    # machine-readable
habl correlate                               # groups by declared correlation_id
habl correlate --infer-location              # + cross-tool file/line overlap
```

All commands take `--root DIR` (default `.`) and `--strict`.

- **Nothing is silently dropped.** Malformed ledger lines are listed on stderr with line numbers. `--strict` turns them into exit code 1. Usage errors exit 2.
- **Declared and inferred links stay distinct.** A shared `correlation_id` is a link a tool *declared*. Location overlap is a link `correlate` *inferred*, and it is labelled that way.
- **A group is not a verdict.** Correlation marks findings for joint inspection. Each finding remains attributable to the tool that emitted it.
- **Output is deterministic** for a given ledger and arguments.

`python -m habl ...` works as well.

## Known limits in v0.1.1

These are deliberate, documented behaviours:

- **Missing parents give partial chains.** `read_provenance_chain` returns the chain up to a missing parent and stops. `habl stats` lists every such reference under `health.dangling_parents`.
- **Duplicate `finding_id`s are detected, not refused.** Caught when a provenance walk reaches one (`DuplicateFindingIdError`), listed by `habl stats` under `health.duplicate_ids`.
- **Unknown fields are rejected.** A ledger line with a field this version does not know is reported as malformed.
- **Locking is POSIX-only and cooperative.** `flock` keeps HABL writers from interleaving on Linux and macOS.
- **Bytes are stable, not canonical.** Keys are sorted and output is compact strict JSON, but full canonical form (RFC 8785 JCS) is planned for v0.2.

## Planned for v0.2

1. Canonical serialization (RFC 8785 JCS) as input to a hash chain
2. Stronger writer coordination: crash recovery and a Windows implementation
3. Forward compatibility for unknown fields with schema-version rules
4. Duplicate prevention at append time
5. Whether a missing parent should fail closed in provenance-sensitive uses

## Schema version

Current: `0.1.0` (package `0.1.1`; v0.1.1 adds read-side tooling, no schema change)

## Author

**Bilal Syed Arfeen**

## License

MIT

# Bismillah ir-Rahman ir-Rahim
