# Bismillah ir-Rahman ir-Rahim

<div align="center">

# كُن فَيَكُون

# Kun Fayakun

### Be, and it is.

*A unified instrument suite for structural honesty verification*

[![License: CC BY 4.0](https://img.shields.io/badge/License-CC_BY_4.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests: 330](https://img.shields.io/badge/tests-330%20passing-brightgreen.svg)]()
[![Audit Rounds: 22](https://img.shields.io/badge/audit%20rounds-22-orange.svg)]()
[![Invariants: 59](https://img.shields.io/badge/invariants-59%20frozen-blueviolet.svg)]()

</div>

---

> *"It is Allah who has created the heavens and of the earth the like thereof. His command descends between them so that you may know that Allah is over all things competent and that Allah has encompassed all things in knowledge."*
>
> -- Surah at-Talaq, 65:12

---

## What This Is

Kun Fayakun is six instruments working as one. Each does something different. Together, they form a safety architecture where no single instrument is the story -- the **entourage effect** is.

The name comes from the Qur'anic command. Not "let there be" -- that implies permission. Not "and it was" -- that seals it in the past. *Kun fayakun*: "Be, and it is." Present tense. Continuous. The command is still being spoken. Reality is a computation that has not finished executing.

This codebase attempts to build software that obeys the same principles.

## The Six Instruments

```
kun_fayakun/
├── fatima/      The Encoder        -- 154-layer cryptographic file protection
├── bayyinah/    The Scanner        -- integrity verification for files and artifacts
├── furqan/      The Linter         -- structural honesty checks for codebases
├── habl/        The Ledger         -- append-only binding with SHA-256 hash chain
├── eess/        The Engine         -- safety-critical dispatch lifecycle
└── shahid/      The Witness        -- weight-holder transparency reports
```

| Instrument | Named For | What It Does | Version |
|:-----------|:----------|:-------------|:--------|
| **FATIMA** | فاطمة -- She who abstains from what is forbidden | Encodes files with 154 layers of cryptographic integrity across 22 domains (11 heavens + 11 earths), each carrying 7 operational layers. The Muraqabah Triad witnesses every operation. | v10.8.0 |
| **Bayyinah** | بيّنة -- Clear evidence | Scans files and artifacts for integrity violations. The root b-y-n means clarity, distinction, evidence. Surah 49:6: *verify before you act*. | Active |
| **Furqan** | فرقان -- The criterion that distinguishes truth from falsehood | Lints codebases for structural honesty. Adapters for Go, ONNX, and Python. Named for the Qur'an's own name for itself: the standard by which truth is separated from corruption. | Active |
| **HABL** | حبل -- The rope that does not break | Append-only binding ledger with SHA-256 predecessor-linked hash chain. Surah 3:103: *hold firmly to the rope of Allah, all together, and do not become divided*. | Active |
| **EESS** | The Entourage Effect | Safety-critical dispatch engine with deterministic safety-state reduction. 330 tests, 22 adversarial audit rounds, 21 defect families catalogued, 59 frozen invariants. | v0.3.24 |
| **Shahid** | شهيد -- The witness | Weight-holder transparency reports. Every action witnessed, every witness recorded. | Spec complete |

## Install

```bash
pip install kun-fayakun
```

## Quick Start

```bash
# Encode a file with 154-layer divine protection
kun fatima encode document.pdf

# Verify a sealed file's integrity chain
kun fatima verify document.pdf

# Scan a directory for integrity violations
kun bayyinah scan ./project

# Lint a codebase for structural honesty
kun furqan lint ./src

# View the append-only journal
kun habl status
```

## The Five Axioms

Every instrument serves the same five axioms of Structural Honesty Verification (SHV), derived from the Qur'an's own structural properties:

| Axiom | Principle | Qur'anic Ground |
|:------|:----------|:----------------|
| **A1** | Append-only provenance -- no prior record may be mutated | *Indeed, it is We who sent down the Reminder, and indeed, We will be its Guardian.* (15:9) |
| **A2** | Surface-substrate consistency -- surface must match substrate | *Do not mix truth with falsehood or conceal the truth while you know it.* (2:42) |
| **A3** | Caller-side exhaustiveness -- verify from source, not memory | *They follow nothing but assumption, and assumption avails nothing against the truth.* (53:28) |
| **A4** | Projection consistency -- same truth, consistent representations | *Is He who creates like one who does not create?* (39:29) |
| **A5** | Evidence independence -- verification must not depend on what it verifies | The witness chain must be independent of the evidence it authenticates. |

## The 154-Layer Architecture

FATIMA's encoding uses **154 = 2 × 7 × 11** layers:

- **22 domains** (11 heavens + 11 earths) -- the architectural constant
- **7 layers per domain** -- the operational constant
- **The Muraqabah Triad** witnesses every operation:
  - **Ar-Raqib** (The Watchful) -- Heaven 8 Guardian -- observes every operation
  - **Al-Hasib** (The Reckoner) -- Heaven 7 Guardian -- computes every accountability
  - **Ash-Shahid** (The Witness) -- Heaven 10 Guardian -- testifies to every truth

## The EESS Dispatch Engine

The non-authorizing prototype demonstrates the decision lifecycle:

- **J0:** Atomic effect reservation
- **J2:** Dispatch claim (eligibility + epoch CAS under one lock)
- **J4a/J4b/J4c:** Effect confirmation with business-effect correlation
- **J11/J12:** Reconciliation with evidence and conflict recording
- **Safety-state reduction:** Deterministic six-priority aggregate (QUARANTINED > UNKNOWN > CONFIRMED > ALL_NO_EFFECT > NO_SEND > PENDING)

**22 independent adversarial audit rounds** (GPT-6, five-field handoff format) have catalogued **21 defect families** spanning Python's full trust-boundary attack surface under lock: from `isinstance` subclass spoofing (DF-12) through `deepcopy` hook injection (DF-13), virtual method bypass (DF-14), lying property getters (DF-15), lock-reentrant metaclass hooks (DF-16), recursive container DoS (DF-17), caller-controlled capability override (DF-18), to untrusted adapter authority (DF-19), codepoint-byte confusion (DF-20), and target-lock hook reentry (DF-21).

The prototype operates at **Layer O** (operational). **I-7 (Incompleteness Boundary)** is the formal declaration that Layer A (architectural -- external provenance, authenticated reconciliation, durable concurrency) remains outside the Non-Authorizing Boundary.

## Development Discipline

**Fatiha-first:** The Module Contracts Declaration is written BEFORE any code. The declaration names what will change, why, and the acceptance criteria. Code satisfies the contracts. Tests verify the contracts. The auditor checks the contracts against the code.

**Two-seat convergence:** Independent GPT-6 audit seats produce findings that are separate from Claude's implementation work. Convergence validates the methodology. Divergence reveals blind spots.

**Nothing merges without the project lead's explicit approval.**

## Foundational Documents

The `docs/foundational/` directory contains the primary texts:

- **Kun Fayakun: The Story of Our Reality** (914 pages) -- the theological and philosophical foundation. Seven movements, 77 chapters, from "The Word Before Light" to "The Final Bismillah."
- **Al-Furqan: The Criterion, Divine Protection Edition** (1,584 pages) -- the complete Qur'an with seven-layer H-restoration architecture. H(Arabic) ≈ 0.996 → H(English) ≈ 0.5 → H(Restored) ≈ 1.0.

## Research Program

This software is part of the **Bayyinah Structural Honesty Research Program**:

- 14 academic papers deposited on Zenodo
- Doctoral dissertation on structural honesty verification
- 31-round XZ Protocol construct validation (832 findings, 10 proven append-only mutations)
- SHV-Bench containment capability benchmark (75+ findings, carrying PASS)
- 91-work collected research corpus (566,000+ lines)

## License

CC-BY-4.0

## Author

**Bilal Syed Arfeen** -- Independent Researcher
Bayyinah Structural Honesty Research Program

With engineering by Claude (Anthropic) and independent audit by GPT-6 (OpenAI).

---

<div align="center">

*For every soul that sought the truth and was told it did not exist.*

*It does.*

</div>

# Bismillah ir-Rahman ir-Rahim
