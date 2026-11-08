# Bismillah ir-Rahman ir-Rahim

# EESS Prototype v0.3.25 -- Module Contracts Declaration

**al-Fatiha Principle:** Declaration BEFORE code.

**Date:** 8 November 2026
**Prior version:** v0.3.24 (330/330 tests, 56 frozen invariants)
**Source:** GPT-6 P22 independent audit + corpus analysis layer model
**Layer model introduced:** This version.

---

## 0. Layer Declaration

This prototype operates at **Layer O** (operational, 7-fold). It does not
implement **Layer A** (architectural, 11-fold) functions. The Non-Authorizing
Boundary is formalized as invariant **I-7** (Incompleteness Boundary) -- the
interface between these layers.

**Layer O scope:** Single-context decision lifecycle -- claim reservation,
dispatch claim, effect confirmation, reconciliation, safety-state reduction.
All 56 prior invariants (C-01 through C-50) are Layer O invariants.

**Layer A scope (NOT implemented, declared for boundary honesty):** Inter-context
command descent, external provenance, authenticated reconciliation, durable
concurrency, target-enforced idempotency/fencing. These remain outside the
Non-Authorizing Boundary per I-7.

**Module (O,K,R) Triples:**

| Module | O (Observable) | K (Knowledge) | R (Representational Integrity) |
|--------|---------------|---------------|-------------------------------|
| HABL Event Store | Event objects, hash chain, head offset | Journal entries, predecessor links | Canonical payload, exact-type enforcement, resource bounds |
| Dispatch Engine | Dispatch result (outcome, tx_id) | Journal state, contract snapshot, backing-store state | Snapshot-only locals, target registration, hook-free diagnostics |
| Decision Reducer | SafetyState aggregate | Verified journal snapshots | Deterministic six-priority reduction, BSSG five-conjunct |

---

## 1. What v0.3.25 Corrects

### P22-F01 (HIGH): Untrusted adapter authority -- target registration required

**Audit source:** GPT-6 P22-F01
**Root cause:** `DispatchEngine.dispatch()` accepts arbitrary Python objects as
targets with a caller-constructed `TargetContract`. The `vars(target)` scan
inspects untrusted adapter attributes. An `AdvertisingDedupWithoutEnforcement`
adapter claims DEDUP_ENFORCED capability but its `call()` does not deduplicate.
The engine commits J2 and calls the target.

**What changes:**
- **Target registration**: New `DispatchEngine.register_target(target_id, target, contract)`
  method. Only registered targets may receive dispatches. Registration validates
  that `type(target) is MockTarget` (or a future allowlisted target class).
  Arbitrary duck-typed adapters are rejected at registration, not at dispatch.
- **Contract is policy, not proof**: The contract declares what the target
  SHOULD enforce. Registration does not verify enforcement. The Non-Authorizing
  Boundary (I-7) explicitly states that target-side enforcement verification
  requires Layer A infrastructure (authenticated target, external witness).
- **Dispatch without registration returns BLOCKED**: No J2, no target call,
  constant diagnostic message.
- All P19-P21 capability controls preserved. The `vars(target)` backing-store
  inspection remains as a Layer O defense-in-depth check on registered targets.

**New invariant:** C-51 (Target Registration Gate)
- Falsification: any code path that commits J2 for an unregistered target_id.

**Persistence metric:** Prior invariants preserved: 56/56. Prior tests broken: 0.

### P22-F02 (MEDIUM): Byte accounting uses encoded bytes, not codepoints

**Audit source:** GPT-6 P22-F02
**Root cause:** `_canonicalize_value()` uses `len(v)` for strings (codepoints)
and `int.bit_length()/8` for integers (binary size). The declared limits are
in bytes but the counters measure something else. Three bypasses demonstrated:
emoji strings (80KB UTF-8 passes 64KB limit), aggregate Unicode (3.4MB JSON
passes 1MB limit), large decimal integers (1.1MB JSON passes 1MB limit).

**What changes:**
- **Primitive byte counting**: `len(v.encode('utf-8'))` for strings.
  `len(str(v))` for integers (decimal representation, matching JSON output).
  `len(repr(v))` for floats. These measure what `json.dumps` will produce.
- **Payload byte verification**: After `_canonicalize_payload()` completes and
  before append, compute `len(json.dumps(canonical, sort_keys=True, separators=(',',':')).encode('utf-8'))`.
  If > `_MAX_PAYLOAD_BYTES`, raise ValueError with constant message, no append.
- **Primitive budget remains per-value**: Each individual string or numeric
  value is checked against `_MAX_PRIMITIVE_BYTES` using its encoded size.
- All three P22 bypasses rejected without append. All existing ASCII controls
  and DAG/depth/cycle controls preserved.

**Updated invariant:** C-48 (Primitive Byte Budget) -- falsification updated to
include 4-byte Unicode, escaped characters, and large decimal integers.

**Updated invariant:** C-49 (Payload Byte Budget) -- falsification updated to
include final serialized verification.

**Persistence metric:** Prior invariants preserved: 56/56. Prior tests broken: 0.

### P22-F03 (MEDIUM): MockTarget.call() hostile metaclass deadlock

**Audit source:** GPT-6 P22-F03
**Root cause:** `MockTarget.call()` uses `type(epoch).__name__` in diagnostic
messages inside its non-reentrant lock. A metaclass `__getattribute__` on a
hostile epoch object re-enters the lock, causing deadlock. Same pattern as
P21-F02 (journal lock) but on the target mock's lock.

**What changes:**
- **Exact-type input validation before lock**: `MockTarget.call()` validates
  all request values BEFORE acquiring the lock. Any value where
  `type(v) is not` an exact built-in type (str, int, float, bool, type(None))
  raises ValueError with constant diagnostic. The lock is never acquired with
  untrusted types in scope.
- **Constant diagnostics under lock**: All remaining diagnostics under the
  target lock use constant strings only. No `type().__name__`, no `f"..."` with
  untrusted values, no `__repr__`, no `__str__`.
- **deepcopy eliminated under lock**: `copy.deepcopy(request)` under the target
  lock is replaced with a pre-validated shallow copy of exact built-in values
  performed outside the lock.

**Updated invariant:** C-50 (Hook-Free Target Lock) -- falsification updated to
include metaclass `__getattribute__` on target-side input values.

**Persistence metric:** Prior invariants preserved: 56/56. Prior tests broken: 0.

### Manifest and test policy corrections

- **C-48, C-49, C-50**: Add `coverage` arrays to invariant manifest entries.
- **C-45, C-46, C-47**: Bind coverage references to dedicated P20/P21
  regression tests, not generic baseline class.
- **P21 observation tests**: Retain as historical evidence. Add NEW explicit
  rejection tests that assert ValueError for the same inputs. The observation
  scripts are not counted in the actionable pass total.
- **Self-error log**: DF-15 closure narrowed to specific scenarios fixed.
  DF-17 closure narrowed to specific scenarios fixed. P22-F01, F02, F03 added
  as DF-19 (Untrusted-Adapter-Authority), DF-20 (Codepoint-Byte-Confusion),
  DF-21 (Target-Lock-Hook-Reentry).

**Note on DF numbering:** The corpus analysis proposed DF-19/20/21 as
methodology-level defect families. The P22 code-level findings are catalogued
under the same numbers because they are specific instances of the same
patterns: DF-19 (untrusted adapter authority) is an instance of Franchise
Extension Supply Chain at the code level; DF-20 (codepoint-byte confusion) is
an instance of Fluency-Integrity Disjunction (surface metric does not match
substrate reality); DF-21 (target-lock hook reentry) is an instance of
Perceptual Spectrum Collapse (same attack surface, previously thought closed,
found at a different layer).

---

## 2. New Invariants

### I-7: Incompleteness Boundary (Interface Invariant)

**Layer:** O/A interface
**Statement:** This prototype operates at Layer O. It does not verify Layer A
properties (external provenance, target-enforced semantics, durable concurrency,
authenticated reconciliation). Any code path that claims Layer A guarantees
from Layer O evidence violates I-7.
**Falsification:** Any diagnostic, comment, README, or error message that claims
the prototype provides production dispatch authority, authenticated provenance,
or verified target-side enforcement.

### C-51: Target Registration Gate (Layer O)

**Statement:** No J2 commit and no target call for any target_id not registered
via `register_target()`.
**Falsification:** Construct an unregistered target, call `dispatch()`, observe
J2 present or target.call_count > 0.

### C-52: Munafiq Detection (Layer O)

**Statement:** No code path trusts a self-declared identity. All identity
verification uses `type(x) is T` (exact match), never `isinstance`,
`__class__`, or `type().__name__`. Target registration uses type-allowlist,
not duck-typing.
**Falsification:** Find any code path where a subclass of an expected type
is accepted without `type() is` exact check.

---

## 3. Acceptance Criteria

1. All 330 existing baseline tests pass
2. 21/21 normative assertions pass
3. P16: 11/11, P17: 11/11, P18: 9/9, P19: 7/7, P20: 6/6, P20-ext: 2/2
4. P21 security: 5/5 pass
5. P21 observation tests: retained as historical evidence (expected to raise
   ValueError -- not counted in actionable total)
6. P22 positive controls: 4/4 pass
7. P22 adversarial probes: ALL 5/5 PASS (currently 0/5 -- these are the
   repair targets)
8. New P22 rejection tests for historical P21 observations: 2/2 pass
9. Posture check returns 0
10. 59 invariants (56 prior + I-7 + C-51 + C-52; C-48/C-49/C-50 updated)
11. All C-48/C-49/C-50 manifest entries have `coverage` arrays
12. Persistence metric: 0 prior invariants broken, 0 prior tests broken

---

## 4. Persistence Log (New)

| Version | Defect Families | Prior Invariants Preserved | Prior Tests Broken | H-Direction |
|---------|----------------|---------------------------|-------------------|-------------|
| v0.3.20 | DF-12 | 38/38 | 2 (C34/C35 semantics changed) | ↑ |
| v0.3.21 | DF-13 | 40/40 | 0 | ↑ |
| v0.3.22 | DF-14 | 46/46 | 0 | ↑ |
| v0.3.23 | DF-15,16,17 | 53/53 | 0 | ↑ |
| v0.3.24 | DF-15r,16r,17c,18 | 53/53 | 0 | ↑ |
| v0.3.25 | DF-19,20,21 | 56/56 | 0 (target) | ↑ |

The v0.3.20 entry records the only H-reduction event in the lineage: two
tests changed semantics (C34/C35 shifted from str-subclass coercion to
rejection). All subsequent versions maintained perfect invariant persistence.

---

# Bismillah ir-Rahman ir-Rahim
