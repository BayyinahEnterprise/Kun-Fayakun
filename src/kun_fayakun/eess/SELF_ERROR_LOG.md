# Bismillah ir-Rahman ir-Rahim
# EESS Self-Error Pattern Log -- v0.3.24

## Purpose

Track recurrent defect families across audit rounds to detect structural patterns
and close them at their root cause rather than instance by instance.

## Defect Families

### DF-01: Integrity-Guard-Per-API

- **First seen:** P5
- **Recurred:** P6, P7, P8
- **Closed:** P9 (invariant-by-interface matrix adopted)
- **Pattern:** Each audit round discovered one more public API missing an integrity check. The root cause was that integrity verification was opt-in per method rather than structurally required.
- **Structural fix:** Universal integrity guard (`_require_integrity()`) on all 13 typed mutators; status readers return `None`/`True`/`False`/`[]` on corruption.

### DF-02: Input-Validation-Boundary

- **First seen:** P7
- **Recurred:** P8, P9, P10
- **Closed:** P10 (validate-then-mutate established as architectural pattern)
- **Pattern:** Each round found one more input type the mock/engine accepted without validation. Bool epochs (P7), empty effect_id (P8), non-string J11 tx_id (P8), whitespace effect_id (P9), float epoch (P10), empty hash (P10).
- **Structural fix:** All validation checks precede any state mutation. Single-point-of-mutation pattern in `_record_effect()`.

### DF-03: SHA-256-Representation

- **First seen:** P10
- **Recurred:** P11 (J12 call site missed in P10 fix)
- **Closed:** P11 (all call sites now use `_validate_sha256_hex()`)
- **Pattern:** `int(value, 16)` accepted non-hex-64 strings. P10 fixed the validator but missed the J12 `record_evidence_conflict()` call site which still used the old pattern.
- **Structural fix:** `re.fullmatch(r'[0-9a-fA-F]{64}', value)` in `_validate_sha256_hex()`, called from ALL hash-valued field validations including J12. No raw `int(..., 16)` remains in any hash validation path.

### DF-04: Fencing-State-Mutation-Timing

- **First seen:** P10
- **Closed:** P10
- **Pattern:** `_seen_epochs` was advanced during validation, before the request was accepted. A rejected invalid request could "poison" the epoch state and block subsequent valid requests.
- **Structural fix:** Validate-then-mutate -- `_record_effect()` is the single mutation point, called only after all checks pass.

### DF-05: Trust-Boundary-Contracts

- **First seen:** P8
- **Recurred:** P9
- **Status:** OPEN (deferred to production integration)
- **Pattern:** Test-only reconciliation helper does not authenticate target responses. J11 "not-found" can lead to J4b without verified no-effect window. This is an integration trust contract, not a prototype defect.
- **Expected resolution:** Production executor with authenticated evidence provider.

## Convergence Analysis

| Round | Total Findings | Confirmed | Contract | Boundary | New Families | Closed Families |
|-------|---------------|-----------|----------|----------|-------------|-----------------|
| P5    | 22 gaps       | --        | --       | --       | DF-01       | --              |
| P6    | 27 (broader)  | 8         | --       | --       | --          | --              |
| P7    | 12            | 8         | --       | --       | DF-02       | --              |
| P8    | 9             | 2         | 7        | --       | DF-05       | --              |
| P9    | 12            | 2         | 9        | 1        | --          | DF-01           |
| P10   | 12            | 3 families| --       | --       | DF-03, DF-04| DF-02, DF-03, DF-04 |
| P11   | 4             | 4         | --       | --       | DF-06, DF-07| DF-03 (re-closed), DF-06, DF-07 |
| P11-R3/P12 | 4 (converged) | 4      | --       | --       | DF-09, DF-10| DF-09, DF-10 |
| P11-R4/P13 | 4 (converged) | 4      | --       | --       | DF-11       | DF-11         |
| P14        | 3 (converged) | 3      | --       | --       | DF-12       | DF-12         |
| P15        | 2 (converged) | 2      | --       | --       | --          | DF-12 (extended) |
| P16        | 5             | 5      | --       | --       | --          | DF-12 (journal-complete) |
| P17        | 4             | 4      | --       | --       | DF-13       | DF-12 (canonical), DF-13 |
| P18        | 3             | 3      | --       | --       | DF-14       | DF-12 (engine), DF-14    |
| P19        | 3             | 3      | --       | --       | DF-15, DF-16 | DF-15, DF-16           |
| P20        | 3             | 3      | --       | --       | DF-17       | DF-15 (reopened), DF-16 (extended), DF-17 |
| P21        | 3             | 3      | --       | --       | DF-18       | DF-15 (re-closed), DF-16 (re-closed), DF-17 (completed), DF-18 |

### DF-06: Fail-Open-on-Journal-Error

- **First seen:** P11
- **Closed:** P11
- **Pattern:** Dispatch engine swallowed J3 integrity failure (`except ValueError: pass`) and continued to call the target. The general pattern: exception handling that silences a safety-relevant error and continues to the side-effect.
- **Structural fix:** J3 failure is a no-send halt. Any exception from `record_attempt_observed()` returns BLOCKED without calling the target. Post-J3 revocation re-check added before `target.call()`.

### DF-07: Contract-Claims-Exceed-Implementation

- **First seen:** P11
- **Closed:** P11
- **Pattern:** Contract C07 and invariant I-2 claimed "prev_hash linking" (cryptographic hash chain) but the implementation used independent per-event hashes with no predecessor linkage.
- **Structural fix:** Added `prev_hash` field to `HABLEvent`. `compute_hash()` includes `prev_hash` in hash input. `verify_head()` and `_verify_integrity_under_lock()` check chain linkage. Contract C07 now accurately describes the implementation.

## Trajectory

Defect severity continues the convergent trend. P11 found 4 findings (all confirmed, all same-round closable). Two new defect families emerged:
- DF-06 (fail-open on error) is a cousin of DF-01 (integrity-guard-per-API) -- both involve a missing safety check at a boundary. DF-06 is at the exception-handling level rather than the API validation level.
- DF-07 (contract exceeds implementation) is a NEW family -- the first time the contract documentation overstated what the code actually does. Previous defects were missing code; this is correct code described with a stronger claim than it deserved.

The remaining open item is DF-05 (trust-boundary contracts) which requires production integration.

### DF-09: Vacuous-Truth-in-Diagnostic

- **First seen:** P11-R3/P12 (converged across both seats)
- **Closed:** P11-R3/P12
- **Pattern:** BSSG diagnostic reported TRUE from absence of counter-evidence rather than presence of supporting evidence. `effect_type_valid` was TRUE when `attempt_count == 0` (no J2 to validate), `target_allowed` was TRUE when J0 exists (no policy engine), `evidence_current` was TRUE when no J8/J9 exists (no freshness proof).
- **Structural fix:** `effect_type_valid` is UNKNOWN when no J2 exists. `target_allowed` is always UNKNOWN (no policy engine in prototype). Comments clarify the semantics of `evidence_current` and `witness_healthy`.
- **Related:** DF-07 (contract-claims-exceed-implementation) -- both involve over-claiming what the code actually verifies.

### DF-10: Claim-Scope-Exceeds-Mechanism

- **First seen:** P11-R3/P12 (converged across both seats)
- **Closed:** P11-R3/P12
- **Pattern:** I-6 (NC-P2 monotone authority) claimed "removing any event must never upgrade SafetyState" but the hash chain mechanism only detects inconsistent corruption (mid-chain tampering). Consistent suffix truncation (removing the last event with consistent internal bookkeeping) is undetectable by the local hash chain because no retained event's prev_hash references the removed event.
- **Structural fix:** I-6 narrowed to "detectable-corruption monotonicity" -- hash chain inconsistency must cause QUARANTINED. Suffix truncation documented as KNOWN LIMITATION requiring external monotonic anchor. AWARENESS tests document the limitation rather than claiming it doesn't exist.
- **Related:** DF-07 (contract-claims-exceed-implementation) -- both involve claiming a property stronger than what the mechanism provides. DF-10 is architecturally significant: it identifies the fundamental boundary of local hash chain integrity.

## Trajectory (continued)

P11-R3/P12 found 4 converged findings across two independent seats (continuous + fresh). Two new defect families:
- DF-09 (vacuous truth in diagnostic) is a cousin of DF-07 (contract exceeds implementation) -- the diagnostic reports TRUE without the evidence its name implies.
- DF-10 (claim scope exceeds mechanism) is the deepest family yet -- it identifies the architectural boundary of local hash chains vs. external anchoring. This cannot be fixed locally; it requires a production decision about external witnesses.

The fresh seat (P12) found J10/J12 tail-loss variants that the continuous seat (P11-R3) did not, confirming the value of the seat change. The continuous seat found J0 action-semantics (P11-R3-F03) that the fresh seat did not.

### DF-11: Enforcement-at-Wrong-Boundary

- **First seen:** P11-R4/P13 (converged across both seats)
- **Closed:** P11-R4/P13
- **Pattern:** C-32 action vocabulary freeze was enforced only at `DispatchEngine.commit_decision()` -- a convenience method. The authoritative boundary is `HABLJournal.reserve_effect_and_commit_decision()`, which is a public API. A caller bypassing the engine could create a J0 with action="DENY" and dispatch it.
- **Structural fix:** `ALLOWED_ACTIONS` defined as shared constant in the event store (importable by reducer and engine). Enforced at the journal ingestion boundary. Defense-in-depth check added at dispatch boundary. BSSG `contract_match` checks J0 action validity.
- **Related:** DF-10 (claim-scope-exceeds-mechanism) -- both involve a gap between what is claimed and what the mechanism actually covers. DF-11 is the API-boundary variant: enforcement at a high-level wrapper while the low-level API remains open.

P11-R4/P13 found 4 converged findings. One new defect family: DF-11 (enforcement at wrong boundary) is a variant of the DF-10 pattern -- the mechanism was present but placed at the wrong level of abstraction. The two-seat convergence continues to be productive: both seats found the same bypass independently.

### DF-12: Subclass-Permissive-Type-Guard

- **First seen:** P14 (converged across both seats)
- **Closed:** P14
- **Pattern:** Action validation used `isinstance(action, str)` which admits `str` subclasses. A subclass can override `__eq__` and `__hash__` to spoof set membership while serializing as a different value. `SemanticSpoof("DENY")` compared equal to `"SEND"` for `in ALLOWED_ACTIONS` but serialized as `"DENY"` under `json.dumps`.
- **Structural fix:** All action validation now uses `type(action) is str` (exact built-in type) before checking `action in ALLOWED_ACTIONS`. This rejects subclasses at the lowest boundary. The reducer's `dispatchable` predicate also includes `action_valid`.
- **Related:** DF-11 (enforcement at wrong boundary) -- both involve a gap between the checked predicate and the actual safety property. DF-12 is the type-system variant: the membership test was correct but the type guard admitted adversarial equality semantics.

P14 found 3 findings (1 HIGH, 1 MEDIUM, 1 LOW/ADVISORY). One new defect family: DF-12 (subclass-permissive type guard) is the deepest Python-specific finding yet -- it identifies that `isinstance` is not sufficient for security-critical set membership when the input can be an adversarial subclass.

P15 found 2 findings (both converged), no new defect family. P15-F01 (capability spoofing) and P15-F02 (response outcome spoofing) are the same DF-12 pattern applied to different fields. v0.3.17 fixed DF-12 for the action field only; v0.3.18 extended to engine/dispatch/reducer boundaries.

P16 found 5 findings (3 HIGH, 2 MEDIUM), no new defect family. P16-F01 through F05 demonstrated that v0.3.18's DF-12 closure covered high-level entry points but not all 14 journal mutators. The same `str` subclass bypass worked at `atomic_dispatch_claim` (target), `record_effect_confirmed` (request_hash), `record_no_effect` (request_hash), `record_reconciliation_evidence` (request_hash), `release_lease` (worker_id), and `reserve_effect_and_commit_decision` (payload business_effect_id). v0.3.19 systematically adds `_require_exact_str()` or `type(x) is str` to ALL string parameters of ALL 14 public journal mutators BEFORE any comparison or state mutation. DF-12 is now closed at every journal boundary. All 11 P16 probes pass.

### DF-13: Deepcopy-Hook-Injection

- **First seen:** P17
- **Closed:** P17
- **Pattern:** `copy.deepcopy(payload)` invoked `__deepcopy__` on dict subclasses. A dict subclass could present valid values during `isinstance`/`.get` validation, then its `__deepcopy__` hook yields entirely different values (different action, target, effect). The journal accepted and hashed the mutated payload, while effect reservation remained keyed to the original. `verify_head()` returned True -- the corruption was hashed in, not detected.
- **Structural fix:** `_canonicalize_payload()` replaces `copy.deepcopy`. Builds a plain `dict` from scratch by iterating `.items()`. Rejects non-exact-dict payloads (`type(payload) is not dict`). Rejects non-exact-str keys. Coerces str/int subclass values to plain built-in types. Called BEFORE validation in `reserve_effect_and_commit_decision()` and INSTEAD of `copy.deepcopy` in `_build_event()`. No copy hooks are ever invoked.
- **Related:** DF-12 (subclass-permissive type guard) -- both exploit Python's subclass semantics. DF-12 exploits `isinstance` checks; DF-13 exploits `copy.deepcopy` protocol hooks. DF-13 is architecturally deeper: even with perfect `type() is str` guards on individual fields, a dict subclass container can mutate BETWEEN validation and storage via `__deepcopy__`.

P17 found 4 findings (3 HIGH, 1 MEDIUM). One new defect family: DF-13 (deepcopy hook injection) is the deepest Python protocol exploit yet -- it identifies that `copy.deepcopy` is a dangerous operation on untrusted input because it invokes arbitrary code via `__deepcopy__` and `__copy__` hooks. P17-F02/F03/F04 are residual DF-12 on optional parameters and boundary methods that v0.3.19's systematic closure missed.

### DF-14: Polymorphic-Virtual-Method-Bypass

- **First seen:** P18
- **Closed:** P18
- **Pattern:** `dispatch()` used `isinstance(target_contract, TargetContract)` which admits subclasses. A `TargetContract` subclass overriding `supports_automated_dispatch()` could return `True` for fencing-only capability, bypassing the automated dispatch safety gate. Similarly, `isinstance(value, (int, float))` in retention validation admitted numeric subclasses with overridden `__float__`, `__le__`, `__lt__`. And the list branch of `_canonicalize_payload()` was only one level deep, leaving nested subclass hooks alive.
- **Structural fix:** (1) `type(target_contract) is TargetContract` -- exact type, no subclasses. Contract properties copied to canonical local built-in values. Capability policy evaluated with trusted code, not a virtual method. (2) `type(retention) in (int, float)` with explicit bool rejection. Values coerced to plain built-in before validation. (3) `_canonicalize_value()` recursive helper handles arbitrary nesting depth for all container and primitive types.
- **Related:** DF-12 (subclass-permissive type guard) and DF-13 (deepcopy hook injection). DF-14 extends the pattern to virtual method dispatch: even with `type() is str` on string fields, a *class* instance whose methods are overridden provides a different attack surface. Also extends DF-13 to list-nested values that escaped shallow canonicalization.

P18 found 3 findings (2 HIGH, 1 MEDIUM). One new defect family: DF-14 (polymorphic virtual method bypass) completes the Python subclass attack surface: DF-12 covered `isinstance` on values, DF-13 covered `copy.deepcopy` hooks, and DF-14 covers virtual method dispatch on objects and shallow container canonicalization.

### DF-15: TOCTOU-Mutable-Dependency-Drift

- **First seen:** P19
- **Closed:** P19
- **Pattern:** `dispatch()` snapshotted `contract_capability` early but continued re-reading `target_contract.target_id` and `target_contract.capability` at 18+ later call sites. A `MockTarget` subclass with a `dedup_retention` property getter that mutated both the contract and adapter capability could flip capability from DEDUP_ENFORCED to FENCING_ENFORCED between the authorization check and J2 recording. The target was called once; J2 recorded a capability the engine never authorized. No contract subclass needed -- the attack used an exact `TargetContract` with mutable attributes.
- **Structural fix:** ALL contract properties snapshotted once into canonical locals. `target_contract` is never re-read after the snapshot block -- every reference replaced with the local. Adapter identity fields snapshotted BEFORE `dedup_retention` access (the mutation trigger). Post-retention TOCTOU detection added: adapter fields re-verified after `dedup_retention` access.
- **Related:** DF-14 (polymorphic virtual method bypass). DF-15 is deeper -- even without subclassing, mutable shared dependencies between adapter and contract create a TOCTOU window. The fix is architectural: single-read-then-use-locals, same pattern as DF-13's canonicalize-then-store.

### DF-16: Lock-Reentrant-Subclass-Hook-Execution

- **First seen:** P19
- **Closed:** P19
- **Pattern:** `_canonicalize_value()` called `int(v)` on int subclasses under the journal `_lock`. Python dispatched the subclass's `__int__()` method, which could re-enter public journal APIs (e.g., `verify_head()`). Those APIs attempted to acquire the same non-reentrant `threading.Lock()`, causing permanent deadlock. Also applies to `str(v)`, `float(v)`, `bool(v)`, and list-subclass iteration. A single hostile nested metadata value could permanently hold the journal's synchronization lock.
- **Structural fix:** `_canonicalize_value()` now rejects ALL non-exact-built-in-type values immediately. No conversion hooks (`int()`, `str()`, `float()`, `bool()`) are ever called on untrusted input. Only exact `type(v) in (str, int, float, bool, None, list, dict)` pass through. Subclass coercion is eliminated entirely -- the attack surface does not exist.
- **Related:** DF-13 (deepcopy hook injection) and DF-14 (virtual method bypass). DF-16 completes the Python dunder attack surface: DF-12 covered `isinstance`, DF-13 covered `__deepcopy__`, DF-14 covered virtual methods, DF-15 covered mutable dependency TOCTOU, and DF-16 covered conversion hooks under lock.

P19 found 3 findings (1 HIGH, 2 MEDIUM). Two new defect families: DF-15 (TOCTOU mutable dependency drift) and DF-16 (lock-reentrant subclass hook execution). These are architecturally distinct from DF-12 through DF-14 -- they exploit mutable shared state and lock semantics rather than type identity.

### DF-15 reopened: P19 TOCTOU recheck was itself the attack surface

- **Reopened:** P20
- **Closed:** P20 (three-read stability gate + MockTarget _authorized_capability)
- **Pattern:** P19 added a post-dedup_retention TOCTOU recheck that read adapter capability a second time. `FlipOnSecondCapabilityRead` returns the approved value on read #2 while internally mutating. The recheck passes, J2 commits. The P19 closure overstated completeness -- re-reading untrusted getters cannot close a TOCTOU race when getters can lie.
- **Structural fix:** Three-read stability gate BEFORE J2 commit: two consecutive reads must both match the contract. Moved before `atomic_dispatch_claim`. MockTarget.call() uses `_authorized_capability` from the engine's request dict, never reads its own mutable `self.capability` during dispatch.

### DF-16 extended: Error-message formatting under lock

- **Extended:** P20
- **Pattern:** `_canonicalize_payload()` rejected non-str keys with `f"for key '{k}'"` -- `k.__format__()` is attacker code that re-enters the journal lock. Same pattern as DF-16 (dunder hooks under lock) but via the diagnostic PATH, not the validation path.
- **Structural fix:** Rejected keys are never formatted, repr'd, or str'd. Only `type(k).__name__` appears in the error message.

### DF-17: Unbounded-Recursive-Canonicalization

- **First seen:** P20
- **Closed:** P20
- **Pattern:** `_canonicalize_payload()` and `_canonicalize_value()` recursed into nested containers with no cycle detection or depth limit. A self-referential `list` (`loop = []; loop.append(loop)`) hit Python's stack limit, raising `RecursionError` instead of a typed `ValueError`. The lock is released during stack unwinding but the error is uncaught.
- **Structural fix:** `_MAX_CANONICALIZE_DEPTH = 32` caps nesting. `_seen` set tracks `id()` for cycle detection. Both cyclic and depth-exceeded inputs raise `ValueError` promptly.

P20 found 3 findings (1 HIGH, 2 MEDIUM). One new defect family (DF-17, recursive canonicalization). P20-F01 reopened DF-15 -- demonstrating that the P19 TOCTOU recheck was itself a new mutation point. P20-F02 extended DF-16 to diagnostic formatting paths under lock.

### DF-15 re-closed: Backing-store inspection bypasses lying getters

- **Re-closed:** P21
- **Pattern:** P20's three-read stability gate was itself vulnerable -- a getter that lies on ALL reads (returns approved value while mutating internally) evades any number of getter reads. P21-F01 demonstrated `FlipOnThirdCapabilityRead` passing the three-read check.
- **Structural fix:** After the property reads, `vars(target)` is inspected directly -- bypassing all property getters and metaclass intercepts. If any backing attribute (`_capability`, `capability`, `_init_capability`) disagrees with the contract, BLOCK before J2. Additionally, `_authorized_capability` removed from request dict and MockTarget enforces its own `_init_capability`, never accepting overrides.

### DF-16 re-closed: Constant-only diagnostics (metaclass-safe)

- **Re-closed:** P21
- **Pattern:** P20 fixed `f"for key '{k}'"` but ALL `type(x).__name__` references remained. A metaclass overriding `__getattribute__` intercepts `.__name__` access, enabling the same lock re-entry via `verify_head()`. P21-F02 demonstrated this on `_validate_string_id` (decision_id path).
- **Structural fix:** ALL 29 `type(x).__name__` references replaced with constant strings. No attribute is accessed on rejected objects in any lock-bearing path.

### DF-17 completed: Aggregate resource bounds

- **Completed:** P21
- **Pattern:** P20 fixed cycle detection and depth limits but left no aggregate bounds. Shared DAGs (16 source containers → 65,535+ cloned nodes) and 1 MiB primitives consumed unbounded CPU/memory under lock.
- **Structural fix:** `_MAX_CANONICALIZE_NODES = 10,000`, `_MAX_PRIMITIVE_BYTES = 65,536`, `_MAX_PAYLOAD_BYTES = 1,048,576`. Node counter tracks EXPANDED nodes (not unique inputs), catching DAG alias explosion.

### DF-18: Caller-Controlled-Capability-Override

- **First seen:** P21
- **Closed:** P21
- **Pattern:** `MockTarget.call()` trusted `request.get("_authorized_capability")` over its own configured capability. A caller could inject `_authorized_capability=DEDUP_ENFORCED` into the request dict, causing a fencing-only target to execute with dedup semantics (epoch=0 accepted, no fencing enforcement).
- **Structural fix:** `_authorized_capability` removed from request dict. `MockTarget.call()` uses `_init_capability` (frozen at construction time). No request field can override target-side enforcement.

P21 found 3 findings (1 HIGH, 2 MEDIUM). One new defect family: DF-18 (caller-controlled capability override). P21-F01 demonstrated that the P20 three-read stability gate was fundamentally flawed (DF-15 reopened) and that the P20 _authorized_capability fix introduced DF-18. P21-F02 completed DF-16 closure by removing all `type(x).__name__` accesses. P21-F03 completed DF-17 by adding aggregate resource bounds.

## Trajectory (final -- updated P21)

The P14-P17 arc demonstrates a consistent pattern: each round discovers the same fundamental defect (subclass-permissive type system) at a deeper level of abstraction.

- P14: `isinstance` on action field (DF-12)
- P15: `isinstance` on capability/outcome fields (DF-12 extended)
- P16: `isinstance` on journal mutator parameters (DF-12 journal-complete)
- P17: `copy.deepcopy` on container objects (DF-13 -- new family)

The structural lesson: in Python, ANY operation that invokes dunders on untrusted objects is a potential injection vector. `isinstance`, `==`, `hash()`, `in`, `copy.deepcopy`, `str()`, and virtual method calls -- each delegates to attacker code when the input is a subclass or overridden object.

P18 extended the attack surface to virtual method dispatch, numeric type spoofing, and shallow container canonicalization.

P19 revealed two entirely new attack dimensions:
- Mutable shared state: adapter property getters that mutate the contract between validation and send (DF-15 -- not a subclass issue at all)
- Lock semantics: conversion hooks (`__int__`, `__str__`) invoked under a non-reentrant lock (DF-16 -- deadlock, not data corruption)

The P14-P20 arc catalogues seven distinct Python attack surfaces for safety-critical code: DF-12 (isinstance), DF-13 (deepcopy hooks), DF-14 (virtual methods), DF-15 (mutable dependency TOCTOU -- reopened P20 when the P19 fix itself became the attack surface), DF-16 (lock-reentrant hooks -- extended P20 to diagnostic formatting), DF-17 (unbounded recursive canonicalization). P19-F02 (integer overflow in math.isnan) is a standard defensive-coding issue rather than a new defect family.

P20-F01's lesson: a TOCTOU fix that re-reads untrusted state is itself a new mutation point. P21-F01's deeper lesson: NO number of getter reads can establish trust when the getter lies. The correct pattern is backing-store inspection (vars(target)) that bypasses the getter protocol entirely, combined with target-side enforcement where the mock uses its frozen construction-time capability and never accepts overrides from the request.

P21-F02's lesson: `type(x).__name__` is NOT a safe operation on untrusted types -- metaclass `__getattribute__` intercepts it. The ONLY safe diagnostic under lock is a constant string.

P14-P21 arc: eight defect families (DF-12 through DF-18) cataloguing Python's full trust-boundary attack surface for safety-critical code under lock.

# Bismillah ir-Rahman ir-Rahim

### DF-08: Negative-Predicate-Authorization-Check

- **First seen:** P11-R2
- **Closed:** P11-R2
- **Pattern:** Post-J3 authorization gate checked `== "REVOKED"` (negative predicate, missing EXPIRED and other non-VALID states) instead of `!= "VALID"` (positive predicate). The pre-J3 guard at line 555 used the correct positive predicate; the post-J3 guard at line 620 did not match it.
- **Structural fix:** Both gates now use `!= "VALID"` (positive authorization predicate). Post-J3 gate also checks `safety == QUARANTINED` for integrity failures injected between the pre-J3 verify and the post-J3 reduce.
- **Related:** DF-06 (fail-open on journal error) -- both are incomplete error-path handling at the dispatch boundary.

