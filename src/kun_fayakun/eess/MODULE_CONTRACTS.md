# Bismillah ir-Rahman ir-Rahim

# EESS Prototype v0.3.24 -- Module Contracts Declaration

**al-Fatiha Principle:** Declaration BEFORE code.

**Date:** 7 November 2026
**Prior version:** v0.3.23 (330/330 tests, 58 frozen contracts, 53 invariants)
**Source:** GPT-6 P21 audit

---

## 1. What v0.3.24 Corrects

### P21-F01: Getter reads cannot establish capability trust at any depth

**Audit source:** P21-F01 (HIGH)
**Root cause:** The P20 three-read stability gate read adapter capability via
property getters. A lying getter can return the approved value on reads 1--N
while mutating its backing storage. Additionally, MockTarget.call() trusted
_authorized_capability from the request dict, allowing a caller to downgrade
fencing to dedup.

**What changes:**
- Three-read stability gate retained but supplemented with BACKING STORE
  inspection: after the property reads, vars(target) is scanned for _capability,
  capability, and _init_capability -- if any backing attribute disagrees with
  the contract, BLOCK before J2
- This bypasses lying getters by reading the object's __dict__ directly
- _authorized_capability REMOVED from the request dict entirely
- MockTarget.call() uses _init_capability (frozen at construction), never
  accepts capability overrides from the request
- _record_effect() receives _cap from call(), not from request or self.capability
- C-42 updated: falsification is now about re-reading contract properties after
  snapshot, not about number of adapter reads
- C-45 updated: backing-store drift detection, not getter-count stability

### P21-F02: Metaclass __getattribute__ traps type(x).__name__ under lock

**Audit source:** P21-F02 (MEDIUM)
**Root cause:** All diagnostic paths used type(x).__name__ on rejected values.
A metaclass overriding __getattribute__ intercepts the __name__ access and can
re-enter the journal lock via verify_head(), deadlocking the writer.

**What changes:**
- ALL type(x).__name__ references removed from HABL Event Store (29 occurrences)
- All error messages in lock-bearing paths use CONSTANT strings only
- No attribute access on rejected objects (no __format__, __repr__, __str__,
  __name__, or any metaclass-interceptable hook)
- Covers all 14 public journal mutators, query filters, and canonicalization

### P21-F03: Aggregate resource bounds for canonicalization

**Audit source:** P21-F03 (MEDIUM)
**Root cause:** Shared DAGs (16 source containers expanding to 65,535+ cloned
nodes) and oversized primitives (1 MiB strings) were accepted without limits,
consuming CPU/memory while the journal lock was held.

**What changes:**
- _MAX_CANONICALIZE_NODES = 10,000 -- max expanded container + leaf nodes
- _MAX_PRIMITIVE_BYTES = 65,536 -- max bytes for a single str/int value
- _MAX_PAYLOAD_BYTES = 1,048,576 -- max total serialized payload (1 MiB)
- Node counter tracks expanded nodes (not unique input objects), so DAG
  aliases are counted at their true expansion cost
- All limits raise ValueError with constant messages, no append, unchanged head

### Advisory: C-42/C-45 contradiction resolved

- C-42 updated: falsification is re-reading contract properties from the live
  object after the snapshot block, not number of adapter reads
- C-45 updated: backing-store drift detection, not getter-count stability
- DF-15 and DF-16 closure statements corrected in self-error log

---

## 2. Acceptance Criteria

1. All 330 existing tests pass
2. 21/21 normative assertions pass
3. P16: 11/11, P17: 11/11, P18: 9/9, P19: 7/7, P20: 6/6
4. P20-extended metaclass tests: 2/2 pass
5. P21 security rejection tests: 5/5 pass (F01 third-getter, F01 override,
   F02 metaclass __name__, cycle control, depth control)
6. P21 observation tests: now REJECTED by limits (shared DAG exceeds
   node count, 1 MiB string exceeds primitive size) -- converted from
   demonstrating missing limits to verifying limits work
7. Posture check returns 0
8. 56 invariants (53 + C-48, C-49, C-50; C-42 and C-45 updated)

---

# Bismillah ir-Rahman ir-Rahim
