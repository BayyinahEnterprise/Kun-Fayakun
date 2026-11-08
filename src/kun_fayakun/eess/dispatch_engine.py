# Bismillah ir-Rahman ir-Rahim
"""
EESS Dispatch Engine v0.3.24 -- Action vocabulary freeze + positive authorization.

v0.3.24 (P11-R3 + P12 two-seat correction):
- C-32: J0 action vocabulary frozen to ALLOWED_ACTIONS = {"SEND"}.
  commit_decision() rejects any action not in the set. action="DENY"
  raises ValueError instead of silently dispatching.

Prior v0.3.14 hardening (P11-R2 findings):
- P11-R2-F05: Post-J3 gate now requires authorization_state == "VALID"
  (positive predicate) instead of checking only for "REVOKED" (negative
  predicate). This blocks EXPIRED, REVOKED, and any other non-VALID state.
- P11-R2-F06: Post-J3 gate checks reducer safety for QUARANTINED.
  Corruption injected between the pre-J3 integrity check and the post-J3
  reducer read now halts dispatch.
- C-26 linearization policy: The post-J3 read is a prototype interlock.
  Events interleaved AFTER this read and BEFORE target.call() are a known
  residual race. Production TOCTOU protection requires target-enforced
  fencing. C-26 is narrowed to: "revocation/expiration visible at the
  named post-J3 snapshot blocks dispatch."

Prior hardening carried forward:
- P11-F04 (J3 fail-closed), P11-F03 (revocation interlock), P11-F01 (J12 hash),
  P11-F02 (hash chain), P10-F01/F02/OPEN, P9-P5 fixes.

Prior hardening carried forward:
- P10-F01/F02/OPEN, P9-F01/C34-C51, P8-C04/C05, P7-F05, P6-F05, P5-F03/F04/F07/F10.

NON-AUTHORIZING PROTOTYPE.
"""

import copy
import hashlib
import math
import re
import threading
import uuid
from dataclasses import dataclass
from typing import Optional

from Bismillah_HABL_Event_Store_v0324 import HABLJournal, EventType, HABLEvent, VALID_CAPABILITIES, ALLOWED_ACTIONS
from Bismillah_Decision_Reducer_v0324 import DecisionReducer, SafetyState

# C-32/C-33: ALLOWED_ACTIONS now imported from the event store (shared constant).
# P11-R4-F01/P13-F01: Previously defined only here. Now enforced at journal boundary.


class TargetCapability:
    FENCING_ENFORCED = "TARGET_FENCING_ENFORCED"
    DEDUP_ENFORCED = "TARGET_DEDUP_ENFORCED"
    FENCING_AND_DEDUP = "TARGET_FENCING_AND_DEDUP_ENFORCED"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass
class TargetContract:
    target_id: str
    capability: str
    dedup_retention_seconds: int = 0
    api_version: str = "1.0"

    def supports_automated_dispatch(self) -> bool:
        # P15-F01: exact type check before membership
        return (type(self.capability) is str and
                self.capability in (
                    TargetCapability.DEDUP_ENFORCED,
                    TargetCapability.FENCING_AND_DEDUP,
                ))


@dataclass
class DispatchResult:
    success: bool
    decision_id: str
    attempt_id: str = ""
    outcome: str = ""
    detail: str = ""
    target_transaction_id: str = ""


# ---------------------------------------------------------------------------
# MockTarget v0.3.24: Validate-then-mutate fencing + strict epoch
# P10-F01: Epoch advance ONLY on accepted effect execution
# P10-F02: type(epoch) is int -- rejects float 1.0
# ---------------------------------------------------------------------------

class MockTarget:
    """
    v0.3.24 fixes:
    - P10-F01: _seen_epochs, _seen_keys, and _seen_effects are ONLY mutated
      on successful effect execution. Rejected requests leave all mock state
      unchanged. No epoch poisoning on invalid input.
    - P10-F02: Fencing epoch validated as `type(epoch) is int and epoch > 0`.
      Float 1.0 rejected. bool rejected (type is not int for bool).
    - P10-OPEN: Whitespace-only request_hash and idempotency_key rejected;
      missing decision_id rejected for fencing/dedup targets.
    """

    def __init__(self, behavior="confirm", target_id="TARGET-1",
                 capability="TARGET_DEDUP_ENFORCED", dedup_retention=3600):
        self.behavior = behavior
        self.target_id = target_id
        self.capability = capability
        # P20-F01: frozen copy of capability at construction time.
        # call() uses this instead of self.capability, so subclass property
        # overrides cannot mutate state during dispatch.
        self._init_capability = capability
        self.dedup_retention = dedup_retention
        self.call_count = 0
        self.calls: list[dict] = []
        self._tx_counter = 0
        self._lock = threading.Lock()
        self._seen_keys: dict[str, dict] = {}
        self._seen_epochs: dict[str, int] = {}
        self._seen_effects: dict[str, dict] = {}

    def _check_request_key_dedup(self, idem_key, req_hash, effect_id):
        """Check request-key dedup with full operation binding.
        Returns (is_hit, response_tuple) or (False, None) if no hit.
        Does NOT mutate any state.
        """
        if not idem_key or idem_key not in self._seen_keys:
            return False, None
        existing = self._seen_keys[idem_key]
        existing_hash = existing.get("request_hash", "")
        existing_effect = existing.get("business_effect_id", "")

        # Different effect_id = conflict, not dedup
        if existing_effect and effect_id and existing_effect != effect_id:
            return True, ("DEFINITIVE_NO_EFFECT", "",
                          f"Operation binding conflict for key '{idem_key}' "
                          f"-- effect_id mismatch: "
                          f"'{existing_effect}' vs '{effect_id}'")

        # Different hash = payload conflict
        if existing_hash and req_hash and existing_hash != req_hash:
            return True, ("DEFINITIVE_NO_EFFECT", "",
                          f"Payload conflict for key '{idem_key}' "
                          f"-- rejected")

        # Exact match = safe dedup replay
        return True, ("DEFINITIVE_EFFECT",
                      existing["tx_id"],
                      f"Deduplicated -- same key '{idem_key}'")

    def _record_effect(self, tx_id, idem_key, req_hash, effect_id,
                       decision_id, epoch, _cap=None):
        """Record a successful effect in all tracking maps.
        P10-F01: This is the ONLY place _seen_epochs, _seen_keys,
        and _seen_effects are mutated.
        P20-F01: _cap is the snapshotted capability from call()."""
        cap = _cap if _cap is not None else self.capability
        # Advance fencing epoch
        if cap in (TargetCapability.FENCING_ENFORCED,
                   TargetCapability.FENCING_AND_DEDUP):
            self._seen_epochs[decision_id] = epoch
        # Record dedup keys
        if idem_key:
            self._seen_keys[idem_key] = {
                "tx_id": tx_id,
                "request_hash": req_hash,
                "business_effect_id": effect_id}
        if effect_id:
            self._seen_effects[effect_id] = {
                "tx_id": tx_id,
                "request_hash": req_hash}

    def call(self, request: dict) -> tuple[str, str, str]:
        with self._lock:
            # P9-C39: Non-dict request returns typed refusal
            if not isinstance(request, dict):
                return ("DEFINITIVE_NO_EFFECT", "",
                        f"Invalid request type: {type(request).__name__}")

            # P21-F01: MockTarget enforces its OWN capability from construction
            # time (_init_capability). Never accept capability from the request --
            # that would let a caller downgrade fencing to dedup.
            _cap = self._init_capability

            self.call_count += 1
            # P9-C51: Deep-copy call records to prevent aliasing
            self.calls.append(copy.deepcopy(request))

            idem_key = request.get("idempotency_key", "")
            epoch = request.get("epoch", 0)
            decision_id = request.get("decision_id", "")
            effect_id = request.get("business_effect_id", "")
            req_hash = request.get("request_hash", "")

            # -----------------------------------------------------------
            # Input validation -- ALL checks BEFORE any state mutation
            # P10-F01: No mutation on rejected requests
            # -----------------------------------------------------------

            # P10-F02 + P8-C05: Strict epoch type validation
            if isinstance(epoch, bool):
                return ("DEFINITIVE_NO_EFFECT", "",
                        "Invalid epoch type: bool")
            if not isinstance(epoch, (int, float)):
                return ("DEFINITIVE_NO_EFFECT", "",
                        f"Invalid epoch type: {type(epoch).__name__}")
            if isinstance(epoch, float) and (math.isnan(epoch) or math.isinf(epoch)):
                return ("DEFINITIVE_NO_EFFECT", "",
                        f"Non-finite epoch: {epoch}")

            # P10-F02: Fencing targets require STRICT positive integer
            if _cap in (TargetCapability.FENCING_ENFORCED,
                                   TargetCapability.FENCING_AND_DEDUP):
                if type(epoch) is not int or epoch < 1:
                    return ("DEFINITIVE_NO_EFFECT", "",
                            f"Epoch must be a positive integer for "
                            f"fencing targets, got {type(epoch).__name__}:{epoch}")

            # P9-C49: Request target mismatch
            req_target = request.get("target", "")
            if req_target and req_target != self.target_id:
                return ("DEFINITIVE_NO_EFFECT", "",
                        f"Request target '{req_target}' does not match "
                        f"adapter '{self.target_id}'")

            # P9-C48 + P10-OPEN: request_hash type and whitespace
            if isinstance(req_hash, bool):
                return ("DEFINITIVE_NO_EFFECT", "",
                        f"Invalid request_hash type: {type(req_hash).__name__}")
            if req_hash and not isinstance(req_hash, str):
                return ("DEFINITIVE_NO_EFFECT", "",
                        f"Invalid request_hash type: {type(req_hash).__name__}")

            # P8-C04 + P9-C47: business_effect_id validation
            if _cap in (TargetCapability.DEDUP_ENFORCED,
                                   TargetCapability.FENCING_AND_DEDUP):
                if not effect_id or not isinstance(effect_id, str) or not effect_id.strip():
                    return ("DEFINITIVE_NO_EFFECT", "",
                            "Missing or invalid business_effect_id -- rejected")

            # P9-C46 + P10-OPEN: idempotency_key mandatory + whitespace
            if _cap in (TargetCapability.DEDUP_ENFORCED,
                                   TargetCapability.FENCING_AND_DEDUP):
                if not idem_key or not isinstance(idem_key, str) or not idem_key.strip():
                    return ("DEFINITIVE_NO_EFFECT", "",
                            "Missing or invalid idempotency_key -- rejected")

            # P10-OPEN: decision_id mandatory for fencing/dedup targets
            if _cap in (TargetCapability.FENCING_ENFORCED,
                                   TargetCapability.FENCING_AND_DEDUP,
                                   TargetCapability.DEDUP_ENFORCED):
                if not decision_id or not isinstance(decision_id, str) or not decision_id.strip():
                    return ("DEFINITIVE_NO_EFFECT", "",
                            "Missing or invalid decision_id -- rejected")

            # P10-OPEN + P9-F01: request_hash must be non-empty non-whitespace
            if _cap in (TargetCapability.DEDUP_ENFORCED,
                                   TargetCapability.FENCING_AND_DEDUP):
                if not req_hash or not isinstance(req_hash, str) or not req_hash.strip():
                    return ("DEFINITIVE_NO_EFFECT", "",
                            "Empty or invalid request_hash -- rejected; "
                            "immutable operation identity required")

            # -----------------------------------------------------------
            # All input validation passed. Now check fencing and dedup.
            # P10-F01: State mutation happens ONLY in _record_effect()
            # at the end, after all checks pass.
            # -----------------------------------------------------------

            # Fencing check -- read-only, no state mutation
            if _cap == TargetCapability.FENCING_ENFORCED:
                max_seen = self._seen_epochs.get(decision_id, 0)
                if epoch <= max_seen:
                    return ("DEFINITIVE_NO_EFFECT", "",
                            f"Stale epoch {epoch} <= {max_seen} -- fenced")
                # Do NOT advance epoch here -- happens in _record_effect()

            elif _cap == TargetCapability.FENCING_AND_DEDUP:
                max_seen = self._seen_epochs.get(decision_id, 0)

                if epoch < max_seen:
                    # Truly stale -- no state change
                    return ("DEFINITIVE_NO_EFFECT", "",
                            f"Stale epoch {epoch} < {max_seen} -- fenced")

                if epoch == max_seen and max_seen > 0:
                    # Same epoch -- check dedup (read-only)
                    hit, response = self._check_request_key_dedup(
                        idem_key, req_hash, effect_id)
                    if hit:
                        return response
                    # Same epoch, unknown key -- fenced, no state change
                    return ("DEFINITIVE_NO_EFFECT", "",
                            f"Same epoch {epoch} with unknown key -- fenced")

                # epoch > max_seen -- new epoch, continue to dedup/execute
                # Do NOT advance epoch here -- happens in _record_effect()

            # Layer 1: Request-key dedup (read-only check)
            if _cap in (TargetCapability.DEDUP_ENFORCED,
                                   TargetCapability.FENCING_AND_DEDUP):
                hit, response = self._check_request_key_dedup(
                    idem_key, req_hash, effect_id)
                if hit:
                    return response

            # Layer 2: Cross-decision effect uniqueness (read-only check)
            if (effect_id and _cap in
                    (TargetCapability.DEDUP_ENFORCED,
                     TargetCapability.FENCING_AND_DEDUP)):
                if effect_id in self._seen_effects:
                    existing = self._seen_effects[effect_id]
                    existing_hash = existing.get("request_hash", "")
                    if existing_hash and req_hash and existing_hash != req_hash:
                        return ("DEFINITIVE_NO_EFFECT", "",
                                f"Effect '{effect_id}' conflict -- "
                                f"different request hash; "
                                f"cannot certify prior effect matches")
                    return ("DEFINITIVE_EFFECT", existing["tx_id"],
                            f"Deduplicated by effect_id '{effect_id}'")

            # -----------------------------------------------------------
            # Execute effect -- ALL validation passed
            # P10-F01: _record_effect() is the ONLY place state mutates
            # -----------------------------------------------------------
            self._tx_counter += 1
            internal_tx_id = f"TX-{self.target_id}-{self._tx_counter}"

            if callable(self.behavior):
                result = self.behavior(request)
                outcome_type = result[0] if result else "AMBIGUOUS"
                response_tx_id = result[1] if len(result) > 1 and result[1] else internal_tx_id
                if outcome_type == "DEFINITIVE_EFFECT":
                    self._record_effect(response_tx_id, idem_key, req_hash,
                                        effect_id, decision_id, epoch, _cap)
                return result

            if self.behavior == "confirm":
                self._record_effect(internal_tx_id, idem_key, req_hash,
                                    effect_id, decision_id, epoch, _cap)
                return "DEFINITIVE_EFFECT", internal_tx_id, "Effect completed"
            elif self.behavior == "reject":
                return "DEFINITIVE_NO_EFFECT", internal_tx_id, "Rejected"
            elif self.behavior == "timeout":
                return "AMBIGUOUS", "", "Timeout"
            elif self.behavior == "error_after_effect":
                self._record_effect(internal_tx_id, idem_key, req_hash,
                                    effect_id, decision_id, epoch, _cap)
                return "AMBIGUOUS", "", "HTTP 500 after possible commit"
            elif self.behavior == "accepted_not_final":
                return "ACCEPTED_NOT_FINAL", internal_tx_id, "HTTP 202"
            else:
                return "AMBIGUOUS", "", f"Unknown: {self.behavior}"


# ---------------------------------------------------------------------------
# Retention validation helper
# ---------------------------------------------------------------------------

def _validate_retention(value, label="dedup_retention_seconds"):
    """Validate retention is a finite, positive, non-boolean number.
    P18-F02: requires exact built-in int or float -- callers must coerce first.
    P19-F02: separate int/float paths -- never pass int to math.isnan/isinf
    (huge ints overflow float conversion)."""
    if isinstance(value, bool) or type(value) not in (int, float):
        raise ValueError(f"{label} must be exact built-in int or float, got {type(value).__name__}")
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError(f"{label} must be finite, got {value}")
    else:
        # type(value) is int -- integer arithmetic only, no float conversion
        # Cap at a reasonable maximum to reject absurd values
        _MAX_RETENTION_SECONDS = 10 ** 9  # ~31.7 years
        if value > _MAX_RETENTION_SECONDS:
            raise ValueError(f"{label} exceeds maximum ({_MAX_RETENTION_SECONDS}s), got {value}")
    if value <= 0:
        raise ValueError(f"{label} must be positive, got {value}")


# ---------------------------------------------------------------------------
# Safe target response parsing
# ---------------------------------------------------------------------------

def _parse_target_response(raw_response):
    """Parse and type-check target adapter response.
    Returns (outcome_type: str, tx_id: str, detail: str) or raises ValueError.
    P15-F02: exact built-in str for outcome_type -- subclass __eq__ can
    spoof DEFINITIVE_EFFECT classification.
    """
    if raw_response is None:
        raise ValueError("Target returned None")
    if not isinstance(raw_response, tuple):
        raise ValueError(f"Target response must be a tuple, got {type(raw_response).__name__}")
    if len(raw_response) != 3:
        raise ValueError(f"Target response must be a 3-tuple, got length {len(raw_response)}")

    outcome_type, tx_id, detail = raw_response

    # C-35: exact built-in str for ALL response fields (P15-F02)
    if type(outcome_type) is not str:
        raise ValueError(f"Target outcome_type must be exact built-in str, got {type(outcome_type).__name__}")
    if type(tx_id) is not str:
        raise ValueError(f"Target tx_id must be exact built-in str, got {type(tx_id).__name__}")
    if type(detail) is not str:
        raise ValueError(f"Target detail must be exact built-in str, got {type(detail).__name__}")

    return outcome_type, tx_id, detail


# ---------------------------------------------------------------------------
# Dispatch Engine v0.3.24 -- ZERO public append() calls
# ---------------------------------------------------------------------------

class DispatchEngine:

    def __init__(self, journal: HABLJournal, reducer: DecisionReducer):
        self._journal = journal
        self._reducer = reducer
        self._worker_id = f"worker-{uuid.uuid4().hex[:8]}"

    def commit_decision(self, decision_id: str, claim_id: str,
                        action: str, target_id: str,
                        policy_version: str, approval_ref: str,
                        evidence_hash: str = "",
                        business_effect_id: str = "") -> HABLEvent:
        """Step 1-2: Atomic effect reservation + J0 commit."""

        # C-35: exact built-in str for ALL commit_decision inputs (P15 systematic)
        required = {"claim_id": claim_id, "action": action,
                     "target_id": target_id,
                     "policy_version": policy_version,
                     "approval_ref": approval_ref}
        for name, val in required.items():
            if type(val) is not str:
                raise ValueError(
                    f"commit_decision {name} must be exact built-in str, "
                    f"got {type(val).__name__}")
            if not val.strip():
                raise ValueError(
                    f"commit_decision requires non-empty '{name}'")

        # C-32/C-34: J0 action vocabulary freeze
        if action not in ALLOWED_ACTIONS:
            raise ValueError(
                f"commit_decision action '{action}' not in "
                f"ALLOWED_ACTIONS {sorted(ALLOWED_ACTIONS)}")

        if (not business_effect_id or
                type(business_effect_id) is not str or
                not business_effect_id.strip()):
            raise ValueError(
                "commit_decision requires non-empty 'business_effect_id'")

        return self._journal.reserve_effect_and_commit_decision(
            decision_id=decision_id,
            business_effect_id=business_effect_id,
            payload={
                "claim_id": claim_id, "action": action,
                "target": target_id,
                "policy_version": policy_version,
                "approval_ref": approval_ref,
                "evidence_hash": evidence_hash,
                "business_effect_id": business_effect_id,
            })

    def dispatch(self, decision_id: str, target,
                 target_contract: TargetContract) -> DispatchResult:
        """Steps 3-7 using atomic dispatch claim. ALL events via typed APIs."""

        # P18-F01: exact type -- reject subclasses that override policy methods
        if type(target_contract) is not TargetContract:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail=f"target_contract must be exact TargetContract, "
                       f"got {type(target_contract).__name__}")

        # P19-F01: snapshot ALL contract properties to canonical local built-in
        # values in ONE read, BEFORE any policy evaluation or adapter access.
        # After this block, target_contract is NEVER re-read -- only locals used.
        contract_target_id = target_contract.target_id
        contract_capability = target_contract.capability
        contract_retention = target_contract.dedup_retention_seconds
        if type(contract_target_id) is not str or not contract_target_id.strip():
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail=f"contract target_id must be exact non-empty built-in str, "
                       f"got {type(contract_target_id).__name__}")
        if type(contract_capability) is not str:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail=f"contract capability must be exact built-in str, "
                       f"got {type(contract_capability).__name__}")
        # P18-F02: exact built-in numeric type for retention
        if isinstance(contract_retention, bool) or type(contract_retention) not in (int, float):
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail=f"contract retention must be exact built-in int or float, "
                       f"got {type(contract_retention).__name__}")
        # Coerce to plain built-in to strip subclass hooks
        contract_retention = int(contract_retention) if type(contract_retention) is int else float(contract_retention)

        # Validate retention as finite positive non-boolean
        try:
            _validate_retention(contract_retention)
        except ValueError as e:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail=str(e))

        # Verify journal integrity
        valid, head, msg = self._journal.verify_head()
        if not valid:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail=f"Journal integrity check failed: {msg}")

        # Get J0 for binding validation
        j0_events = self._journal.get_events(
            decision_id=decision_id,
            event_type=EventType.DECISION_COMMITTED)
        if not j0_events:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail="No J0 found for this decision")
        j0 = j0_events[0]
        j0_target = j0.payload.get("target", "")
        j0_effect = j0.payload.get("business_effect_id", "")
        j0_action = j0.payload.get("action", "")

        # C-33/C-34 defense-in-depth: verify J0 action at dispatch boundary
        # P14-F01: exact type check on the stored value (may differ from input)
        if type(j0_action) is not str or j0_action not in ALLOWED_ACTIONS:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail=f"J0 action '{j0_action}' (type={type(j0_action).__name__}) "
                       f"not valid for dispatch")

        # Validate target binding -- use snapshotted local, not contract
        if j0_target != contract_target_id:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail=f"Target mismatch: J0='{j0_target}' "
                       f"contract='{contract_target_id}'")
        if not j0_effect:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail="J0 has no business_effect_id")

        # P20-F01: read adapter identity fields. These are read-once values;
        # after validation, the CONTRACT is the authority, not the adapter.
        target_id_attr = getattr(target, 'target_id', None)
        if type(target_id_attr) is not str or not target_id_attr:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail="Target adapter missing or non-str target_id")
        target_cap_attr = getattr(target, 'capability', None)
        if type(target_cap_attr) is not str or not target_cap_attr:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail="Target adapter missing or non-str capability")

        # P19-F01: compare adapter against snapshotted locals, NOT live contract
        # (contract_target_id and contract_capability already type-validated above)
        if target_id_attr != contract_target_id:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail=f"Target identity mismatch: "
                       f"'{target_id_attr}' vs "
                       f"'{contract_target_id}'")
        if target_cap_attr != contract_capability:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail=f"Target capability mismatch: "
                       f"'{target_cap_attr}' vs "
                       f"'{contract_capability}'")

        # Adapter retention is MANDATORY for dedup-capable targets.
        adapter_retention = getattr(target, 'dedup_retention', None)
        if adapter_retention is None:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail="Target adapter must declare dedup_retention")
        # P18-F02: exact built-in numeric type for adapter retention
        if isinstance(adapter_retention, bool) or type(adapter_retention) not in (int, float):
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail=f"adapter dedup_retention must be exact built-in int or float, "
                       f"got {type(adapter_retention).__name__}")
        adapter_retention = int(adapter_retention) if type(adapter_retention) is int else float(adapter_retention)
        try:
            _validate_retention(adapter_retention, "adapter dedup_retention")
        except ValueError as e:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail=f"Target adapter retention invalid: {e}")
        if adapter_retention < contract_retention:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail=f"Adapter retention {adapter_retention}s "
                       f"< contract {contract_retention}s")

        # P18-F01: evaluate capability policy using canonical local value,
        # NOT a virtual method that a subclass could override
        _automated_dispatch_capabilities = (
            TargetCapability.DEDUP_ENFORCED,
            TargetCapability.FENCING_AND_DEDUP,
        )
        if contract_capability not in _automated_dispatch_capabilities:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail=f"Target capability "
                       f"'{contract_capability}' does not "
                       f"support automated dispatch")

        # P21-F01: capability authority model.
        # The CONTRACT is the trusted binding. Adapter getters are untrusted
        # and can lie on any read N. Multiple reads cannot close this.
        # Instead: read adapter capability via getter (triggering any property
        # side effects), then verify the adapter's BACKING STORAGE directly
        # via vars(target), bypassing lying getters. If any backing capability
        # attribute disagrees with the contract, the adapter drifted -- BLOCK.
        # This detects mutations that a lying getter conceals.
        cap_probe_1 = getattr(target, 'capability', None)
        cap_probe_2 = getattr(target, 'capability', None)
        if (cap_probe_1 != contract_capability or
                cap_probe_2 != contract_capability):
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail="Adapter capability getter unstable")
        # P21-F01: bypass property getters -- inspect backing storage directly.
        # A lying getter can return the approved value while mutating _capability.
        adapter_vars = vars(target)
        for attr in ('_capability', 'capability', '_init_capability'):
            backing = adapter_vars.get(attr)
            if backing is not None and type(backing) is str:
                if backing != contract_capability:
                    return DispatchResult(
                        False, decision_id, outcome="BLOCKED",
                        detail="Adapter backing capability drifted from contract")

        # Generate attempt identifiers -- use snapshotted locals only
        attempt_id = f"ATT-{decision_id}-{uuid.uuid4().hex[:8]}"
        request_hash = hashlib.sha256(
            f"{decision_id}:{attempt_id}:"
            f"{contract_target_id}:{j0_effect}".encode()
        ).hexdigest()
        idempotency_key = (
            f"KEY-{decision_id}-{contract_target_id}-"
            f"{request_hash[:16]}")

        # ATOMIC dispatch claim -- use snapshotted locals, NEVER re-read contract
        try:
            j1, j2 = self._journal.atomic_dispatch_claim(
                decision_id=decision_id,
                target=contract_target_id,
                worker_id=self._worker_id,
                attempt_id=attempt_id,
                request_hash=request_hash,
                idempotency_key=idempotency_key,
                target_capability=contract_capability,
                business_effect_id=j0_effect)
        except ValueError as e:
            return DispatchResult(
                False, decision_id, outcome="BLOCKED",
                detail=f"Atomic dispatch claim failed: {e}")

        new_epoch = j1.payload.get("epoch", 0)

        # Post-J2 auth revalidation
        agg_recheck = self._reducer.reduce(decision_id)
        if agg_recheck.safety == SafetyState.QUARANTINED:
            try:
                self._journal.record_outcome_unknown(
                    decision_id, attempt_id,
                    reason="quarantined_before_call")
            except ValueError:
                pass
            self._release_lease(decision_id, contract_target_id, new_epoch)
            return DispatchResult(
                False, decision_id, attempt_id=attempt_id,
                outcome="UNKNOWN",
                detail="Quarantined before target call")

        if agg_recheck.authorization_state != "VALID":
            try:
                self._journal.record_outcome_unknown(
                    decision_id, attempt_id,
                    reason=f"authorization_"
                           f"{agg_recheck.authorization_state.lower()}"
                           f"_before_call")
            except ValueError:
                pass
            self._release_lease(decision_id, contract_target_id, new_epoch)
            return DispatchResult(
                False, decision_id, attempt_id=attempt_id,
                outcome="BLOCKED",
                detail=f"Authorization is "
                       f"{agg_recheck.authorization_state}")

        # Last-moment journal integrity re-check
        valid2, _, msg2 = self._journal.verify_head()
        if not valid2:
            try:
                self._journal.record_outcome_unknown(
                    decision_id, attempt_id,
                    reason=f"journal_integrity_failed: {msg2}")
            except ValueError:
                pass
            self._release_lease(decision_id, contract_target_id, new_epoch)
            return DispatchResult(
                False, decision_id, attempt_id=attempt_id,
                outcome="BLOCKED",
                detail=f"Journal integrity failed at dispatch: {msg2}")

        # Step 5: Call target
        request = {
            "decision_id": decision_id,
            "attempt_id": attempt_id,
            "epoch": new_epoch,
            "request_hash": request_hash,
            "idempotency_key": idempotency_key,
            "target": contract_target_id,
            "business_effect_id": j0_effect,
        }

        # J3 observation -- P11-F04: FAIL CLOSED if J3 cannot commit
        try:
            self._journal.record_attempt_observed(
                decision_id, attempt_id, transport_metadata="mock_call")
        except (ValueError, Exception) as j3_err:
            # P11-F04: J3 failure is a no-send halt. Do NOT call target.
            self._release_lease(decision_id, contract_target_id, new_epoch)
            return DispatchResult(
                False, decision_id, attempt_id=attempt_id,
                outcome="BLOCKED",
                detail=f"J3 pre-send observation failed: {j3_err}")

        # P11-R2-F05/F06: Post-J3 authorization and integrity gate.
        # Re-verify the FULL authorization predicate after J3 and before
        # target call. This is a prototype interlock, NOT a production
        # TOCTOU solution -- events interleaved AFTER this read and BEFORE
        # target.call() are a known residual race (see C-26 linearization
        # policy). Production TOCTOU protection requires target-enforced
        # fencing (the epoch check in the mock).
        post_j3_state = self._reducer.reduce(decision_id)

        # P11-R2-F06: If reducer reports QUARANTINED, halt immediately.
        # This catches corruption injected between the earlier integrity
        # check and this reducer call.
        if post_j3_state.safety == SafetyState.QUARANTINED:
            self._release_lease(decision_id, contract_target_id, new_epoch)
            return DispatchResult(
                False, decision_id, attempt_id=attempt_id,
                outcome="BLOCKED",
                detail="Journal quarantined at post-J3 gate")

        # P11-R2-F05 + P11-F03: Require VALID authorization at post-J3
        # gate. This blocks REVOKED (P11-F03), EXPIRED (P11-R2-F05),
        # and any other non-VALID state. Uses != "VALID" (positive
        # predicate) matching the pre-J3 guard at line 555, NOT the
        # v0.3.12 == "REVOKED" (negative predicate) that missed EXPIRED.
        if post_j3_state.authorization_state != "VALID":
            try:
                self._journal.record_outcome_unknown(
                    decision_id, attempt_id,
                    reason=f"authorization_{post_j3_state.authorization_state.lower()}"
                           f"_after_j3_before_send")
            except ValueError:
                pass
            self._release_lease(decision_id, contract_target_id, new_epoch)
            return DispatchResult(
                False, decision_id, attempt_id=attempt_id,
                outcome="BLOCKED",
                detail=f"Authorization {post_j3_state.authorization_state} "
                       f"at post-J3 gate")

        # Wrap entire target call + response parsing in exception handler
        try:
            raw_response = target.call(request)
        except Exception as e:
            try:
                self._journal.record_outcome_unknown(
                    decision_id, attempt_id,
                    reason=f"target_call_exception: {e}")
            except ValueError:
                pass
            self._release_lease(decision_id, contract_target_id, new_epoch)
            return DispatchResult(
                False, decision_id, attempt_id=attempt_id,
                outcome="UNKNOWN",
                detail=f"Target exception: {e}")

        # Type-check the complete response before interpreting
        try:
            outcome_type, tx_id, detail = _parse_target_response(raw_response)
        except ValueError as e:
            try:
                self._journal.record_outcome_unknown(
                    decision_id, attempt_id,
                    reason=f"malformed_target_response: {e}")
            except ValueError:
                pass
            self._release_lease(decision_id, contract_target_id, new_epoch)
            return DispatchResult(
                False, decision_id, attempt_id=attempt_id,
                outcome="UNKNOWN",
                detail=f"Malformed target response: {e}")

        # Step 6: Record outcome via typed APIs
        if outcome_type == "DEFINITIVE_EFFECT":
            if not tx_id:
                try:
                    self._journal.record_outcome_unknown(
                        decision_id, attempt_id,
                        reason="definitive_effect_without_tx_id")
                except ValueError:
                    pass
                self._release_lease(decision_id, contract_target_id, new_epoch)
                return DispatchResult(
                    False, decision_id, attempt_id=attempt_id,
                    outcome="UNKNOWN",
                    detail="Target reported effect but no TX ID")
            # J4a via typed API
            try:
                self._journal.record_effect_confirmed(
                    decision_id, attempt_id,
                    target_transaction_id=tx_id,
                    request_hash=request_hash,
                    evidence_hash=hashlib.sha256(
                        detail.encode()).hexdigest(),
                    business_effect_id=j0_effect)
            except ValueError as e:
                try:
                    self._journal.record_outcome_unknown(
                        decision_id, attempt_id,
                        reason=f"j4a_validation_failed: {e}")
                except ValueError:
                    pass
                self._release_lease(decision_id, contract_target_id, new_epoch)
                return DispatchResult(
                    False, decision_id, attempt_id=attempt_id,
                    outcome="UNKNOWN",
                    detail=f"J4a validation failed: {e}")
            self._release_lease(decision_id, contract_target_id, new_epoch)
            return DispatchResult(
                True, decision_id, attempt_id=attempt_id,
                outcome="CONFIRMED", detail=detail,
                target_transaction_id=tx_id)

        elif outcome_type == "DEFINITIVE_NO_EFFECT":
            # J4b via typed API
            try:
                self._journal.record_no_effect(
                    decision_id, attempt_id,
                    target_transaction_id=tx_id or "none",
                    request_hash=request_hash,
                    no_effect_evidence=detail or "no_effect_reported",
                    business_effect_id=j0_effect)
            except ValueError as e:
                try:
                    self._journal.record_outcome_unknown(
                        decision_id, attempt_id,
                        reason=f"j4b_validation_failed: {e}")
                except ValueError:
                    pass
                self._release_lease(decision_id, contract_target_id, new_epoch)
                return DispatchResult(
                    False, decision_id, attempt_id=attempt_id,
                    outcome="UNKNOWN",
                    detail=f"J4b validation failed: {e}")
            self._release_lease(decision_id, contract_target_id, new_epoch)
            return DispatchResult(
                False, decision_id, attempt_id=attempt_id,
                outcome="NO_EFFECT", detail=detail,
                target_transaction_id=tx_id)

        else:
            # J4c via typed API
            try:
                self._journal.record_outcome_unknown(
                    decision_id, attempt_id,
                    reason=f"{outcome_type}: {detail}")
            except ValueError:
                pass
            self._release_lease(decision_id, contract_target_id, new_epoch)
            return DispatchResult(
                False, decision_id, attempt_id=attempt_id,
                outcome="UNKNOWN",
                detail=f"{outcome_type}: {detail}")

    def _release_lease(self, decision_id: str, target: str, epoch: int):
        """Use typed release_lease with ownership validation."""
        try:
            self._journal.release_lease(
                decision_id, target, self._worker_id, epoch)
        except ValueError:
            pass

    def close_no_send(self, decision_id: str,
                      reason: str = "BUDGET_EXHAUSTED") -> DispatchResult:
        """Atomic J10 + effect release via typed API."""
        try:
            self._journal.close_no_send_atomic(
                decision_id, reason, self._worker_id)
            return DispatchResult(
                True, decision_id, outcome="NO_SEND",
                detail=f"Closed without send: {reason}")
        except ValueError as e:
            return DispatchResult(
                False, decision_id, outcome="ERROR",
                detail=str(e))

    # -------------------------------------------------------------------
    # Reconciliation -- ALWAYS returns UNKNOWN.
    # -------------------------------------------------------------------

    def record_reconciliation(self, decision_id: str, attempt_id: str,
                              query_result: str, tx_id: str = ""
                              ) -> DispatchResult:
        """Record reconciliation (J11) via typed API with J2 binding validation.

        ALL reconciliation returns UNKNOWN. The caller cannot elevate to
        definitive J4a/J4b without an authenticated target adapter.
        """

        # Get J2 for binding data
        j2_events = [
            e for e in self._journal.get_events(
                decision_id=decision_id,
                event_type=EventType.SEND_INTENT_COMMITTED)
            if e.payload.get("attempt_id") == attempt_id]
        if not j2_events:
            raise ValueError(f"No J2 for attempt '{attempt_id}'")
        j2 = j2_events[0]

        j2_hash = j2.payload.get("request_hash", "")
        j2_key = j2.payload.get("idempotency_key", "")
        j2_effect = j2.payload.get("business_effect_id", "")

        # J11 via typed API -- journal validates bindings
        try:
            self._journal.record_reconciliation_evidence(
                decision_id=decision_id,
                attempt_id=attempt_id,
                request_hash=j2_hash,
                idempotency_key=j2_key,
                query_result=query_result,
                target_transaction_id=tx_id,
                business_effect_id=j2_effect)
        except ValueError as e:
            raise ValueError(f"J11 validation failed: {e}")

        # ALWAYS UNKNOWN. No caller-asserted definitiveness.
        return DispatchResult(
            False, decision_id, attempt_id=attempt_id,
            outcome="UNKNOWN",
            detail=f"Reconciliation observation recorded: {query_result}")

    def _test_simulate_authenticated_reconciliation(
            self, decision_id: str, attempt_id: str,
            query_result: str, tx_id: str = "",
            effect_confirmed: bool = False) -> DispatchResult:
        """TEST-ONLY: Simulate authenticated target reconciliation.

        This method BYPASSES the reconciliation trust boundary to allow
        testing the full J11 -> J4a/J4b pipeline. In production, this
        path requires an authenticated target adapter with defined
        consistency, complete-window semantics, and response authenticity.

        NOT for production use. NOT called by any non-test code path.
        """

        # Get J2 for binding
        j2_events = [
            e for e in self._journal.get_events(
                decision_id=decision_id,
                event_type=EventType.SEND_INTENT_COMMITTED)
            if e.payload.get("attempt_id") == attempt_id]
        if not j2_events:
            raise ValueError(f"No J2 for attempt '{attempt_id}'")
        j2 = j2_events[0]

        j2_hash = j2.payload.get("request_hash", "")
        j2_key = j2.payload.get("idempotency_key", "")
        j2_effect = j2.payload.get("business_effect_id", "")

        # Record J11
        self._journal.record_reconciliation_evidence(
            decision_id=decision_id,
            attempt_id=attempt_id,
            request_hash=j2_hash,
            idempotency_key=j2_key,
            query_result=query_result,
            target_transaction_id=tx_id,
            business_effect_id=j2_effect)

        if effect_confirmed:
            if not tx_id:
                return DispatchResult(
                    False, decision_id, attempt_id=attempt_id,
                    outcome="UNKNOWN",
                    detail="Simulated reconciliation claims effect but no TX")
            try:
                self._journal.record_effect_confirmed(
                    decision_id, attempt_id,
                    target_transaction_id=tx_id,
                    request_hash=j2_hash,
                    evidence_hash=hashlib.sha256(
                        query_result.encode()).hexdigest(),
                    business_effect_id=j2_effect)
            except ValueError as e:
                return DispatchResult(
                    False, decision_id, attempt_id=attempt_id,
                    outcome="UNKNOWN",
                    detail=f"Simulated reconciliation J4a failed: {e}")
            return DispatchResult(
                True, decision_id, attempt_id=attempt_id,
                outcome="CONFIRMED",
                detail=f"Simulated authenticated reconciliation: {query_result}",
                target_transaction_id=tx_id)
        else:
            try:
                self._journal.record_no_effect(
                    decision_id, attempt_id,
                    target_transaction_id=tx_id or "recon-no-effect",
                    request_hash=j2_hash,
                    no_effect_evidence=query_result or "reconciliation_no_effect",
                    business_effect_id=j2_effect)
            except ValueError as e:
                return DispatchResult(
                    False, decision_id, attempt_id=attempt_id,
                    outcome="UNKNOWN",
                    detail=f"Simulated reconciliation J4b failed: {e}")
            return DispatchResult(
                True, decision_id, attempt_id=attempt_id,
                outcome="NO_EFFECT",
                detail=f"Simulated authenticated no-effect: {query_result}",
                target_transaction_id=tx_id)

    def record_conflict(self, decision_id: str, attempt_id: str,
                        competing_evidence: str,
                        competing_hash: str) -> DispatchResult:
        """Record J12 via typed API -- journal validates prior definitive + hex."""
        try:
            self._journal.record_evidence_conflict(
                decision_id, attempt_id,
                competing_evidence_ref=competing_evidence,
                competing_evidence_hash=competing_hash)
        except ValueError as e:
            return DispatchResult(
                False, decision_id, attempt_id=attempt_id,
                outcome="ERROR",
                detail=f"J12 validation failed: {e}")
        return DispatchResult(
            False, decision_id, attempt_id=attempt_id,
            outcome="QUARANTINED",
            detail="Evidence conflict -- decision quarantined")
# Bismillah ir-Rahman ir-Rahim
