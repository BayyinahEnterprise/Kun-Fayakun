# Bismillah ir-Rahman ir-Rahim
"""
EESS Decision Reducer v0.3.24 -- Deterministic six-priority aggregate + BSSG diagnostic.

v0.3.24 (P11-R4 + P13 two-seat correction):
- C-33: contract_match now checks J0 action against ALLOWED_ACTIONS.
  P11-R4-F02/P13-F02: Previously TRUE for any J0 regardless of action.

v0.3.15 (P11-R3 + P12 two-seat correction):
- C-31 CORRECTED: BSSG diagnostic truth conditions narrowed.
  * effect_type_valid: UNKNOWN when no J2 exists (was vacuously TRUE).
  * target_allowed: Always UNKNOWN (no policy engine in prototype).
  * witness_healthy: TRUE when verify_head passes (local chain, not
    independent witness attestation).
  * evidence_current: TRUE when auth_state VALID (no countermanding
    event recorded -- NOT independent freshness verification).
  * contract_match: TRUE when J0 exists with allowed action.

v0.3.14:
- C-31: BSSG five-conjunct read-only diagnostic alongside SafetyState.
  Decomposes the aggregate into ContractMatch, EffectTypeValid,
  TargetAllowed, WitnessHealthy, EvidenceCurrent -- each three-valued
  (TRUE/FALSE/UNKNOWN). Informational only -- does not gate dispatch.

Prior:
- P7-F01: Reducer consumes ONLY verified journal snapshots.

NON-AUTHORIZING PROTOTYPE.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from Bismillah_HABL_Event_Store_v0324 import HABLJournal, EventType, ALLOWED_ACTIONS


class SafetyState(Enum):
    QUARANTINED = 1
    UNKNOWN = 2
    TERMINAL_CONFIRMED = 3
    TERMINAL_NO_EFFECT = 4
    TERMINAL_NO_SEND = 5
    PENDING = 6


class BusinessEffect(Enum):
    CONFIRMED = "CONFIRMED"
    NO_EFFECT = "NO_EFFECT"
    NO_SEND = "NO_SEND"
    UNDETERMINED = "UNDETERMINED"
    QUARANTINED = "QUARANTINED"


class AttemptState(Enum):
    SEND_INTENT = "SEND_INTENT"
    ATTEMPTED = "ATTEMPTED"
    CONFIRMED = "CONFIRMED"
    NO_EFFECT = "NO_EFFECT"
    UNKNOWN = "UNKNOWN"


@dataclass
class AttemptRecord:
    attempt_id: str
    state: AttemptState
    epoch: int = 0
    target_transaction_id: Optional[str] = None
    has_j3: bool = False


@dataclass
class BSGGDiagnostic:
    """BSSG five-conjunct read-only diagnostic (C-31).
    Three-valued: 'TRUE', 'FALSE', or 'UNKNOWN'.
    Informational only -- does not gate dispatch.
    Maps EESS journal state to the BSSG kernel (P058 Section 3.1)."""
    contract_match: str = "UNKNOWN"      # J0 exists with allowed action
    effect_type_valid: str = "UNKNOWN"   # J2 exists with bound effect
    target_allowed: str = "UNKNOWN"      # ALWAYS UNKNOWN: no policy engine
    witness_healthy: str = "UNKNOWN"     # Local chain integrity (not attestation)
    evidence_current: str = "UNKNOWN"    # No countermanding auth event recorded


@dataclass
class DecisionAggregate:
    decision_id: str
    safety: SafetyState
    business_effect: BusinessEffect
    dispatchable: bool
    attempt_count: int
    confirmed_effects: int
    unresolved_attempts: int
    conflicting_observations: int
    has_j10: bool
    authorization_state: str
    lease_epoch: int
    attempts: list[AttemptRecord] = field(default_factory=list)
    detail: str = ""
    bssg_diagnostic: BSGGDiagnostic = field(default_factory=BSGGDiagnostic)


class DecisionReducer:
    """Deterministic six-priority aggregate reducer.
    P7-F01: Consumes only verified journal snapshots."""

    def __init__(self, journal: HABLJournal):
        self._journal = journal

    def reduce(self, decision_id: str) -> DecisionAggregate:
        # P7-F01: Use verified snapshot -- corrupt journal -> QUARANTINED
        result = self._journal.verified_snapshot_or_quarantine(decision_id)
        if result[0] is False:
            # Journal integrity failed -- return QUARANTINED, never dispatchable
            quarantine_bssg = BSGGDiagnostic(witness_healthy="FALSE")
            return DecisionAggregate(
                decision_id=decision_id, safety=SafetyState.QUARANTINED,
                business_effect=BusinessEffect.QUARANTINED, dispatchable=False,
                attempt_count=0, confirmed_effects=0, unresolved_attempts=0,
                conflicting_observations=0, has_j10=False,
                authorization_state="UNKNOWN", lease_epoch=0,
                detail=f"QUARANTINED: journal integrity failed -- {result[2]}",
                bssg_diagnostic=quarantine_bssg)

        _, events, head_offset, head_hash = result

        if not events:
            return DecisionAggregate(
                decision_id=decision_id, safety=SafetyState.PENDING,
                business_effect=BusinessEffect.UNDETERMINED, dispatchable=False,
                attempt_count=0, confirmed_effects=0, unresolved_attempts=0,
                conflicting_observations=0, has_j10=False,
                authorization_state="UNKNOWN", lease_epoch=0,
                detail="No events found for this decision")

        attempts: dict[str, AttemptRecord] = {}
        has_j0 = False
        j0_action = ""  # C-33: track J0 action for BSSG contract_match
        has_j10 = False
        conflict_count = 0
        max_epoch = 0
        auth_state = "UNKNOWN"
        confirmed_tx_ids: set[str] = set()

        for event in events:
            et = event.event_type
            p = event.payload

            if et == EventType.DECISION_COMMITTED:
                has_j0 = True
                j0_action = p.get("action", "")
                if auth_state == "UNKNOWN":
                    auth_state = "VALID"
            elif et == EventType.LEASE_ACQUIRED:
                epoch = p.get("epoch", 0)
                if epoch > max_epoch:
                    max_epoch = epoch
            elif et == EventType.SEND_INTENT_COMMITTED:
                aid = p.get("attempt_id", "")
                epoch = p.get("epoch", 0)
                attempts[aid] = AttemptRecord(
                    attempt_id=aid, state=AttemptState.SEND_INTENT,
                    epoch=epoch)
            elif et == EventType.ATTEMPT_OBSERVED:
                aid = p.get("attempt_id", "")
                if aid in attempts:
                    attempts[aid].has_j3 = True
                    if attempts[aid].state == AttemptState.SEND_INTENT:
                        attempts[aid].state = AttemptState.ATTEMPTED
            elif et == EventType.TARGET_EFFECT_CONFIRMED:
                aid = p.get("attempt_id", "")
                if aid in attempts:
                    attempts[aid].state = AttemptState.CONFIRMED
                    tx_id = p.get("target_transaction_id", "")
                    if tx_id:
                        attempts[aid].target_transaction_id = tx_id
                        confirmed_tx_ids.add(tx_id)
            elif et == EventType.TARGET_NO_EFFECT:
                aid = p.get("attempt_id", "")
                if aid in attempts:
                    attempts[aid].state = AttemptState.NO_EFFECT
            elif et == EventType.OUTCOME_UNKNOWN:
                aid = p.get("attempt_id", "")
                if aid in attempts:
                    if attempts[aid].state not in (
                            AttemptState.CONFIRMED, AttemptState.NO_EFFECT):
                        attempts[aid].state = AttemptState.UNKNOWN
            elif et == EventType.EVIDENCE_CONFLICT:
                conflict_count += 1
            elif et == EventType.DISPATCH_CLOSED_NO_SEND:
                has_j10 = True
            elif et == EventType.AUTHORIZATION_REVOKED:
                auth_state = "REVOKED"
            elif et == EventType.AUTHORIZATION_EXPIRED:
                auth_state = "EXPIRED"

        attempt_list = list(attempts.values())
        attempt_count = len(attempt_list)
        unresolved = sum(
            1 for a in attempt_list
            if a.state in (AttemptState.SEND_INTENT,
                           AttemptState.ATTEMPTED,
                           AttemptState.UNKNOWN))
        confirmed_count = sum(
            1 for a in attempt_list if a.state == AttemptState.CONFIRMED)
        no_effect_count = sum(
            1 for a in attempt_list if a.state == AttemptState.NO_EFFECT)

        # C-31: BSSG five-conjunct diagnostic (v0.3.24 corrected truth conditions)
        bssg = BSGGDiagnostic()
        # C-34: exact built-in str check for action admissibility
        action_valid = (type(j0_action) is str and j0_action in ALLOWED_ACTIONS)
        # ContractMatch: J0 exists with allowed action (P14-F01: exact type)
        if has_j0 and action_valid:
            bssg.contract_match = "TRUE"
        elif has_j0:
            bssg.contract_match = "FALSE"  # J0 exists but action is invalid
        else:
            bssg.contract_match = "FALSE"
        # EffectTypeValid: at least one attempt has progressed past SEND_INTENT
        # P11-R3-F02/P12-F03: UNKNOWN when no J2 (no bound effect to validate)
        has_progressed_attempt = any(
            a.state != AttemptState.SEND_INTENT
            for a in attempt_list) if attempt_list else False
        if not has_j0:
            bssg.effect_type_valid = "UNKNOWN"
        elif attempt_count == 0:
            # No attempts yet -- nothing to validate
            bssg.effect_type_valid = "UNKNOWN"
        elif has_progressed_attempt:
            bssg.effect_type_valid = "TRUE"
        else:
            bssg.effect_type_valid = "UNKNOWN"
        # TargetAllowed: ALWAYS UNKNOWN in prototype (no policy engine)
        # P11-R3-F02/P12-F03: dispatch engine checks target-contract binding,
        # but the reducer has no policy authority to declare TRUE.
        bssg.target_allowed = "UNKNOWN"
        # WitnessHealthy: local chain integrity verified via verified_snapshot
        # This is NOT independent witness attestation -- it is self-hash consistency.
        bssg.witness_healthy = "TRUE"
        # EvidenceCurrent: no countermanding authorization event recorded
        # P12-F03: this reflects absence of J8/J9, NOT independently verified
        # evidence freshness. Renamed semantics for honesty.
        if auth_state == "EXPIRED":
            bssg.evidence_current = "FALSE"
        elif auth_state == "REVOKED":
            bssg.evidence_current = "FALSE"
        elif auth_state == "VALID":
            bssg.evidence_current = "TRUE"
        else:
            bssg.evidence_current = "UNKNOWN"

        def _agg(safety, biz, disp, detail):
            return DecisionAggregate(
                decision_id=decision_id, safety=safety,
                business_effect=biz, dispatchable=disp,
                attempt_count=attempt_count,
                confirmed_effects=len(confirmed_tx_ids),
                unresolved_attempts=unresolved,
                conflicting_observations=conflict_count,
                has_j10=has_j10, authorization_state=auth_state,
                lease_epoch=max_epoch, attempts=attempt_list,
                detail=detail, bssg_diagnostic=bssg)

        # Priority 1: QUARANTINED
        if conflict_count > 0:
            return _agg(SafetyState.QUARANTINED,
                        BusinessEffect.QUARANTINED, False,
                        f"QUARANTINED: {conflict_count} J12 conflict(s)")
        if len(confirmed_tx_ids) > 1:
            return _agg(SafetyState.QUARANTINED,
                        BusinessEffect.QUARANTINED, False,
                        f"QUARANTINED: {len(confirmed_tx_ids)} distinct "
                        f"target transactions -- cardinality violation")

        # Priority 2: UNKNOWN
        if unresolved > 0:
            return _agg(SafetyState.UNKNOWN,
                        BusinessEffect.UNDETERMINED, False,
                        f"UNKNOWN: {unresolved} attempt(s) lack "
                        f"definitive resolution")

        # Priority 3: CONFIRMED
        if confirmed_count > 0 and unresolved == 0:
            return _agg(SafetyState.TERMINAL_CONFIRMED,
                        BusinessEffect.CONFIRMED, False,
                        f"CONFIRMED: {confirmed_count} attempt(s) "
                        f"confirmed effect")

        # Priority 4: ALL NO EFFECT (non-vacuous)
        if attempt_count > 0 and no_effect_count == attempt_count:
            return _agg(SafetyState.TERMINAL_NO_EFFECT,
                        BusinessEffect.NO_EFFECT, False,
                        f"NO_EFFECT: all {attempt_count} attempt(s) "
                        f"definitively no-effect")

        # Priority 5: NO SEND
        if has_j10 and attempt_count == 0:
            return _agg(SafetyState.TERMINAL_NO_SEND,
                        BusinessEffect.NO_SEND, False,
                        "NO_SEND: J10 terminal closure")

        # Priority 6: PENDING
        # P14-F02: dispatchable requires valid action (consistent with contract_match)
        dispatchable = (has_j0 and action_valid and auth_state == "VALID"
                        and attempt_count == 0)
        return _agg(SafetyState.PENDING,
                     BusinessEffect.UNDETERMINED, dispatchable,
                     "PENDING: eligible for dispatch"
                     if dispatchable else "PENDING: not yet dispatchable")
# Bismillah ir-Rahman ir-Rahim
