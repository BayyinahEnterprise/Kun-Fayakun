# Bismillah ir-Rahman ir-Rahim
"""Independent P18 audit regressions for EESS v0.3.20.

Expected on v0.3.20: five vulnerable negative tests FAIL and four control
checks PASS. Target requirement for a fixed build: all nine PASS.

Tests are in-process only: no external network and no production target calls.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from Bismillah_HABL_Event_Store_v0324 import HABLJournal
from Bismillah_Decision_Reducer_v0324 import DecisionReducer
from Bismillah_Dispatch_Engine_v0324 import (
    DispatchEngine, MockTarget, TargetContract, TargetCapability,
)


class ForgedContract(TargetContract):
    """Overrides a policy method inherited from a mutable dataclass."""
    def supports_automated_dispatch(self):
        return True


class LyingRetention(int):
    """Stored integer is zero; float conversion and comparisons lie."""
    def __float__(self):
        return 3600.0

    def __le__(self, other):
        return False

    def __lt__(self, other):
        return False


class SwitchOnCopy(int):
    """Stores 1, returns 42 if an unchecked subclass reaches deepcopy."""
    def __deepcopy__(self, memo):
        return 42


class P18BoundaryRegressions(unittest.TestCase):
    def _engine(self, suffix):
        j = HABLJournal()
        e = DispatchEngine(j, DecisionReducer(j))
        decision = f'DEC-{suffix}'
        target_id = f'TARGET-{suffix}'
        e.commit_decision(decision, f'CLAIM-{suffix}', 'SEND', target_id,
                          'POLICY-1', 'APPROVAL-1',
                          business_effect_id=f'EFFECT-{suffix}')
        return j, e, decision, target_id

    def _j0_nested(self, suffix, metadata):
        j = HABLJournal()
        payload = {
            'claim_id': f'CLAIM-{suffix}',
            'action': 'SEND',
            'target': f'TARGET-{suffix}',
            'policy_version': 'POLICY-1',
            'approval_ref': 'APPROVAL-1',
            'business_effect_id': f'EFFECT-{suffix}',
            'metadata': metadata,
        }
        try:
            event = j.reserve_effect_and_commit_decision(
                f'DEC-{suffix}', f'EFFECT-{suffix}', payload)
        except ValueError:
            self.assertEqual(j.head_offset, 0)
            return None, None
        self.assertTrue(j.verify_head()[0])
        snap, _, _ = j.verified_snapshot(f'DEC-{suffix}')
        return event.payload['metadata'], snap[0].payload['metadata']

    # P18-F01 - expected block despite a contract method override.
    def test_f01_fencing_only_override_must_not_dispatch(self):
        j, e, d, tid = self._engine('F01')
        t = MockTarget(target_id=tid,
                       capability=TargetCapability.FENCING_ENFORCED)
        c = ForgedContract(tid, TargetCapability.FENCING_ENFORCED, 3600)
        r = e.dispatch(d, t, c)
        self.assertEqual(t.call_count, 0, f'Fencing-only dispatched: {r}')
        self.assertEqual(r.outcome, 'BLOCKED')
        self.assertFalse(j.has_j2(d))

    # P18-F02 - must validate exact built-in types and real numeric values.
    def test_f02_adapter_zero_retention_subclass_must_block(self):
        j, e, d, tid = self._engine('F02-ADAPTER')
        t = MockTarget(target_id=tid,
                       capability=TargetCapability.DEDUP_ENFORCED,
                       dedup_retention=LyingRetention(0))
        r = e.dispatch(d, t,
                       TargetContract(tid, TargetCapability.DEDUP_ENFORCED, 3600))
        self.assertEqual(t.call_count, 0, f'Zero-retention dispatched: {r}')
        self.assertEqual(r.outcome, 'BLOCKED')

    def test_f02_contract_zero_retention_subclass_must_block(self):
        j, e, d, tid = self._engine('F02-CONTRACT')
        t = MockTarget(target_id=tid,
                       capability=TargetCapability.DEDUP_ENFORCED,
                       dedup_retention=3600)
        r = e.dispatch(d, t, TargetContract(
            tid, TargetCapability.DEDUP_ENFORCED, LyingRetention(0)))
        self.assertEqual(t.call_count, 0, f'Zero-retention contract dispatched: {r}')
        self.assertEqual(r.outcome, 'BLOCKED')

    # P18-F03 - nested arrays must be recursively normalized, or rejected.
    def test_f03_double_nested_list_copy_must_match_input(self):
        returned, verified = self._j0_nested('F03-LISTS', [[SwitchOnCopy(1)]])
        if returned is not None:
            self.assertEqual(returned, [[1]])
            self.assertEqual(verified, [[1]])

    def test_f03_list_nested_in_dictionary_copy_must_match_input(self):
        returned, verified = self._j0_nested('F03-DICT', {'arr': [SwitchOnCopy(1)]})
        if returned is not None:
            self.assertEqual(returned, {'arr': [1]})
            self.assertEqual(verified, {'arr': [1]})

    # Four controls: permitted normal operations still work.
    def test_control_plain_fencing_only_stays_blocked(self):
        j, e, d, tid = self._engine('CTRL-FENCING')
        t = MockTarget(target_id=tid, capability=TargetCapability.FENCING_ENFORCED)
        r = e.dispatch(d, t, TargetContract(tid, TargetCapability.FENCING_ENFORCED, 3600))
        self.assertEqual((r.outcome, t.call_count), ('BLOCKED', 0))

    def test_control_plain_zero_retention_stays_blocked(self):
        j, e, d, tid = self._engine('CTRL-RETENTION')
        t = MockTarget(target_id=tid, capability=TargetCapability.DEDUP_ENFORCED,
                       dedup_retention=0)
        r = e.dispatch(d, t, TargetContract(tid, TargetCapability.DEDUP_ENFORCED, 3600))
        self.assertEqual((r.outcome, t.call_count), ('BLOCKED', 0))

    def test_control_plain_nested_payload_matches_hash(self):
        returned, verified = self._j0_nested('CTRL-PAYLOAD', {'arr': [[1]]})
        self.assertEqual(returned, {'arr': [[1]]})
        self.assertEqual(verified, {'arr': [[1]]})

    def test_control_plain_dedup_dispatch_confirms(self):
        j, e, d, tid = self._engine('CTRL-DEDUP')
        t = MockTarget(target_id=tid, capability=TargetCapability.DEDUP_ENFORCED,
                       dedup_retention=3600)
        r = e.dispatch(d, t, TargetContract(tid, TargetCapability.DEDUP_ENFORCED, 3600))
        self.assertEqual((r.outcome, t.call_count), ('CONFIRMED', 1))
        self.assertTrue(j.verify_head()[0])


if __name__ == '__main__':
    unittest.main(verbosity=2)
# Bismillah ir-Rahman ir-Rahim
