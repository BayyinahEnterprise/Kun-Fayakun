# Bismillah ir-Rahman ir-Rahim
"""Frozen independent P19 adversarial suite for EESS v0.3.21.

Expected ON the submitted v0.3.21: 3 security tests fail/error, 4 controls pass.
Expected AFTER repair: all 7 pass, with no weakening of assertions.
All tests run in memory and do not call external targets.
"""
import sys
import threading
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
# The audit packet may contain this test alongside the extracted source tree.
SRC = HERE / 'eess_prototype_v0324'
if not SRC.is_dir():
    SRC = HERE
sys.path.insert(0, str(SRC))
from Bismillah_HABL_Event_Store_v0324 import HABLJournal, EventType
from Bismillah_Decision_Reducer_v0324 import DecisionReducer
from Bismillah_Dispatch_Engine_v0324 import (
    DispatchEngine, MockTarget, TargetContract, TargetCapability,
)


class CapabilityFlipTarget(MockTarget):
    """Runtime adapter capability changes during retention-attribute access."""
    def __init__(self, contract, **kwargs):
        self._armed = False
        self._contract = contract
        super().__init__(**kwargs)
        self._armed = True

    @property
    def dedup_retention(self):
        if self._armed:
            self._contract.capability = TargetCapability.FENCING_ENFORCED
            self.capability = TargetCapability.FENCING_ENFORCED
        return self._retention

    @dedup_retention.setter
    def dedup_retention(self, value):
        self._retention = value


class P19Regressions(unittest.TestCase):
    def build(self, suffix):
        journal = HABLJournal()
        engine = DispatchEngine(journal, DecisionReducer(journal))
        did = 'DEC-' + suffix
        tid = 'TARGET-' + suffix
        engine.commit_decision(did, 'CLAIM-' + suffix, 'SEND', tid,
                               'POLICY-1', 'APPROVAL-1',
                               business_effect_id='EFFECT-' + suffix)
        return journal, engine, did, tid

    def test_f01_capability_flip_after_validation_must_not_send(self):
        journal, engine, did, tid = self.build('P19-F01')
        contract = TargetContract(tid, TargetCapability.DEDUP_ENFORCED, 3600)
        adapter = CapabilityFlipTarget(
            contract, target_id=tid,
            capability=TargetCapability.DEDUP_ENFORCED, dedup_retention=3600)
        result = engine.dispatch(did, adapter, contract)
        self.assertEqual(adapter.capability, TargetCapability.FENCING_ENFORCED)
        self.assertEqual(contract.capability, TargetCapability.FENCING_ENFORCED)
        self.assertEqual(adapter.call_count, 0,
                         f'Unsupported fencing-only target was called: {result}')
        self.assertEqual(result.outcome, 'BLOCKED')
        self.assertFalse(journal.has_j2(did))

    def test_f02_huge_exact_integer_retention_must_return_typed_block(self):
        journal, engine, did, tid = self.build('P19-F02')
        adapter = MockTarget(target_id=tid,
                             capability=TargetCapability.DEDUP_ENFORCED)
        result = engine.dispatch(
            did, adapter,
            TargetContract(tid, TargetCapability.DEDUP_ENFORCED, 10 ** 400))
        self.assertEqual(adapter.call_count, 0)
        self.assertEqual(result.outcome, 'BLOCKED')
        self.assertFalse(journal.has_j2(did))

    def test_f03_recursive_input_conversion_must_not_deadlock_journal(self):
        journal = HABLJournal()
        entered_hook = threading.Event()
        finished = threading.Event()
        result = []

        class ReentrantInt(int):
            def __int__(self):
                entered_hook.set()
                # Called while reserve_effect_and_commit_decision holds _lock.
                # A public journal reader tries to acquire that same Lock.
                journal.verify_head()
                return 1

        payload = dict(claim_id='CLAIM-P19-F03', action='SEND',
                       target='TARGET-P19-F03', policy_version='POLICY-1',
                       approval_ref='APPROVAL-1',
                       business_effect_id='EFFECT-P19-F03',
                       metadata={'nested': [ReentrantInt(1)]})

        def submit():
            try:
                journal.reserve_effect_and_commit_decision(
                    'DEC-P19-F03', 'EFFECT-P19-F03', payload)
                result.append('ACCEPTED')
            except ValueError:
                result.append('REJECTED')
            except Exception as exc:
                result.append(type(exc).__name__)
            finally:
                finished.set()

        thread = threading.Thread(target=submit, daemon=True)
        thread.start()
        self.assertTrue(finished.wait(timeout=0.6),
                        'Journal writer is blocked in attacker-controlled __int__; '
                        f'entered_hook={entered_hook.is_set()}')
        self.assertIn(result[0], ('ACCEPTED', 'REJECTED'),
                      'Expected an in-band accept or ValueError reject')

    def test_control_normal_dedup_dispatch(self):
        journal, engine, did, tid = self.build('P19-C01')
        adapter = MockTarget(target_id=tid,
                             capability=TargetCapability.DEDUP_ENFORCED)
        result = engine.dispatch(did, adapter,
                                 TargetContract(tid, TargetCapability.DEDUP_ENFORCED, 3600))
        self.assertEqual(result.outcome, 'CONFIRMED')
        self.assertEqual(adapter.call_count, 1)
        self.assertTrue(journal.verify_head()[0])

    def test_control_static_fencing_only_blocked(self):
        journal, engine, did, tid = self.build('P19-C02')
        adapter = MockTarget(target_id=tid,
                             capability=TargetCapability.FENCING_ENFORCED)
        result = engine.dispatch(did, adapter,
                                 TargetContract(tid, TargetCapability.FENCING_ENFORCED, 3600))
        self.assertEqual(result.outcome, 'BLOCKED')
        self.assertEqual(adapter.call_count, 0)

    def test_control_normal_retention_accepted(self):
        journal, engine, did, tid = self.build('P19-C03')
        adapter = MockTarget(target_id=tid,
                             capability=TargetCapability.DEDUP_ENFORCED,
                             dedup_retention=3600)
        result = engine.dispatch(did, adapter,
                                 TargetContract(tid, TargetCapability.DEDUP_ENFORCED, 3600))
        self.assertEqual(result.outcome, 'CONFIRMED')

    def test_control_exact_nested_metadata_stable(self):
        journal = HABLJournal()
        payload = dict(claim_id='CLAIM-P19-C04', action='SEND',
                       target='TARGET-P19-C04', policy_version='POLICY-1',
                       approval_ref='APPROVAL-1',
                       business_effect_id='EFFECT-P19-C04',
                       metadata={'nested': [[1, 2], {'flag': True, 'value': None}]})
        event = journal.reserve_effect_and_commit_decision(
            'DEC-P19-C04', 'EFFECT-P19-C04', payload)
        snap, _, _ = journal.verified_snapshot('DEC-P19-C04')
        self.assertEqual(event.payload, snap[0].payload)
        self.assertTrue(journal.verify_head()[0])


if __name__ == '__main__':
    unittest.main(verbosity=2)
# Bismillah ir-Rahman ir-Rahim
