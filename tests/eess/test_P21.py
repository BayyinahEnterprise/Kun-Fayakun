# Bismillah ir-Rahman ir-Rahim
"""Independent, local v0.3.23 P21 probes. Never use against live targets.

The third-getter and identifier-diagnostic tests are rejection gates. The
shared-DAG and oversized-primitive cases are *observations*, not arbitrary
regression thresholds: they demonstrate missing aggregate resource budgets.
"""
import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from Bismillah_HABL_Event_Store_v0324 import HABLJournal
from Bismillah_Decision_Reducer_v0324 import DecisionReducer
from Bismillah_Dispatch_Engine_v0324 import (
    DispatchEngine, MockTarget, TargetContract, TargetCapability,
)


def payload(suffix):
    return dict(claim_id='CLAIM-' + suffix, action='SEND', target='TARGET-' + suffix,
                policy_version='POLICY-1', approval_ref='APPROVAL-1',
                business_effect_id='EFFECT-' + suffix)


class FlipOnThirdCapabilityRead(MockTarget):
    def __init__(self, **kwargs):
        self._reads = 0
        super().__init__(**kwargs)

    @property
    def capability(self):
        self._reads += 1
        approved = self._capability
        if self._reads == 3:
            self._capability = TargetCapability.FENCING_ENFORCED
        return approved

    @capability.setter
    def capability(self, value):
        self._capability = value


class P21NewIndependentProbes(unittest.TestCase):
    def test_p21_f01_third_getter_can_mutate_after_reporting_approved(self):
        journal = HABLJournal()
        engine = DispatchEngine(journal, DecisionReducer(journal))
        did, tid = 'DEC-P21-F01', 'TARGET-P21-F01'
        engine.commit_decision(did, 'CLAIM-P21-F01', 'SEND', tid,
                               'POLICY-1', 'APPROVAL-1',
                               business_effect_id='EFFECT-P21-F01')
        target = FlipOnThirdCapabilityRead(target_id=tid,
            capability=TargetCapability.DEDUP_ENFORCED, dedup_retention=3600)
        result = engine.dispatch(did, target,
            TargetContract(tid, TargetCapability.DEDUP_ENFORCED, 3600))
        self.assertEqual(target._reads, 3)
        self.assertEqual(target._capability, TargetCapability.FENCING_ENFORCED)
        # These are the required no-send/no-J2 security outcomes.
        self.assertEqual(target.call_count, 0, 'changed capability target called: ' + result.outcome)
        self.assertEqual(result.outcome, 'BLOCKED')
        self.assertFalse(journal.has_j2(did))

    def test_p21_f01_mock_target_accepts_untrusted_capability_override(self):
        """A caller-provided request key must not downgrade target-side fencing."""
        r = dict(decision_id='D-P21-OVERRIDE', attempt_id='A-P21-OVERRIDE',
                 epoch=0, request_hash='a' * 64, idempotency_key='K-P21-OVERRIDE',
                 target='TARGET-P21-OVERRIDE', business_effect_id='E-P21-OVERRIDE')
        control = MockTarget(target_id='TARGET-P21-OVERRIDE',
                             capability=TargetCapability.FENCING_ENFORCED)
        self.assertEqual(control.call(r)[0], 'DEFINITIVE_NO_EFFECT')
        self.assertEqual(control._tx_counter, 0)
        target = MockTarget(target_id='TARGET-P21-OVERRIDE',
                            capability=TargetCapability.FENCING_ENFORCED)
        hostile_request = dict(r, _authorized_capability=TargetCapability.DEDUP_ENFORCED)
        result = target.call(hostile_request)
        self.assertEqual(result[0], 'DEFINITIVE_NO_EFFECT',
                         'caller-controlled capability overrode target-side fencing: ' + str(result))
        self.assertEqual(target._tx_counter, 0)

    def test_p21_f02_invalid_decision_id_metaclass_name_hook_must_not_deadlock(self):
        journal, entered, done = HABLJournal(), threading.Event(), threading.Event()
        results = []
        class MaliciousMeta(type):
            def __getattribute__(cls, name):
                if name == '__name__':
                    entered.set()
                    journal.verify_head()
                return super().__getattribute__(name)
        class MaliciousDecisionId(metaclass=MaliciousMeta):
            pass
        def writer():
            try:
                journal.reserve_effect_and_commit_decision(
                    MaliciousDecisionId(), 'EFFECT-P21-F02', payload('P21-F02'))
                results.append('ACCEPTED')
            except ValueError:
                results.append('REJECTED')
            except Exception as e:
                results.append(type(e).__name__)
            finally:
                done.set()
        threading.Thread(target=writer, daemon=True).start()
        self.assertTrue(done.wait(0.5), 'journal deadlocked; __name__ hook=' + str(entered.is_set()))
        self.assertEqual(results, ['REJECTED'])
        self.assertEqual(journal.head_offset, 0)

    def test_control_cycle_rejected_without_append(self):
        journal = HABLJournal()
        obj = []
        obj.append(obj)
        p = payload('P21-C01')
        p['metadata'] = obj
        with self.assertRaises(ValueError):
            journal.reserve_effect_and_commit_decision('DEC-P21-C01','EFFECT-P21-C01', p)
        self.assertEqual(journal.head_offset, 0)
        self.assertTrue(journal.verify_head()[0])

    def test_control_depth_limit_rejected_without_append(self):
        journal = HABLJournal()
        obj = 'leaf'
        for i in range(36):
            obj = [obj]
        p = payload('P21-C02')
        p['metadata'] = obj
        with self.assertRaises(ValueError):
            journal.reserve_effect_and_commit_decision('DEC-P21-C02','EFFECT-P21-C02', p)
        self.assertEqual(journal.head_offset, 0)
        self.assertTrue(journal.verify_head()[0])

    def test_observation_shared_dag_exponential_growth_is_accepted(self):
        journal = HABLJournal()
        node = ['leaf']
        for _ in range(15):
            node = [node, node]
        p = payload('P21-OBS01')
        p['metadata'] = {'shared_dag': node}
        t0 = time.perf_counter()
        event = journal.reserve_effect_and_commit_decision('DEC-P21-OBS01','EFFECT-P21-OBS01',p)
        elapsed = time.perf_counter() - t0
        expanded = event.payload['metadata']['shared_dag']
        for _ in range(15):
            self.assertIsNot(expanded[0],expanded[1])
            expanded = expanded[0]
        self.assertEqual(journal.head_offset, 1)
        self.assertTrue(journal.verify_head()[0])
        print('OBS-P21: shared input DAG ~16 distinct containers expanded to '
              '>=65,535 cloned list nodes without node budget, elapsed %.3fs'%elapsed)

    def test_observation_oversized_primitive_is_accepted(self):
        journal = HABLJournal()
        p = payload('P21-OBS02')
        p['metadata'] = {'big': 'X' * (1024*1024)}
        journal.reserve_effect_and_commit_decision('DEC-P21-OBS02','EFFECT-P21-OBS02',p)
        self.assertEqual(journal.head_offset, 1)
        self.assertTrue(journal.verify_head()[0])
        print('OBS-P21: 1 MiB metadata string accepted, no payload byte budget')


if __name__ == '__main__':
    unittest.main(verbosity=2)
# Bismillah ir-Rahman ir-Rahim
