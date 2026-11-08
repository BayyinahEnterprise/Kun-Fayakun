# Bismillah ir-Rahman ir-Rahim
"""Independent v0.3.18 P15 regression and P16 targeted boundary probes.
All failing tests encode desirable security behavior. No external target calls.
"""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from Bismillah_HABL_Event_Store_v0324 import HABLJournal
from Bismillah_Decision_Reducer_v0324 import DecisionReducer, SafetyState
from Bismillah_Dispatch_Engine_v0324 import DispatchEngine, MockTarget, TargetContract, TargetCapability

GOOD_HASH = 'a' * 64
BAD_HASH = 'b' * 64

class SpoofStr(str):
    def __new__(cls, value, pretend):
        obj = str.__new__(cls, value)
        obj.pretend = pretend
        return obj
    def __eq__(self, other):
        if type(other) is str and other == self.pretend:
            return True
        return str.__eq__(self, other)
    def __ne__(self, other):
        return not self.__eq__(other)
    __hash__ = str.__hash__
    def __reduce_ex__(self, protocol):
        return (self.__class__, (str(self), self.pretend))

class FalseOutcomeTarget:
    target_id = 'TARGET-SAFE'
    capability = TargetCapability.DEDUP_ENFORCED
    dedup_retention = 3600
    def __init__(self): self.call_count = 0
    def call(self, request):
        self.call_count += 1
        return (SpoofStr('AMBIGUOUS', 'DEFINITIVE_EFFECT'), 'TX-UNVERIFIED', 'ambiguous')

class PlainAmbiguousTarget(FalseOutcomeTarget):
    def call(self, request):
        self.call_count += 1
        return ('AMBIGUOUS', '', 'unknown')

class SecurityRegression(unittest.TestCase):
    def setUp(self):
        self.j = HABLJournal()
        self.r = DecisionReducer(self.j)
        self.e = DispatchEngine(self.j, self.r)
        self.contract = TargetContract('TARGET-SAFE', TargetCapability.DEDUP_ENFORCED, dedup_retention_seconds=3600)

    def commit(self):
        return self.e.commit_decision('DEC-P16', 'CLAIM-P16', 'SEND',
            'TARGET-SAFE', 'POL-P16', 'APP-P16', business_effect_id='EFF-P16')

    def claim(self, target='TARGET-SAFE'):
        return self.j.atomic_dispatch_claim('DEC-P16', target, 'worker-owner',
            'ATT-P16', GOOD_HASH, 'KEY-P16', TargetCapability.DEDUP_ENFORCED, 'EFF-P16')

    def test_p15_engine_rejects_target_subclass(self):
        with self.assertRaises(ValueError):
            self.e.commit_decision('DEC-X', 'CLAIM-X', 'SEND', SpoofStr('UNAPPROVED', 'TARGET-SAFE'),
                'POL-X', 'APP-X', business_effect_id='EFF-X')
        self.assertEqual(self.j.head_offset, 0)

    def test_p15_journal_rejects_target_subclass(self):
        """P19: subclasses rejected outright -- no coercion hooks invoked."""
        payload = {'claim_id':'CLAIM-X','action':'SEND','target':SpoofStr('UNAPPROVED','TARGET-SAFE'),
            'policy_version':'POL-X', 'approval_ref':'APP-X', 'business_effect_id':'EFF-X'}
        with self.assertRaises(ValueError) as ctx:
            self.j.reserve_effect_and_commit_decision('DEC-X','EFF-X',payload)
        self.assertIn('exact built-in type', str(ctx.exception))

    def test_p15_spoof_response_cannot_confirm(self):
        self.commit()
        t = FalseOutcomeTarget()
        result = self.e.dispatch('DEC-P16', t, self.contract)
        self.assertNotEqual(result.outcome,'CONFIRMED')
        self.assertNotEqual(self.r.reduce('DEC-P16').safety, SafetyState.TERMINAL_CONFIRMED)
        self.assertEqual(t.call_count, 1)
        self.assertFalse(any(e.event_type.value == 'J4a' for e in self.j.replay()))

    def test_plain_target_confirms(self):
        self.commit()
        t = MockTarget(target_id='TARGET-SAFE', capability=TargetCapability.DEDUP_ENFORCED)
        result = self.e.dispatch('DEC-P16', t, self.contract)
        self.assertTrue(result.success)
        self.assertEqual(result.outcome,'CONFIRMED')
        self.assertEqual(t.call_count, 1)

    def test_plain_ambiguous_remains_not_confirmed(self):
        self.commit()
        result = self.e.dispatch('DEC-P16', PlainAmbiguousTarget(), self.contract)
        self.assertNotEqual(result.outcome,'CONFIRMED')
        self.assertNotEqual(self.r.reduce('DEC-P16').safety, SafetyState.TERMINAL_CONFIRMED)

    # NEW: direct authoritative journal boundaries still permissive.
    def test_p16_atomic_claim_rejects_spoofed_target(self):
        self.commit()
        before = self.j.head_offset
        with self.assertRaises(ValueError):
            self.claim(target=SpoofStr('TARGET-UNAPPROVED', 'TARGET-SAFE'))
        self.assertEqual(self.j.head_offset, before)

    def test_p16_j0_rejects_spoofed_payload_effect_id(self):
        payload = {'claim_id':'CLAIM-X','action':'SEND','target':'TARGET-SAFE',
            'policy_version':'POL-X', 'approval_ref':'APP-X',
            'business_effect_id':SpoofStr('EFF-UNAPPROVED', 'EFF-X')}
        with self.assertRaises(ValueError):
            self.j.reserve_effect_and_commit_decision('DEC-X','EFF-X',payload)
        self.assertEqual(self.j.head_offset,0)

    def test_p16_j4a_rejects_spoofed_request_hash(self):
        self.commit(); self.claim()
        with self.assertRaises(ValueError):
            self.j.record_effect_confirmed('DEC-P16','ATT-P16','TX-P16',
                SpoofStr(BAD_HASH,GOOD_HASH), evidence_hash='c'*64)
        self.assertFalse(any(e.event_type.value == 'J4a' for e in self.j.replay()))

    def test_p16_j4b_rejects_spoofed_request_hash(self):
        self.commit(); self.claim()
        with self.assertRaises(ValueError):
            self.j.record_no_effect('DEC-P16','ATT-P16','',
                SpoofStr(BAD_HASH,GOOD_HASH),no_effect_evidence='signed proof')
        self.assertFalse(any(e.event_type.value == 'J4b' for e in self.j.replay()))

    def test_p16_j11_rejects_spoofed_request_hash(self):
        self.commit(); self.claim()
        with self.assertRaises(ValueError):
            self.j.record_reconciliation_evidence('DEC-P16','ATT-P16',
                SpoofStr(BAD_HASH,GOOD_HASH),'KEY-P16','NOT_FOUND')
        self.assertFalse(any(e.event_type.value == 'J11' for e in self.j.replay()))

    def test_p16_j6_rejects_spoofed_worker(self):
        self.commit(); self.claim()
        with self.assertRaises(ValueError):
            self.j.release_lease('DEC-P16','TARGET-SAFE',SpoofStr('worker-attacker','worker-owner'),1)
        self.assertFalse(any(e.event_type.value == 'J6' for e in self.j.replay()))

if __name__ == '__main__':
    unittest.main(verbosity=2)
# Bismillah ir-Rahman ir-Rahim
