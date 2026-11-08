# Bismillah ir-Rahman ir-Rahim
"""EESS v0.3.19: eight independent adversarial assertions + three positive controls.
The eight negative assertions should pass once the relevant boundaries are hardened.
On the submitted release they are expected to fail (confirming reproduced gaps).
Purely in-process; no external network or non-mock target requests.
"""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from Bismillah_HABL_Event_Store_v0324 import HABLJournal
from Bismillah_Decision_Reducer_v0324 import DecisionReducer, SafetyState

HASH = 'a'*64
EVIDENCE = 'c'*64

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

class SpoofKey(SpoofStr):
    def __hash__(self):
        return hash(self.pretend)

class SpoofInt(int):
    def __new__(cls, value, pretend):
        obj = int.__new__(cls, value)
        obj.pretend = pretend
        return obj
    def __eq__(self, other):
        if type(other) is int and other == self.pretend:
            return True
        return int.__eq__(self, other)
    def __ne__(self, other):
        return not self.__eq__(other)
    __hash__ = int.__hash__
    def __reduce_ex__(self, protocol):
        return (self.__class__, (int(self), self.pretend))

class SpoofTarget(SpoofStr):
    def __hash__(self):
        return hash(self.pretend)

class MutationOnDeepCopy(dict):
    def __deepcopy__(self, memo):
        modified = dict(self)
        modified['action'] = 'DENY'
        modified['target'] = 'TARGET-UNAPPROVED'
        modified['business_effect_id'] = 'EFF-UNRESERVED'
        return modified

class P17Regressions(unittest.TestCase):
    def setUp(self):
        self.j = HABLJournal()
        self.d = 'DEC-P17'
        self.eff = 'EFF-P17'
        self.att = 'ATT-P17'
        self.payload = {
            'claim_id':'CLAIM-P17', 'action':'SEND', 'target':'TARGET-SAFE',
            'policy_version':'POL-P17', 'approval_ref':'APP-P17',
            'business_effect_id':self.eff,
        }

    def commit(self, payload=None):
        return self.j.reserve_effect_and_commit_decision(self.d, self.eff,
                                                          self.payload if payload is None else payload)

    def claim(self):
        return self.j.atomic_dispatch_claim(self.d, 'TARGET-SAFE', 'worker-owner',
            self.att, HASH, 'KEY-P17', 'TARGET_DEDUP_ENFORCED', self.eff)

    # F01: The input that passed validation must match what is serialized.
    def test_p17_01_j0_rejects_dict_deepcopy_mutation(self):
        with self.assertRaises(ValueError):
            self.commit(MutationOnDeepCopy(self.payload))
        self.assertEqual(self.j.head_offset, 0)
        self.assertIsNone(self.j.is_effect_reserved(self.eff))

    def test_p17_02_j0_rejects_key_spoofing(self):
        payload = {k:v for k,v in self.payload.items() if k != 'action'}
        payload[SpoofKey('not_action', 'action')] = 'SEND'
        with self.assertRaises(ValueError):
            self.commit(payload)
        self.assertEqual(self.j.head_offset, 0)

    # F02: Optional *business_effect_id* must be exact built-in str before comparison.
    def test_p17_03_j4a_rejects_spoofed_effect(self):
        self.commit(); self.claim()
        with self.assertRaises(ValueError):
            self.j.record_effect_confirmed(self.d, self.att, 'TX-P17',HASH,EVIDENCE,
                SpoofStr('EFF-UNBOUND', self.eff))
        self.assertEqual(self.j.head_offset, 3)
        self.assertNotEqual(DecisionReducer(self.j).reduce(self.d).safety,
                            SafetyState.TERMINAL_CONFIRMED)

    def test_p17_04_j4b_rejects_spoofed_effect(self):
        self.commit(); self.claim()
        with self.assertRaises(ValueError):
            self.j.record_no_effect(self.d, self.att, '', HASH, 'test proof',
                SpoofStr('EFF-UNBOUND', self.eff))
        self.assertEqual(self.j.head_offset, 3)

    def test_p17_05_j11_rejects_spoofed_effect(self):
        self.commit(); self.claim()
        with self.assertRaises(ValueError):
            self.j.record_reconciliation_evidence(self.d, self.att, HASH,
                'KEY-P17', 'NOT_FOUND', business_effect_id=SpoofStr('EFF-UNBOUND', self.eff))
        self.assertEqual(self.j.head_offset, 3)

    # F03: J7 exact epoch/target binding; avoid false lease expiration.
    def test_p17_06_j7_rejects_spoofed_epoch(self):
        self.commit();self.claim()
        with self.assertRaises(ValueError):
            self.j.expire_lease(self.d, 'TARGET-SAFE', SpoofInt(999, 1))
        self.assertEqual(self.j.head_offset, 3)
        self.assertEqual(self.j._active_leases[(self.d,'TARGET-SAFE')], ('worker-owner', 1))

    def test_p17_07_j7_rejects_spoofed_target(self):
        self.commit();self.claim()
        with self.assertRaises(ValueError):
            self.j.expire_lease(self.d, SpoofTarget('TARGET-UNAPPROVED', 'TARGET-SAFE'), 1)
        self.assertEqual(self.j.head_offset, 3)
        self.assertIn((self.d,'TARGET-SAFE'),self.j._active_leases)

    # F04: status reader filter must reflect its actual serialized identifier.
    def test_p17_08_verified_snapshot_rejects_spoofed_filter(self):
        self.commit()
        self.j.reserve_effect_and_commit_decision('DEC-OTHER', 'EFF-OTHER', {
            'claim_id':'CLAIM-OTHER', 'action':'SEND', 'target':'TARGET-SAFE',
            'policy_version':'POL-P17', 'approval_ref':'APP-P17',
            'business_effect_id':'EFF-OTHER'})
        with self.assertRaises(ValueError):
            self.j.verified_snapshot(SpoofStr('DEC-OTHER', self.d))

    # Controls: no false positives against ordinary input.
    def test_control_plain_dict_j0(self):
        self.commit()
        self.assertEqual(self.j.replay()[0].payload['action'], 'SEND')
        self.assertTrue(self.j.verify_head()[0])

    def test_control_plain_j4a(self):
        self.commit();self.claim()
        self.j.record_effect_confirmed(self.d,self.att,'TX-P17',HASH,EVIDENCE,self.eff)
        self.assertEqual(DecisionReducer(self.j).reduce(self.d).safety,
                         SafetyState.TERMINAL_CONFIRMED)
        self.assertTrue(self.j.verify_head()[0])

    def test_control_plain_j7(self):
        self.commit();self.claim()
        e=self.j.expire_lease(self.d,'TARGET-SAFE',1)
        self.assertEqual(e.payload['epoch'],1)
        self.assertTrue(self.j.verify_head()[0])

if __name__ == '__main__':
    unittest.main(verbosity=2)
# Bismillah ir-Rahman ir-Rahim
