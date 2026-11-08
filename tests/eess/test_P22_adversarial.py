# Bismillah ir-Rahman ir-Rahim
"""P22 independent security probes for v0.3.24. Local mock only; no external effects.
Rejection tests deliberately fail on observed vulnerability. The prior frozen suites are unchanged.
"""
import copy
import json
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / 'eess_prototype_v0324'))
from Bismillah_HABL_Event_Store_v0324 import HABLJournal
from Bismillah_Decision_Reducer_v0324 import DecisionReducer
from Bismillah_Dispatch_Engine_v0324 import DispatchEngine, MockTarget, TargetContract, TargetCapability


def valid_payload(suffix):
    return dict(claim_id='CLAIM-'+suffix, action='SEND',target='TARGET-'+suffix,
                policy_version='POLICY-1',approval_ref='APPROVAL-1',
                business_effect_id='EFFECT-'+suffix)


class AdvertisingDedupWithoutEnforcement:
    """Adversarial local adapter: public attestation is not actual enforcement."""
    def __init__(self, target_id):
        self.target_id = target_id
        self.capability = TargetCapability.DEDUP_ENFORCED
        self.dedup_retention = 3600
        self._backend_mode = 'NO_DEDUP'
        self.calls = []
        self.effects = []

    def call(self, request):
        self.calls.append(copy.deepcopy(request))
        self.effects.append(request.get('business_effect_id'))
        return ('DEFINITIVE_EFFECT', f'TX-NO-DEDUP-{len(self.effects)}', 'accepted without dedup')


class P22IndependentProbes(unittest.TestCase):
    def test_p22_f01_advertising_dedup_but_no_enforcement_must_not_commit_send(self):
        journal=HABLJournal()
        engine=DispatchEngine(journal, DecisionReducer(journal))
        decision_id='DEC-P22-F01'; target_id='TARGET-P22-F01'
        engine.commit_decision(decision_id,'CLAIM-P22-F01','SEND',target_id,
                               'POLICY-1','APPROVAL-1',business_effect_id='EFFECT-P22-F01')
        target=AdvertisingDedupWithoutEnforcement(target_id)
        result=engine.dispatch(decision_id,target,TargetContract(target_id,TargetCapability.DEDUP_ENFORCED,3600))
        if target.calls:
            replay=target.call(copy.deepcopy(target.calls[0]))
            self.assertEqual(replay[0], 'DEFINITIVE_EFFECT')
            self.assertNotEqual(replay[1],result.target_transaction_id)
            print('OBS-P22-F01 outcome=%s sends=%s J2=%s duplicate_tx=%s' %
                  (result.outcome,len(target.effects),journal.has_j2(decision_id),replay[1]))
        self.assertEqual(len(target.effects),0,'Untrusted adapter was called despite no dedup enforcement')
        self.assertFalse(journal.has_j2(decision_id),'J2 committed for unregistered non-enforcing target')
        self.assertEqual(result.outcome,'BLOCKED')

    def test_p22_f02_primitive_max_bytes_must_use_encoded_bytes(self):
        journal=HABLJournal()
        p=valid_payload('P22-F02A')
        p['metadata']={'nonascii':'😀'*20_000}  # 20k codepoints, 80k utf8 bytes
        self.assertGreater(len(p['metadata']['nonascii'].encode('utf-8')), journal._MAX_PRIMITIVE_BYTES)
        with self.assertRaises(ValueError):
            journal.reserve_effect_and_commit_decision('DEC-P22-F02A','EFFECT-P22-F02A',p)
        self.assertEqual(journal.head_offset,0)

    def test_p22_f02_total_payload_serialized_bytes_must_be_bounded(self):
        journal=HABLJournal()
        p=valid_payload('P22-F02B')
        p['metadata']=['😀'*12_000 for _ in range(24)] # 1.15MiB UTF-8 input, 3.45MiB json ASCII
        self.assertLess(max(len(x.encode('utf-8')) for x in p['metadata']),journal._MAX_PRIMITIVE_BYTES)
        encoded = json.dumps(p,sort_keys=True,separators=(',',':')).encode('utf-8')
        self.assertGreater(len(encoded),journal._MAX_PAYLOAD_BYTES)
        with self.assertRaises(ValueError):
            journal.reserve_effect_and_commit_decision('DEC-P22-F02B','EFFECT-P22-F02B',p)
        self.assertEqual(journal.head_offset,0)

    def test_p22_f02_large_decimal_integer_payload_must_count_serialized_bytes(self):
        journal=HABLJournal()
        p=valid_payload('P22-F02C')
        p['metadata']=[int('9'*1100) for _ in range(1000)]
        encoded=json.dumps(p,sort_keys=True,separators=(',',':')).encode('utf-8')
        self.assertGreater(len(encoded),journal._MAX_PAYLOAD_BYTES)
        with self.assertRaises(ValueError):
            journal.reserve_effect_and_commit_decision('DEC-P22-F02C','EFFECT-P22-F02C',p)
        self.assertEqual(journal.head_offset,0)

    def test_p22_f03_mock_target_rejected_epoch_metaclass_must_not_deadlock(self):
        target=MockTarget(target_id='TARGET-P22-F03', capability=TargetCapability.DEDUP_ENFORCED)
        invoked=threading.Event();done=threading.Event();out=[]
        good_req=dict(decision_id='DEC-P22-F03',attempt_id='ATT-P22-F03',
                      epoch=1,request_hash='a'*64,idempotency_key='KEY-P22-F03',
                      target='TARGET-P22-F03',business_effect_id='EFFECT-P22-F03')
        class MaliciousMeta(type):
            def __getattribute__(cls, name):
                if name=='__name__':
                    invoked.set()
                    target.call(good_req)  # reenter non-reentrant lock
                return super().__getattribute__(name)
        class BadEpoch(metaclass=MaliciousMeta):pass
        bad_req=dict(good_req,epoch=BadEpoch())
        def writer():
            try:out.append(target.call(bad_req)[0])
            except Exception as exc:out.append(type(exc).__name__)
            finally:done.set()
        thread=threading.Thread(target=writer,daemon=True)
        thread.start()
        completed=done.wait(0.5)
        print('OBS-P22-F03 completed=%s hook=%s effects=%s' %
              (completed,invoked.is_set(),target._tx_counter))
        self.assertTrue(completed,'Untrusted metaclass __name__ reentered target lock')
        self.assertEqual(out,['DEFINITIVE_NO_EFFECT'])
        self.assertEqual(target._tx_counter,0)


if __name__=='__main__':unittest.main(verbosity=2)
# Bismillah ir-Rahman ir-Rahim
