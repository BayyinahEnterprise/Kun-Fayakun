# Bismillah ir-Rahman ir-Rahim
"""Local v0.3.24 controls confirming the documented limits work for simple cases."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent / 'eess_prototype_v0324'))
from Bismillah_HABL_Event_Store_v0324 import HABLJournal

def p(tag, metadata):
    return dict(claim_id='CLAIM-'+tag, action='SEND',target='TARGET-'+tag,
                policy_version='POLICY-1',approval_ref='APPROVAL-1',
                business_effect_id='EFFECT-'+tag, metadata=metadata)

class P22PositiveLimitControls(unittest.TestCase):
    def assert_refused_cleanly(self,tag,metadata):
        j=HABLJournal()
        with self.assertRaises(ValueError):
            j.reserve_effect_and_commit_decision('DEC-'+tag,'EFFECT-'+tag,p(tag,metadata))
        self.assertEqual(j.head_offset,0)
        self.assertTrue(j.verify_head()[0])

    def test_plain_ascii_above_primitive_limit_rejected(self):
        self.assert_refused_cleanly('P22-CTL1','x'*(HABLJournal._MAX_PRIMITIVE_BYTES+1))

    def test_shared_dag_expansion_exceeds_node_count_rejected(self):
        node=['leaf']
        for _ in range(15):node=[node,node]
        self.assert_refused_cleanly('P22-CTL2',{'shared_dag':node})

    def test_plain_ascii_aggregate_over_budget_rejected(self):
        self.assert_refused_cleanly('P22-CTL3',['x'*40000 for _ in range(30)])

    def test_small_nested_json_accepted_and_journal_valid(self):
        j=HABLJournal();tag='P22-CTL4'; metadata={'x':['hello',7,True,None], 'nested':{'k':3.5}}
        event=j.reserve_effect_and_commit_decision('DEC-'+tag,'EFFECT-'+tag,p(tag,metadata))
        self.assertEqual(event.payload['metadata'],metadata)
        self.assertEqual(j.head_offset,1)
        self.assertTrue(j.verify_head()[0])

if __name__=='__main__':unittest.main(verbosity=2)
# Bismillah ir-Rahman ir-Rahim
