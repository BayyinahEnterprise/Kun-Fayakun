# Bismillah ir-Rahman ir-Rahim
"""Additional independent in-process P20 lock-hook probes; expected unsafe under v0.3.22."""
import sys,threading,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from Bismillah_HABL_Event_Store_v0324 import HABLJournal

class P20Extended(unittest.TestCase):
    def _run_case(self, mode):
        journal = HABLJournal()
        entered, finished = threading.Event(), threading.Event()
        outcome=[]
        class MaliciousMeta(type):
            def __getattribute__(cls, name):
                if name == '__name__':
                    entered.set()
                    journal.verify_head()  # re-enters non-reentrant lock
                return super().__getattribute__(name)
        class MaliciousKey(metaclass=MaliciousMeta):
            def __hash__(self): return 31
        class MaliciousValue(metaclass=MaliciousMeta): pass
        p={'claim_id':'CLAIM-X', 'action':'SEND','target':'TARGET-X','policy_version':'P',
           'approval_ref':'A','business_effect_id':'E'}
        p['metadata']=({MaliciousKey():1} if mode=='key' else {'v':MaliciousValue()})
        def writer():
            try:
                journal.reserve_effect_and_commit_decision('D','E',p)
                outcome.append('ACCEPTED')
            except ValueError:
                outcome.append('REJECTED')
            except Exception as e:
                outcome.append(type(e).__name__)
            finally:
                finished.set()
        threading.Thread(target=writer,daemon=True).start()
        completed=finished.wait(0.4)
        self.assertTrue(completed, f'unsafe diagnostic: {mode}, metaclass __name__ hook={entered.is_set()}')
        self.assertEqual(outcome,['REJECTED'])
    def test_f02a_invalid_key_metaclass_name_hook(self): self._run_case('key')
    def test_f02b_unsupported_value_metaclass_name_hook(self): self._run_case('value')
if __name__=='__main__':unittest.main(verbosity=2)
# Bismillah ir-Rahman ir-Rahim
