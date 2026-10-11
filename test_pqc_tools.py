import unittest
from unittest.mock import patch
import pqc_tools as pq

class PQKeyTests(unittest.TestCase):
    def config(self):return {'algorithm':'ml-kem-768','profile':'evaluation','passphrase':'test-only-do-not-use-'+'x'*24}
    def test_government_profile_never_calls_worker(self):
        config=self.config();config['profile']='government'
        with patch.object(pq,'worker') as worker:
            with self.assertRaisesRegex(ValueError,'blocked'):pq.generate(config)
            worker.assert_not_called()
    def test_invalid_algorithm_never_calls_worker(self):
        config=self.config();config['algorithm']='ml-kem-768;whoami'
        with patch.object(pq,'worker') as worker:
            with self.assertRaises(ValueError):pq.generate(config)
            worker.assert_not_called()
    def test_short_and_oversized_passphrases_fail(self):
        for value in ['short','a'*1025,None]:
            config=self.config();config['passphrase']=value
            with patch.object(pq,'worker') as worker:
                with self.assertRaises(ValueError):pq.generate(config)
                worker.assert_not_called()
    def test_only_nonsecret_metadata_reaches_audit_even_with_full_capture(self):
        config=self.config();secret=config['passphrase'];result={'publicKeySha256':'a'*64,'privateKey':{'ciphertext':'sensitive-ciphertext'}}
        with patch.object(pq,'worker',return_value=result) as worker,patch.object(pq.audit_trail,'append') as audit:
            self.assertEqual(pq.generate(config),result)
            self.assertNotIn('passphrase',config)
            payload=audit.call_args.args[3]
            self.assertEqual(set(payload),{'algorithm','publicKeySha256','moduleValidation'})
            self.assertTrue(audit.call_args.kwargs['force_metadata'])
            self.assertNotIn(secret,str(audit.call_args));self.assertNotIn('sensitive-ciphertext',str(audit.call_args))
            self.assertEqual(worker.call_args.args[0]['operation'],'generate')
    def test_failure_releases_lock_and_removes_passphrase(self):
        config=self.config()
        with patch.object(pq,'worker',side_effect=ValueError('failure')):
            with self.assertRaises(ValueError):pq.generate(config)
        self.assertNotIn('passphrase',config)
        self.assertTrue(pq.KEY_LOCK.acquire(False));pq.KEY_LOCK.release()
    def test_parallel_key_generation_is_bounded(self):
        pq.KEY_LOCK.acquire()
        try:
            with self.assertRaisesRegex(ValueError,'already running'):pq.generate(self.config())
        finally:pq.KEY_LOCK.release()
    def test_runtime_unavailable_is_unknown_not_compliant(self):
        with patch.object(pq,'worker',side_effect=ValueError('Node missing')):
            result=pq.status();self.assertFalse(result['available']);self.assertFalse(result['governmentReady'])
    def test_older_runtime_is_not_reported_available(self):
        with patch.object(pq,'worker',return_value={'node':'v22.1.0'}):
            self.assertFalse(pq.status()['available'])

if __name__=='__main__':unittest.main()
