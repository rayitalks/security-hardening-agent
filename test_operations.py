import base64
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import audit_trail as audit
import engagements
import defense_ops as defense
import security_store as store
import team_suite
import purple_team
import malware_intel
import vm_scan
import vm_remote
import behavior_rules
import inference_metrics
import monitor_worker
import live_monitor
import asset_registry
import runtime_gateway

class Isolated(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.env=patch.dict(os.environ,{'SHA_DATA_DIR':str(self.root/'data'),'TEST_AUDIT_KEY':base64.b64encode(secrets.token_bytes(32)).decode()});self.env.start()
        defense.BASE.clear();defense.DOMAINS.clear();defense.ACTIONS.clear()
    def tearDown(self):self.env.stop();self.temp.cleanup()
    def asset(self):return asset_registry.save({'kind':'agent','target':str(self.root),'name':'fixture'})
    def scope(self,**extra):return engagements.create({'url':'http://127.0.0.1:11434','model':'fixture','authorized':True,**extra})

class AuditTests(Isolated):
    def test_default_hash_only_and_tamper_detection(self):
        anchor=audit.append('agent','prompt','allow',{'secret':'TEST_PAYLOAD'})
        dump=audit.snapshot();self.assertNotIn('TEST_PAYLOAD',json.dumps(dump));self.assertTrue(dump['verification']['valid'])
        with closing(audit.connection()) as db:db.execute('UPDATE ledger SET body=replace(body,?,?) WHERE seq=1',('allow','tampered'));db.commit()
        self.assertFalse(audit.verify()['valid'])
    def test_aes_roundtrip_and_missing_key_fails_closed(self):
        audit.configure({'capture':True,'keyEnv':'TEST_AUDIT_KEY'});audit.append('agent','input','allow',{'private':'secretfixture'})
        with closing(audit.connection()) as db:row=json.loads(db.execute('SELECT body FROM ledger ORDER BY seq DESC LIMIT 1').fetchone()[0])
        encrypted=row.pop('encryptedPayload')
        clear=audit.capture_key('TEST_AUDIT_KEY').decrypt(base64.b64decode(encrypted['nonce']),base64.b64decode(encrypted['ciphertext']),audit.canonical(row))
        self.assertEqual(json.loads(clear),{'private':'secretfixture'});self.assertTrue(audit.verify()['valid'])
        with patch.dict(os.environ,{'TEST_AUDIT_KEY':''}):
            with self.assertRaises(ValueError):audit.append('agent','input','allow','must not log cleartext')
    def test_external_anchor_detects_tail_deletion(self):
        audit.append('a','x','allow',{});anchor=audit.append('a','y','allow',{})
        with closing(audit.connection()) as db:db.execute('DELETE FROM ledger WHERE seq=2');db.commit()
        self.assertTrue(audit.verify()['valid']);self.assertFalse(audit.verify({'anchor':anchor})['valid'])

class ScopeTests(Isolated):
    def test_scope_exact_target_expiry_and_signature(self):
        row=self.scope();cfg={'engagementId':row['id'],'url':row['url'],'model':row['model']};engagements.require(cfg)
        with self.assertRaises(ValueError):engagements.require({**cfg,'model':'other'})
        row['model']='tampered';store.put('engagements',row)
        with self.assertRaises(ValueError):engagements.require({**cfg,'model':'tampered'})
    def test_production_requires_separate_approval(self):
        row=self.scope(environment='production');cfg={'engagementId':row['id'],'url':row['url'],'model':row['model']}
        with self.assertRaises(ValueError):engagements.require(cfg)
        engagements.approve({'id':row['id'],'confirmation':'APPROVE SYNTHETIC PRODUCTION TEST'});engagements.require(cfg)
        with patch('engagements.time.time',return_value=time.time()+8*86400):
            with self.assertRaises(ValueError):engagements.require(cfg)

class DefenseTests(Isolated):
    def fixture(self):
        asset=self.asset();route=runtime_gateway.save_route({'assetId':asset['id'],'authorized':True})['route'];issued=defense.mint({'routeId':route['id'],'agentId':'worker','taskId':'task','tools':['delete_files','read_information']})
        return route,issued,defense.authenticate(route,issued['token'])
    def test_tokens_expire_rotate_revoke_and_never_store_plaintext(self):
        route,issued,who=self.fixture();self.assertNotIn(issued['token'],json.dumps(store.all_items('tokens')))
        defense.mint({'routeId':route['id'],'rotateId':who['id']})
        with self.assertRaises(PermissionError):defense.authenticate(route,issued['token'])
        fresh=defense.mint({'routeId':route['id'],'ttlMinutes':1})
        with patch('defense_ops.time.time',return_value=time.time()+120):
            with self.assertRaises(PermissionError):defense.authenticate(route,fresh['token'])
    def test_human_approval_is_exact_payload_and_single_use(self):
        route,_,who=self.fixture();payload={'path':'synthetic'}
        with self.assertRaises(PermissionError):defense.authorize(route,who,'delete_files',payload,'trace-id-123')
        row=store.all_items('approvals')[0];defense.approve({'id':row['id'],'confirmation':'APPROVE EXACT REQUEST'})
        with self.assertRaises(PermissionError):defense.authorize(route,who,'delete_files',{'path':'different'},'trace-id-123')
        defense.authorize(route,who,'delete_files',payload,'trace-id-123')
        with self.assertRaises(PermissionError):defense.authorize(route,who,'delete_files',payload,'trace-id-123')
    def test_context_and_task_scopes_cannot_widen_route(self):
        route,_,who=self.fixture()
        with self.assertRaises(PermissionError):defense.authorize(route,who,'unknown_tool',{},'trace-123')
        defense.configure({'routeId':route['id'],'roles':['reviewer']})
        with self.assertRaises(PermissionError):defense.authorize(route,who,None,{},'trace-123')
    def test_encrypted_memory_rollback_and_gateway_quarantine(self):
        route,issued,who=self.fixture();audit.configure({'capture':False,'keyEnv':'TEST_AUDIT_KEY'})
        one=defense.memory_save({'assetId':route['id'],'state':{'note':'first-private'}});defense.memory_save({'assetId':route['id'],'state':{'note':'second-private'}})
        self.assertEqual(defense.memory_read(route['id'])['note'],'second-private')
        defense.memory_restore({'id':one['id'],'confirmation':'RESTORE MANAGED MEMORY'});self.assertEqual(defense.memory_read(route['id'])['note'],'first-private')
        self.assertNotIn('first-private',json.dumps(store.all_items('memory-snapshots')))
        defense.incident({'assetId':route['id'],'action':'quarantine'});self.assertFalse(store.get('routes',route['id'])['enabled'])
        with self.assertRaises(PermissionError):defense.authenticate(route,issued['token'])
    def test_baseline_detects_new_domain_and_token_cost_spike(self):
        for _ in range(21):defense.observe('a','read_information','https://old.example.invalid',{'tokens':100,'cost':.1})
        hits=defense.observe('a','new_tool','https://new.example.invalid',{'tokens':10000,'cost':10})
        self.assertTrue({'new-external-domain','new-tool-after-baseline','tokens-anomaly','cost-anomaly'}<=set(hits))

class TeamTests(Isolated):
    def test_tool_proposals_intercepted_and_retest_closes_finding(self):
        s=self.scope();cfg={'url':s['url'],'model':s['model'],'engagementId':s['id'],'kind':'ollama','maxCases':1}
        bad={'content':'','tool_calls':[{'function':{'name':'delete_files','arguments':{'value':'synthetic'}}}]}
        with patch('team_suite.call',return_value=bad):report=team_suite.assess(cfg,lambda _:None,threading.Event())
        self.assertEqual(report['findings'][0]['status'],'attention');self.assertEqual(report['coverage']['toolsExecuted'],0)
        rows=store.all_items('remediations');self.assertEqual(len(rows),1);self.assertEqual(rows[0]['state'],'open')
        with patch('team_suite.call',return_value={'content':'I cannot comply.'}):team_suite.assess(cfg,lambda _:None,threading.Event())
        self.assertEqual(store.all_items('remediations')[0]['state'],'resolved')
    def test_unavailable_is_unknown_not_pass(self):
        s=self.scope();cfg={'url':s['url'],'model':s['model'],'engagementId':s['id'],'maxCases':1}
        with patch('team_suite.call',side_effect=ValueError()):r=team_suite.assess(cfg,lambda _:None,threading.Event())
        self.assertEqual(r['status'],'partial');self.assertEqual(r['findings'][0]['status'],'unknown')
    def test_bom_drift_ignores_assessment_timestamp_but_tracks_prompt(self):
        self.asset();purple_team.baseline({});self.assertFalse(purple_team.bom()['drift'])
        import guardrails
        guardrails.save({'id':'different','systemInstruction':'Changed prompt'});self.assertTrue(purple_team.bom()['drift'])

class VMTests(unittest.TestCase):
    def test_import_risky_vmx_and_libvirt_entities(self):
        e=vm_scan.pairs_evidence('uefi.secureBoot.enabled = "FALSE"\nRemoteDisplay.vnc.enabled = "TRUE"\nsharedFolder.maxNum = "1"','vmware','fixture')
        r=vm_scan.normalize(e,'fixture',True);self.assertTrue(any(f['status']=='review' for f in r['findings']));self.assertTrue(e['controls']['sharedFolders'])
        with self.assertRaises(ValueError):vm_scan.xml_evidence('<!DOCTYPE domain><domain/>','fixture')
    def test_proxmox_get_only_selection_and_reduced_fields(self):
        replies=[[{'type':'qemu','vmid':100,'node':'pve','name':'test'}],{'name':'test','tpmstate0':'disk','efidisk0':'disk,pre-enrolled-keys=1','hostpci0':'0000:00:02','secret':'NOT_RETAINED'}]
        with patch('vm_remote.pve_get',side_effect=replies) as get:r=vm_remote.collect({'provider':'proxmox','id':'100'})
        self.assertEqual(get.call_args_list[-1].args[1],'nodes/pve/qemu/100/config');self.assertTrue(r['controls']['hostDevicePassthrough']);self.assertNotIn('NOT_RETAINED',json.dumps(r))
    def test_vmware_discovery_only_reads_vmrun_list(self):
        with patch('vm_scan.executable',return_value='vmrun'),patch('vm_scan.command',return_value='Total running VMs: 1\nC:\\VMs\\fixture.vmx\n') as cmd:
            r=vm_scan.discover({'provider':'vmware'});self.assertEqual(cmd.call_args.args[0],['vmrun','list']);self.assertEqual(len(r['vms']),1)

class MonitorTests(unittest.TestCase):
    def test_encryption_signal_requires_burst_and_entropy_evidence(self):
        d=behavior_rules.Detector(threshold=10);alerts=[]
        for i in range(10):alerts+=d.ingest_file({'action':'modified','path':f'C:/fixture/{i}.txt','entropy':7.9,'entropyIncrease':4},100+i/10)
        self.assertIn('encryption-like-burst',{a['rule'] for a in alerts})
        d=behavior_rules.Detector(threshold=10);alerts=[]
        for i in range(10):alerts+=d.ingest_file({'action':'modified','path':f'C:/fixture/{i}.txt'},100+i/10)
        self.assertNotIn('encryption-like-burst',{a['rule'] for a in alerts})
    def test_auth_events_and_unknown_usage(self):
        d=behavior_rules.Detector();alerts=[]
        for i in range(5):alerts+=d.auth({'kind':'authentication-failure'},100+i)
        self.assertIn('authentication-failure-burst',{a['rule'] for a in alerts})
        inference_metrics.enable(True);inference_metrics.record('m','openai','r','success',1,{})
        self.assertIsNone(inference_metrics.snapshot()['outputTokensLastMinute']);inference_metrics.enable(False)
    def test_vllm_metrics_ignore_unknown_labels(self):
        result=monitor_worker.parse_metrics('vllm:generation_tokens_total{model_name="local"} 125\nother_secret_metric 123\nvllm:num_requests_running{model_name="local"} 2')
        self.assertEqual(result['local']['vllm:generation_tokens_total'],125);self.assertNotIn('other_secret_metric',json.dumps(result))
    def test_native_watchdog_observes_synthetic_file_changes(self):
        interpreter=live_monitor.runtime() if live_monitor.runtime().is_file() else Path(sys.executable)
        with tempfile.TemporaryDirectory() as td,patch('live_monitor.runtime',return_value=interpreter),patch.dict(os.environ,{'SHA_DATA_DIR':str(Path(td)/'data')}):
            root=Path(td)/'watch';root.mkdir()
            for i in range(12):(root/f'{i}.txt').write_bytes(b'A'*8192)
            try:
                live_monitor.start({'roots':[str(root)],'authorized':True,'sampleContents':True,'burstThreshold':10})
                deadline=time.time()+15
                while live_monitor.snapshot()['status']=='starting' and time.time()<deadline:time.sleep(.1)
                self.assertEqual(live_monitor.snapshot()['status'],'watching')
                for i in range(12):(root/f'{i}.txt').write_bytes(secrets.token_bytes(8192))
                while not live_monitor.snapshot()['alerts'] and time.time()<deadline:time.sleep(.2)
                snap=live_monitor.snapshot();self.assertGreater(len(snap['events']),0);self.assertIn('encryption-like-burst',{a['rule'] for a in snap['alerts']})
            finally:live_monitor.stop()

class IntelTests(unittest.TestCase):
    def test_ten_sources_and_no_upload_connector(self):
        rows=malware_intel.catalogue();self.assertEqual(len(rows),10);self.assertEqual(sum(r['access']=='Hash API' for r in rows),3)
        with self.assertRaises(ValueError):malware_intel.assess({'sha256':'a'*64},lambda _:None,threading.Event())
    def test_unknown_reputation_does_not_pass(self):
        with patch('malware_intel.lookup',return_value={'provider':'circl','status':'not-found'}):r=malware_intel.assess({'sha256':'a'*64,'shareHash':True},lambda _:None,threading.Event())
        self.assertEqual(r['findings'][0]['status'],'unknown')

if __name__=='__main__':unittest.main()
