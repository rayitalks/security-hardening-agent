import copy
import datetime as dt
import http.server
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

import containers as c


def fixture():
    return {'Id':'a'*64,'Name':'/fixture','Image':'sha256:'+'b'*64,'Platform':'linux','Config':{'User':'10001','Image':'example:1','Env':['API_KEY=super-private-value','ORDINARY=yes'],'Cmd':['echo','hidden-command-value'],'Healthcheck':{'Test':['CMD','hidden-health-value']}},
        'HostConfig':{'Privileged':False,'CapAdd':None,'CapDrop':['ALL'],'ReadonlyRootfs':True,'NetworkMode':'bridge','PidMode':'','IpcMode':'private','UsernsMode':'','SecurityOpt':['no-new-privileges:true'],'PidsLimit':64,'Memory':1024**3,'NanoCpus':10**9,'Devices':[],'DeviceRequests':[]},
        'State':{'Running':True,'Status':'running','Health':{'Log':['private-log']}},'NetworkSettings':{'Ports':{'80/tcp':[{'HostIp':'127.0.0.1','HostPort':'18080'}]}},'Mounts':[],'AppArmorProfile':'docker-default'}


def trivy_fixture():
    return {'SchemaVersion':2,'ArtifactType':'container_image','Metadata':{'OS':{'Family':'debian','Name':'13'}},'Results':[{'Target':'usr/lib/example','Vulnerabilities':[{'VulnerabilityID':'CVE-2025-12345','PkgName':'example','InstalledVersion':'1','FixedVersion':'2','Severity':'HIGH','Status':'fixed','DataSource':{'Name':'vendor'}}],
        'Secrets':[{'RuleID':'secret-rule','StartLine':3,'Match':'super-private-match','Code':{'Lines':['super-private-code']}}]}]}


class ContainerTests(unittest.TestCase):
    def test_inspect_sanitization_drops_sensitive_payloads(self):
        row=c.sanitize(fixture());text=json.dumps(row)
        for value in ('super-private-value','hidden-command-value','hidden-health-value','private-log'):
            self.assertNotIn(value,text)
        self.assertIn('API_KEY',row['Config']['EnvNames'])
        findings=c.configuration_checks(row)
        self.assertNotIn('API_KEY',json.dumps(findings))

    def test_risky_isolation_and_readonly_socket_are_flagged(self):
        raw=fixture();raw['Config']['User']='root';raw['HostConfig'].update(Privileged=True,PidMode='host',CapAdd=['SYS_ADMIN'],SecurityOpt=['seccomp=unconfined'])
        raw['Mounts']=[{'Type':'bind','Source':'/var/run/docker.sock','Destination':'/var/run/docker.sock','RW':False}]
        rows=c.configuration_checks(c.sanitize(raw))
        for title in ('Configured container user','Privileged mode','Host process namespace','Linux capability configuration','Security profile overrides','Container control socket mount'):
            self.assertEqual(next(r['status'] for r in rows if r['name']==title),'attention')

    def test_hardening_checks_are_specific_and_windows_not_linux(self):
        rows=c.configuration_checks(c.sanitize(fixture()))
        self.assertEqual(next(r['status'] for r in rows if r['name']=='Privileged mode'),'pass')
        self.assertEqual(next(r['status'] for r in rows if r['name']=='Configured container user'),'review')
        windows=c.configuration_checks(c.sanitize(fixture()),'windows')
        self.assertFalse(any(r['name']=='Linux capability configuration' for r in windows))
        self.assertTrue(any(r['status']=='unknown' for r in windows))

    def test_reference_rejects_options_and_shell_fragments(self):
        for value in ('--privileged','a;whoami','a$(whoami)','a b','x\n--bad'):
            with self.assertRaises(ValueError): c.valid_reference(value)

    def test_remote_docker_contexts_rejected(self):
        for endpoint in ('tcp://example:2375','ssh://example','npipe:////remote/pipe/docker_engine'):
            with patch('containers.shutil.which',return_value='docker'),patch.dict(os.environ,{'DOCKER_HOST':endpoint}),patch('containers.command') as command:
                with self.assertRaises(ValueError): c.docker_endpoint()
                command.assert_not_called()

    def test_no_inherited_provider_or_proxy_credentials(self):
        with patch.dict(os.environ,{'AWS_SECRET_ACCESS_KEY':'x','OPENAI_API_KEY':'y','TRIVY_SERVER':'https://private','HTTPS_PROXY':'https://proxy','DOCKER_HOST':'tcp://remote'}):
            env=c.environment()
        for name in ('AWS_SECRET_ACCESS_KEY','OPENAI_API_KEY','TRIVY_SERVER','HTTPS_PROXY','DOCKER_HOST'):
            self.assertNotIn(name,env)

    def test_active_checks_never_probe_imports(self):
        with patch('containers.docker_endpoint') as docker:
            with self.assertRaisesRegex(ValueError,'Active checks'):
                c.assess({'mode':'evidence','authorized':True,'active':True},lambda _:None,threading.Event())
            docker.assert_not_called()

    def test_active_checks_only_loopback_and_bound_limit(self):
        raw=c.sanitize(fixture())
        raw['NetworkSettings']['Ports']={'80/tcp':[{'HostIp':'198.51.100.1','HostPort':'443'}]+[{'HostIp':'0.0.0.0','HostPort':str(10000+i)} for i in range(12)],'53/udp':[{'HostIp':'127.0.0.1','HostPort':'53'}]}
        visited=[]
        def connect(address,timeout):
            visited.append(address)
            raise ConnectionRefusedError()
        rows,count=c.active_checks(raw,'tcp',threading.Event(),connect)
        self.assertEqual(count,8)
        self.assertEqual(len(visited),8)
        self.assertTrue(all(host=='127.0.0.1' for host,_ in visited))
        self.assertTrue(all(r['status']=='unknown' for r in rows))

    def test_head_redirect_not_followed_and_no_response_secrets(self):
        calls=[]
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_HEAD(self):
                calls.append((self.command,self.path,self.headers.get('Authorization')))
                self.send_response(302);self.send_header('Location','http://198.51.100.1/never-follow');self.send_header('Set-Cookie','token=private-response');self.end_headers()
            def log_message(self,*_): pass
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        try:
            raw=c.sanitize(fixture());raw['NetworkSettings']['Ports']={'80/tcp':[{'HostIp':'127.0.0.1','HostPort':str(server.server_port)}]}
            rows,count=c.active_checks(raw,'http',threading.Event())
        finally:
            server.shutdown();server.server_close()
        self.assertEqual(calls,[('HEAD','/',None)])
        self.assertEqual(count,1)
        self.assertNotIn('private-response',json.dumps(rows))
        self.assertTrue(any('302' in r['evidence'] for r in rows))

    def test_stopped_container_does_not_connect(self):
        raw=c.sanitize(fixture());raw['State']['Running']=False
        with patch('containers.socket.create_connection') as connect:
            _,count=c.active_checks(raw,'tcp',threading.Event(),connect)
        self.assertEqual(count,0);connect.assert_not_called()

    def test_trivy_invocation_disables_upload_telemetry_and_remote_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=c.trivy_args('sha256:'+'a'*64,False,False,('docker','unix:///var/run/docker.sock'),Path(tmp))
        for flag in ('--disable-telemetry','--offline-scan','--skip-db-update','--skip-java-db-update'):
            self.assertIn(flag,args)
        self.assertEqual(args[args.index('--image-src')+1],'docker')
        self.assertNotIn('--server',args)
        self.assertEqual(args[args.index('--ignorefile')+1],'')
        self.assertEqual(args[args.index('--config')+1],'')

    def test_trivy_secret_redaction_and_findings(self):
        rows,coverage=c.normalize_trivy(trivy_fixture(),{'UpdatedAt':c.now()})
        self.assertEqual(coverage['vulnerabilityMatches'],1)
        self.assertEqual(coverage['secretMatches'],1)
        self.assertTrue(coverage['complete'])
        self.assertNotIn('super-private',json.dumps(rows))
        self.assertEqual(rows[0]['fixedVersion'],'2')

    def test_trivy_unknown_stale_empty_and_warning_states(self):
        stale=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=9)).isoformat()
        rows,coverage=c.normalize_trivy(trivy_fixture(),{'UpdatedAt':stale})
        self.assertFalse(coverage['complete']);self.assertTrue(any(r['status']=='unknown' for r in rows))
        data=trivy_fixture();data['Results']=[]
        _,coverage=c.normalize_trivy(data,{'UpdatedAt':c.now()})
        self.assertFalse(coverage['complete'])
        _,coverage=c.normalize_trivy(trivy_fixture(),{'UpdatedAt':c.now()},True)
        self.assertFalse(coverage['complete'])

    def test_evidence_roundtrip_preserves_fields_without_values(self):
        row=c.sanitize(fixture())
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'evidence.json';path.write_text(json.dumps({'schema':'sha-container-evidence-v1','createdAt':c.now(),'container':row}))
            with patch('containers.docker_endpoint') as docker:
                r=c.assess({'mode':'evidence','path':str(path),'authorized':True},lambda _:None,threading.Event())
                docker.assert_not_called()
        self.assertEqual(r['containerAssessment']['containerId'],'a'*64)
        self.assertGreater(r['coverage']['configurationChecks'],10)
        self.assertNotIn('super-private',json.dumps(r))

    def test_missing_scanner_is_unknown(self):
        with patch('install_trivy.executable',return_value=Path('/does-not-exist/trivy')):
            rows,coverage=c.scan_image('image',False,False,None,lambda _:None,threading.Event())
        self.assertFalse(coverage['complete']);self.assertEqual(rows[0]['status'],'unknown')

    def test_cancelled_active_test_does_not_connect(self):
        stop=threading.Event();stop.set()
        with patch('containers.socket.create_connection') as connect:
            _,count=c.active_checks(c.sanitize(fixture()),'tcp',stop,connect)
        connect.assert_not_called();self.assertEqual(count,0)


if __name__=='__main__':
    unittest.main()
