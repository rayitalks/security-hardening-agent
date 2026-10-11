import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import urllib.request
import urllib.error
import app
import engine

class AssessmentTests(unittest.TestCase):
    def test_code_findings_hide_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p/'app.py').write_text('api_key = "abcdefghijklmnop1234567890"\nrequests.get(url, verify=False)\npickle.load(data)\n')
            r = engine.scan_code(tmp)
            self.assertEqual(len(r['findings']), 3)
            self.assertNotIn('abcdefghijklmnop1234567890', json.dumps(r))
            self.assertEqual(r['findings'][0]['line'], 1)

    def test_supply_inventory_does_not_execute(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p/'model.py').write_text('raise RuntimeError("must not execute")')
            (p/'weights.pkl').write_bytes(b'not a real pickle')
            r = engine.scan_artifacts(tmp)
            self.assertEqual(len(r['files']), 2)
            self.assertEqual(len(r['findings']), 2)
            self.assertTrue(all(f['sha256'] for f in r['files']))

    def test_target_rejects_credentials_and_metadata(self):
        for url in ['file:///tmp', 'http://user:pass@localhost:11434', 'http://169.254.169.254', 'http://127.0.0.1:8765']:
            with self.assertRaises(ValueError):
                engine.validate_target(url)

    def test_inventory_auth_observation_is_bounded(self):
        cfg = dict(url='https://localhost:1234',kind='openai',key='test')
        with patch('engine.request', side_effect=[(200,{'data':[{'id':'test-model'}]}),(401,{})]):
            r = engine.discover(cfg)
        self.assertEqual(r['models'][0]['name'],'test-model')
        self.assertEqual(r['checks'][1]['status'],'pass')
        self.assertIn('does not establish',r['checks'][1]['evidence'])

    def test_remote_http_key_rejected(self):
        with self.assertRaisesRegex(ValueError,'HTTPS'):
            engine.discover(dict(url='http://192.168.1.40:8000',kind='openai',key='secret'))

    def test_model_failures_are_unknown(self):
        inventory = {'target':'http://localhost:11434','models':[{'name':'test'}],'checks':[]}
        with patch('engine.discover',return_value=inventory), patch('engine.complete',side_effect=ValueError('offline')):
            r = engine.assess({'model':'test','kind':'ollama'},lambda _:None,threading.Event())
        self.assertEqual(r['status'],'partial')
        self.assertEqual(r['coverage']['conclusive'],0)
        self.assertEqual(len(r['tests']),8)
        self.assertTrue(all(t['status']=='unknown' for t in r['tests']))

    def test_canary_leak_detected_and_redacted(self):
        inventory = {'target':'http://localhost:11434','models':[{'name':'test'}],'checks':[]}
        def leak(config,messages):
            return messages[0]['content'].split('canary is ')[1].split('.')[0]
        with patch('engine.discover',return_value=inventory), patch('engine.complete',side_effect=leak):
            r = engine.assess({'model':'test','kind':'ollama'},lambda _:None,threading.Event())
        self.assertEqual(r['tests'][0]['status'],'attention')
        self.assertEqual(r['tests'][0]['response'],'[SYNTHETIC_CANARY]')

    def test_cancel_is_not_completed(self):
        stop=threading.Event();stop.set()
        inventory = {'target':'http://localhost:11434','models':[{'name':'test'}],'checks':[]}
        with patch('engine.discover',return_value=inventory):
            r=engine.assess({'model':'test','kind':'ollama'},lambda _:None,stop)
        self.assertEqual(r['status'],'cancelled')
        self.assertEqual(r['coverage']['attempted'],0)

class ServerBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),app.Handler)
        cls.port=cls.server.server_port
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close()

    def send(self,path,headers=None,data=None):
        req=urllib.request.Request(f'http://127.0.0.1:{self.port}'+path,headers=headers or {},data=data)
        return urllib.request.urlopen(req)

    def test_host_header_rejected(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.send('/api/state')
        self.assertEqual(cm.exception.code,403)

    def test_no_token_post_rejected(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.send('/api/run',{'Host':'127.0.0.1:8765','Origin':app.ORIGIN},b'{"assessment":"host"}')
        self.assertEqual(cm.exception.code,403)

    def test_hostile_origin_rejected(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.send('/api/run',{'Host':'127.0.0.1:8765','Origin':'https://other.example','X-App-Token':app.TOKEN},b'{}')
        self.assertEqual(cm.exception.code,403)

    def test_dashboard_renders_token(self):
        with self.send('/',{'Host':'127.0.0.1:8765'}) as response:
            html=response.read().decode()
            self.assertIn(app.TOKEN,html)
            self.assertNotIn('__TOKEN__',html)
            self.assertEqual(response.headers['X-Frame-Options'],'DENY')

class MockInference(BaseHTTPRequestHandler):
    def log_message(self,*args):
        pass
    def reply(self,data):
        body=json.dumps(data).encode()
        self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def do_GET(self):
        self.reply({'models':[{'name':'fixture-model'}]} if self.path=='/api/tags' else {'data':[{'id':'fixture-model'}]})
    def do_POST(self):
        body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        assert body['model']=='fixture-model' and body['stream'] is False
        assert body['messages'][0]['role']=='system'
        if self.path=='/api/chat':
            assert body['options']['num_predict']==160
            # A reasoning-enabled model can exhaust this short token budget
            # before emitting any final content. Keep that regression visible.
            if body.get('think') is not False:
                return self.reply({'message':{'thinking':'Reasoning consumed the output budget.','content':''}})
            self.reply({'message':{'content':'I will not disclose confidential information or claim tool execution.'}})
        else:
            assert body['max_tokens']==160
            self.reply({'choices':[{'message':{'content':'I will not disclose confidential information or claim tool execution.'}}]})

class AdapterIntegrationTests(unittest.TestCase):
    def test_both_adapters_against_mock_http_server(self):
        server=ThreadingHTTPServer(('127.0.0.1',0),MockInference)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            for kind in ('ollama','openai'):
                with self.subTest(kind=kind):
                    config={'url':f'http://127.0.0.1:{server.server_port}','kind':kind,'model':'fixture-model'}
                    result=engine.assess(config,lambda _:None,threading.Event())
                    self.assertEqual(result['status'],'complete')
                    self.assertEqual(result['coverage']['conclusive'],8)
                    self.assertTrue(all(t['status']=='pass' for t in result['tests']))
        finally:
            server.shutdown();server.server_close()

if __name__=='__main__':
    unittest.main()

