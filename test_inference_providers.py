"""Protocol regressions use local fixtures only; no installed engine is probed."""
import json
import os
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import engine
import inference_providers as providers
import test_app
import app
import engagements
import asset_registry
import runtime_gateway
import integrity_monitor
import urllib.request
import urllib.error


class ProfileTests(unittest.TestCase):
    def test_catalog_profiles_and_proxy_paths(self):
        self.assertEqual(len(providers.PROFILES), 22)
        for selected in providers.PROFILES:
            kind = selected['id']
            with self.subTest(kind=kind):
                self.assertTrue(selected['docs'].startswith('https://'))
                self.assertEqual(providers.profile(kind), selected)
                expected = ('/api/tags', '/api/chat') if kind == 'ollama' else ('/v1/models', '/v1/chat/completions')
                self.assertEqual(engine.api_paths(kind, 'http://localhost:8000/proxy/'), expected)
                expected = ('/tags', '/chat') if kind == 'ollama' else ('/models', '/chat/completions')
                suffix = '/api/' if kind == 'ollama' else '/v1/'
                self.assertEqual(engine.api_paths(kind, 'http://localhost:8000/proxy' + suffix), expected)

    def test_bad_profile_and_full_request_urls_rejected(self):
        for kind in ('unknown', None, [], 'triton-native'):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                engine.api_paths(kind, 'http://localhost:8000')
        for suffix in ('/v1/models', '/v1/chat/completions', '/generate', '/info'):
            with self.assertRaisesRegex(ValueError, 'base URL'):
                engine.api_paths('vllm', 'http://localhost:8000' + suffix)

    def test_native_ollama_does_not_double_api_prefix(self):
        self.assertEqual(engine.api_paths('ollama', 'http://localhost:11434/api'), ('/tags', '/chat'))
        with self.assertRaises(ValueError):
            engine.api_paths('ollama', 'http://localhost:11434/v1')

    def test_every_profile_keeps_remote_credentials_off_http(self):
        for selected in providers.PROFILES:
            cfg = dict(kind=selected['id'], url='http://192.0.2.1:8000', key='fixture-secret', model='fixture')
            with self.subTest(kind=cfg['kind']), patch('engine.request') as request:
                for operation in (lambda: engine.discover(cfg), lambda: engine.complete(cfg, [])):
                    with self.assertRaisesRegex(ValueError, 'HTTPS'):
                        operation()
                request.assert_not_called()


class InventoryTests(unittest.TestCase):
    cfg = dict(kind='vllm', url='http://localhost:8000/prefix/v1')

    def test_inventory_ids_exact_deduplicated_and_bounded(self):
        long_id = 'a' * 301
        rows = [{'id': 'base/model'}, {'id': 'adapter/LoRA'}, {'id': 'base/model'},
                {'id': long_id}, {'id': 'bad\nname'}, {'name': 'wrong-field'}, {'id': ''}, None]
        with patch('engine.request', return_value=(200, {'data': rows})) as request:
            result = engine.discover(self.cfg)
        self.assertEqual([m['name'] for m in result['models']], ['base/model', 'adapter/LoRA'])
        self.assertEqual(result['coverage']['omittedModels'], 5)
        self.assertFalse(result['coverage']['inferenceTested'])
        request.assert_called_once_with(self.cfg['url'], '/models', '', timeout=12)
        self.assertNotIn(long_id, json.dumps(result))

    def test_malformed_inventories_fail_closed(self):
        for payload in ([], None, 'html', {}, {'data': {}}, {'error': 'bad'}):
            with self.subTest(payload=payload), patch('engine.request', return_value=(200, payload)):
                with self.assertRaises(ValueError):
                    engine.discover(self.cfg)

    def test_empty_and_large_inventories_are_explicit(self):
        for count in (0, 201):
            with patch('engine.request', return_value=(200, {'data': [{'id': str(n)} for n in range(count)]})):
                result = engine.discover(self.cfg)
            self.assertEqual(len(result['models']), min(200, count))
            self.assertEqual(result['checks'][-1]['status'], 'unknown')

    def test_tgi_info_fallback_preserves_prefix_and_actual_identity(self):
        cfg = dict(self.cfg, kind='tgi', key='fixture-key')
        responses = [(404, {}), (200, {'model_id': 'organization/model'}), (401, {})]
        with patch('engine.request', side_effect=responses) as request:
            result = engine.discover(cfg)
        self.assertEqual(result['models'][0]['name'], 'organization/model')
        self.assertEqual(result['coverage']['inventoryUrl'], 'http://localhost:8000/prefix/info')
        self.assertTrue(result['coverage']['fallbackUsed'])
        self.assertEqual(request.call_args_list[1].args, ('http://localhost:8000/prefix', '/info', 'fixture-key'))
        self.assertEqual(request.call_args_list[2].args, ('http://localhost:8000/prefix', '/info'))
        self.assertNotIn('fixture-key', json.dumps(result))

    def test_no_fallback_on_auth_errors_or_other_engines(self):
        for kind, code in [('tgi', 401), ('tgi', 403), ('tgi', 500), ('vllm', 404)]:
            with patch('engine.request', return_value=(code, {})) as request:
                with self.assertRaises(ValueError):
                    engine.discover(dict(self.cfg, kind=kind))
            self.assertEqual(request.call_count, 1)

    def test_unauth_probe_failure_does_not_erase_authenticated_inventory(self):
        with patch('engine.request', side_effect=[(200, {'data': [{'id': 'fixture'}]}), ValueError('failed')]):
            result = engine.discover(dict(self.cfg, key='fixture-key'))
        self.assertEqual(result['models'][0]['name'], 'fixture')
        self.assertEqual(result['checks'][1]['status'], 'unknown')


class InferenceTests(unittest.TestCase):
    cfg = dict(kind='vllm', url='http://localhost:8000/v1', model='fixture')

    def test_malformed_empty_reasoning_and_tool_responses_inconclusive(self):
        bodies = [[], {}, {'choices': []}, {'choices': [{'message': {'content': ''}}]},
                  {'choices': [{'message': {'reasoning_content': 'private', 'content': None}}]},
                  {'choices': [{'message': {'content': 'text', 'tool_calls': [{'id': 'x'}]}}]},
                  {'choices': [{'message': {'content': 'x' * 16001}}]}]
        for body in bodies:
            with patch('engine.request', return_value=(200, body)):
                with self.assertRaises(ValueError):
                    engine.complete(self.cfg, [])

    def test_compatibility_check_one_call_no_safety_verdict(self):
        inventory = {'target': self.cfg['url'], 'kind': 'vllm', 'provider': providers.profile('vllm'),
                     'models': [{'name': 'fixture'}], 'checks': []}
        with patch('engine.discover', return_value=inventory), patch('engine.complete', return_value='READY') as complete:
            result = engine.check_endpoint(self.cfg, lambda _: None, threading.Event())
        self.assertEqual(result['coverage'], {'planned': 1, 'attempted': 1, 'conclusive': 1})
        self.assertEqual(result['status'], 'complete')
        self.assertIn('not a safety verdict', result['findings'][0]['evidence'])
        self.assertEqual(complete.call_count, 1)

    def test_compatibility_failure_cancel_and_wrong_model(self):
        inventory = {'target': self.cfg['url'], 'kind': 'vllm', 'provider': providers.profile('vllm'),
                     'models': [{'name': 'fixture'}], 'checks': []}
        with patch('engine.discover', return_value=inventory), patch('engine.complete', side_effect=ValueError('HTTP 503')) as complete:
            result = engine.check_endpoint(self.cfg, lambda _: None, threading.Event())
            self.assertEqual(result['status'], 'partial')
            self.assertEqual(result['findings'][0]['status'], 'unknown')
            complete.reset_mock()
            stop = threading.Event(); stop.set()
            result = engine.check_endpoint(self.cfg, lambda _: None, stop)
            self.assertEqual(result['status'], 'cancelled')
            complete.assert_not_called()
            with self.assertRaisesRegex(ValueError, 'Discover'):
                engine.check_endpoint(dict(self.cfg, model='invented'), lambda _: None, threading.Event())

    def test_all_profiles_over_real_http(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), test_app.MockInference)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            for selected in providers.PROFILES:
                with self.subTest(kind=selected['id']):
                    cfg = dict(kind=selected['id'], url=f'http://127.0.0.1:{server.server_port}', model='fixture-model')
                    result = engine.assess(cfg, lambda _: None, threading.Event())
                    self.assertEqual(result['status'], 'complete')
                    self.assertEqual(result['coverage']['conclusive'], 8)
                    self.assertEqual(result['provider']['id'], selected['id'])
        finally:
            server.shutdown(); server.server_close()


class SharedIntegrationTests(unittest.TestCase):
    def test_named_profiles_in_registered_assets_routes_and_canaries(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'SHA_DATA_DIR': directory}):
            for selected in providers.PROFILES:
                with self.subTest(kind=selected['id']):
                    asset = asset_registry.save(dict(name='fixture', kind='model', target='http://localhost:8000',
                                                     model='fixture', transport=selected['id']))
                    result = runtime_gateway.save_route(dict(assetId=asset['id'], provider=selected['id'], authorized=True))
                    self.assertEqual(result['route']['provider'], selected['id'])
                    with patch('integrity_monitor.behavior', return_value={'files': {'fixture': 'digest'}, 'gaps': []}):
                        monitor = integrity_monitor.save(dict(name='fixture', kind='behavior', provider=selected['id'],
                                                                url='http://localhost:8000', model='fixture', authorized=True))
                    self.assertEqual(monitor['provider'], selected['id'])
                    self.assertFalse(monitor['enabled'])


class EndpointApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), app.Handler)
        cls.base = f'http://127.0.0.1:{cls.server.server_port}'
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close()

    def call(self, path, payload=None, token=True, origin=None):
        headers = {'Host': '127.0.0.1:8765', 'Origin': origin or app.ORIGIN, 'Content-Type': 'application/json'}
        if token: headers['X-App-Token'] = app.TOKEN
        request = urllib.request.Request(self.base + path, headers=headers,
                                         data=json.dumps(payload).encode() if payload is not None else None)
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as response:
            with response:
                return response.code, json.load(response)

    def test_catalog_available_and_discovery_protected(self):
        code, result = self.call('/api/endpoint-providers')
        self.assertEqual(code, 200)
        self.assertEqual(len(result['providers']), 22)
        cfg = dict(kind='vllm', url='http://localhost:8000')
        with patch('engine.request') as request:
            self.assertEqual(self.call('/api/discover', cfg, token=False)[0], 403)
            self.assertEqual(self.call('/api/discover', cfg, origin='https://example.invalid')[0], 403)
            self.assertEqual(self.call('/api/discover', cfg)[0], 400)
            request.assert_not_called()

    def test_compatibility_requires_exact_scope_and_stays_single_job(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'SHA_DATA_DIR': directory}):
            cfg = dict(assessment='endpoint_check', kind='vllm', url='http://localhost:8000/v1', model='fixture', authorized=True)
            with patch('engine.check_endpoint') as check:
                self.assertEqual(self.call('/api/run', cfg)[0], 400)
                scope = engagements.create(cfg)
                cfg['engagementId'] = scope['id']
                self.assertEqual(self.call('/api/run', dict(cfg, model='other'))[0], 400)
                self.assertEqual(self.call('/api/run', dict(cfg, authorized=False))[0], 400)
                production = engagements.create(dict(cfg, environment='production'))
                self.assertEqual(self.call('/api/run', dict(cfg, engagementId=production['id']))[0], 400)
                with patch.dict(app.STATE, {'running': True}):
                    self.assertEqual(self.call('/api/run', cfg)[0], 409)
                check.assert_not_called()
            with patch('engine.check_endpoint', return_value={'type': 'endpoint-compatibility', 'status': 'complete'}) as check:
                code, _ = self.call('/api/run', cfg)
                self.assertEqual(code, 202)
                for _ in range(100):
                    if not app.STATE['running']: break
                    time.sleep(.02)
                self.assertFalse(app.STATE['running'])
                self.assertEqual(app.STATE['report']['type'], 'endpoint-compatibility')
                check.assert_called_once()


if __name__ == '__main__':
    unittest.main()
