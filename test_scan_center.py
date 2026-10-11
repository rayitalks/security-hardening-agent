import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import scan_center as sc


class ScanCenterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {'SHA_DATA_DIR': self.temp.name})
        self.env.start()
        sc.CATALOGS.clear()
        sc.CURRENT = None
        self.agent = {'id': 'agent-1', 'name': 'Hermes', 'kind': 'agent', 'path': self.temp.name, 'available': True}
        self.drive = {'id': 'C:\\', 'name': 'C:\\', 'kind': 'drive', 'path': 'C:\\', 'available': True}
        sc.CATALOGS['known'] = {'time': time.monotonic(), 'targets': {'agent-1': self.agent, 'C:\\': self.drive}}
        self.config = {'authorized': True, 'discoveryId': 'known', 'targets': ['agent-1'], 'agentMode': 'deep', 'driveHours': 4}

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_wsl_mapping_and_root_traversal_rejection(self):
        self.assertEqual(sc.map_workspace('/home/rayi/project', 'Ubuntu', True), '\\\\wsl.localhost\\Ubuntu\\home\\rayi\\project')
        for value in ('/', '/etc', '/home/rayi/../../etc', '/home/rayi/evil\\path', 'relative', '\\\\evil\\share'):
            with self.assertRaises(ValueError):
                sc.map_workspace(value, 'Ubuntu', True)

    def test_selection_is_bound_to_discovery_and_authorization(self):
        for change in ({'authorized': False}, {'targets': ['elsewhere']}, {'targets': ['agent-1', 'agent-1']}, {'discoveryId': 'unknown'}, {'driveHours': 999}, {'driveHours': True}):
            with self.assertRaises(ValueError):
                sc.validate(dict(self.config, **change))
        sc.CATALOGS['known']['time'] -= 1900
        with self.assertRaises(ValueError):
            sc.validate(self.config)

    def test_discovery_projects_only_and_credentials_removed(self):
        cid = '11111111-1111-1111-1111-111111111111'
        aid = '22222222-2222-2222-2222-222222222222'
        secret = 'PRIVATE-SECRET-MUST-NOT-LEAVE-INVENTORY'
        rows = [{'id': aid, 'name': 'Hermes Operations', 'adapterType': 'codex_local', 'adapterConfig': {'cwd': self.temp.name, 'apiKey': secret, 'env': {'TOKEN': secret}}}]
        with patch.object(sc, 'read_local', side_effect=[[{'id': cid, 'name': 'Team'}], rows]), patch.object(sc, 'map_workspace', return_value=self.temp.name), patch.object(sc, 'fixed_drives', return_value=[]), patch.object(sc, 'defender_status', return_value={}):
            result = sc.discover({})
        self.assertEqual(result['agents'][0]['adapter'], 'codex_local')
        self.assertNotIn(secret, json.dumps(result))
        self.assertTrue(result['agents'][0]['available'])

    def test_no_external_discovery_or_shell_options(self):
        with patch.object(sc, 'read_local') as read:
            for value in ({'port': 'https://remote'}, {'port': 70000}, {'distribution': 'Ubuntu;cmd'}, {'distribution': '..\\host'}):
                with self.assertRaises(ValueError):
                    sc.discover(value)
            read.assert_not_called()

    def test_batch_is_offline_and_survives_reload(self):
        result = {'status': 'complete', 'findings': [{'name': 'Test', 'status': 'review', 'evidence': 'Evidence', 'recommendation': 'Review'}]}
        with patch.object(sc.agent_scanner, 'assess', return_value=result) as scanner:
            report = sc.assess(self.config, lambda _: None, threading.Event())
        self.assertEqual(report['status'], 'complete')
        cfg = scanner.call_args.args[0]
        self.assertIs(cfg['online'], False)
        self.assertIs(cfg['semantic'], False)
        sc.CURRENT = None
        self.assertEqual(sc.saved_report({'id': report['id']})['coverage']['finished'], 1)
        self.assertEqual(len(sc.snapshot()['history']), 1)

    def test_cancellation_skips_targets(self):
        stop = threading.Event()
        stop.set()
        with patch.object(sc.agent_scanner, 'assess') as scanner:
            report = sc.assess(self.config, lambda _: None, stop)
        scanner.assert_not_called()
        self.assertEqual(report['status'], 'cancelled')
        self.assertEqual(report['batchAssessment']['targets'][0]['status'], 'not-run')

    def test_scanner_failure_is_not_clean(self):
        with patch.object(sc.agent_scanner, 'assess', side_effect=ValueError('secret raw exception')):
            report = sc.assess(self.config, lambda _: None, threading.Event())
        self.assertEqual(report['status'], 'partial')
        self.assertEqual(report['batchAssessment']['targets'][0]['status'], 'failed')
        self.assertNotIn('secret raw exception', json.dumps(report))

    def test_drive_halt_skips_remaining_targets(self):
        cfg = dict(self.config, targets=['C:\\', 'agent-1'])
        with patch.object(sc, 'antivirus_drive', return_value={'status': 'partial', 'haltQueue': True, 'findings': []}), patch.object(sc.agent_scanner, 'assess') as scanner:
            report = sc.assess(cfg, lambda _: None, threading.Event())
        scanner.assert_not_called()
        self.assertEqual(report['batchAssessment']['targets'][1]['status'], 'not-run')
        self.assertEqual(report['status'], 'partial')

    def test_drive_removed_does_not_launch(self):
        with patch.object(sc, 'fixed_drives', return_value=[]), patch.object(sc.subprocess, 'Popen') as launch:
            with self.assertRaises(ValueError):
                sc.antivirus_drive(self.drive, 4, lambda _: None, threading.Event())
            launch.assert_not_called()

    def test_defender_arguments_and_error_ambiguity(self):
        class Process:
            returncode = 2
            def poll(self): return self.returncode
            def wait(self): return self.returncode
        def launch(args, **kwargs):
            self.assertIn('-DisableRemediation', args)
            self.assertEqual(args[1:], ['-Scan', '-ScanType', '3', '-File', 'C:\\', '-DisableRemediation'])
            self.assertIs(kwargs['shell'], False)
            kwargs['stdout'].write(b'Scan failed 0x80070005\n')
            return Process()
        with patch.object(sc, 'fixed_drives', return_value=[self.drive]), patch.object(sc, 'defender_binary', return_value=Path('MpCmdRun.exe')), patch.object(sc.subprocess, 'Popen', side_effect=launch):
            result = sc.antivirus_drive(self.drive, 4, lambda _: None, threading.Event())
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['hresults'], ['0x80070005'])
        self.assertFalse(any(f['status'] == 'pass' for f in result['findings']))

    def test_findings_cap_is_explicit(self):
        result = {'status': 'complete', 'findings': [{'name': 'n', 'status': 'review', 'evidence': 'e'}] * 300}
        with patch.object(sc.agent_scanner, 'assess', return_value=result):
            report = sc.assess(self.config, lambda _: None, threading.Event())
        self.assertEqual(len(report['findings']), sc.MAX_FINDINGS)
        self.assertEqual(report['coverage']['omittedFindings'], 300-sc.MAX_FINDINGS)
        self.assertEqual(report['status'], 'partial')

    def test_prior_process_batch_marked_interrupted(self):
        report = {'id': 'a'*32, 'createdAt': sc.containers.now(), 'status': 'running', 'target': 'test', 'coverage': {}, 'findings': [], 'limitations': [], 'batchAssessment': {'targets': []}}
        sc._save(report)
        sc.CURRENT = None
        self.assertEqual(sc.snapshot()['history'][0]['status'], 'interrupted')
        self.assertEqual(sc.saved_report({'id': 'a'*32})['status'], 'interrupted')


if __name__ == '__main__':
    unittest.main()
