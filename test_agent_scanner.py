import tempfile
import threading
import unittest
from unittest.mock import patch

import agent_scanner

def report(status='complete'):
    return {'status':status,'findings':[{'name':'Example finding','status':'review','evidence':'example','recommendation':'Inspect locally'}],'limitations':['Limited coverage']}

class AgentScannerTests(unittest.TestCase):
    def test_standard_never_enables_online_or_semantic(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(agent_scanner.skillspector_integration,'run',return_value=report()) as skill,patch.object(agent_scanner.vulnerabilities,'assess') as cve:
            result=agent_scanner.assess({'path':folder,'mode':'standard','online':True,'semantic':True},lambda _:None,threading.Event())
            self.assertFalse(skill.call_args.args[0]['semantic']);cve.assert_not_called()
            self.assertEqual(result['agentAssessment']['stagesFinished'],1)
    def test_deep_keeps_other_results_when_one_engine_fails(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(agent_scanner.skillspector_integration,'run',side_effect=RuntimeError('secret diagnostic')),patch.object(agent_scanner.engine,'scan_code',return_value=report()),patch.object(agent_scanner.engine,'scan_artifacts',return_value=report()),patch.object(agent_scanner.vulnerabilities,'assess',return_value=report()) as cve:
            result=agent_scanner.assess({'path':folder,'mode':'deep','online':False},lambda _:None,threading.Event())
            self.assertEqual(result['status'],'partial');self.assertEqual(result['agentAssessment']['stagesFinished'],4)
            self.assertFalse(cve.call_args.args[0]['online']);self.assertNotIn('secret diagnostic',str(result))
            self.assertEqual(len(result['findings']),4)
    def test_cancel_preserves_completed_stage(self):
        stop=threading.Event()
        def first(*args):stop.set();return report()
        with tempfile.TemporaryDirectory() as folder,patch.object(agent_scanner.skillspector_integration,'run',side_effect=first),patch.object(agent_scanner.engine,'scan_code') as code:
            result=agent_scanner.assess({'path':folder,'mode':'deep'},lambda _:None,stop)
            self.assertEqual(result['status'],'cancelled');self.assertEqual(result['agentAssessment']['stagesFinished'],1);code.assert_not_called()
    def test_remote_and_missing_target_rejected(self):
        for target in ('https://github.com/example/agent',''):
            with self.assertRaises(ValueError):agent_scanner.assess({'path':target},lambda _:None,threading.Event())
    def test_invalid_semantic_endpoint_rejected_before_scanning(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(agent_scanner.skillspector_integration,'run') as scan:
            with self.assertRaises(ValueError):agent_scanner.assess({'path':folder,'mode':'deep','semantic':True,'endpoint':'https://cloud.example','model':'test'},lambda _:None,threading.Event())
            scan.assert_not_called()

if __name__=='__main__':unittest.main()
