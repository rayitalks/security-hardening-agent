"""The Security Hardening Agent — local assessment console."""
import json
import os
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import collector
import engine
import skillspector_integration
import vulnerabilities
import containers
import model_tools
import model_weights
import model_behavior
import traffic
import actions
import agent_scanner
import asset_registry
import guardrails
import security_store
import runtime_gateway
import mcp_security
import redteam
import deployment_audits
import integrity_monitor
import vm_scan
import live_monitor
import malware_intel
import engagements
import audit_trail
import defense_ops
import team_suite
import purple_team
import pqc_tools
import scan_center

ROOT = Path(__file__).resolve().parent
PORT = 8765
ORIGIN = f'http://127.0.0.1:{PORT}'
TOKEN = secrets.token_urlsafe(32)
LOCK = threading.Lock()
STOP = threading.Event()
STATE = {'running': False, 'progress': 'Ready', 'report': None, 'error': None, 'cancellable': False}

def progress(message):
    with LOCK:
        STATE['progress'] = message

def job(kind, config):
    try:
        audit_trail.append('console','assessment-'+kind,'started',{k:v for k,v in config.items() if k not in ('key','token','password')})
        if kind == 'scan_batch':
            report = scan_center.assess(config, progress, STOP)
        elif kind == 'vm':
            report = vm_scan.assess(config, progress, STOP)
        elif kind == 'malware_intel':
            report = malware_intel.assess(config, progress, STOP)
        elif kind == 'team_suite':
            report = team_suite.assess(config, progress, STOP)
        elif kind == 'endpoint_check':
            report = engine.check_endpoint(config, progress, STOP)
        elif kind == 'validate':
            report = engine.assess(config, progress, STOP)
        elif kind == 'host':
            report = collector.collect()
            if os.environ.get('SHA_CONTAINER'):
                report['limitations'].insert(0, 'This evidence describes the container, not the Docker host. Run collector.py on the host and import its report for host hardening checks.')
                report['target'] = 'Container: ' + report['target']
        elif kind == 'code':
            report = engine.scan_code(config.get('path', ''))
        elif kind == 'artifacts':
            report = engine.scan_artifacts(config.get('path', ''))
        elif kind == 'skillspector':
            report = skillspector_integration.run(config, progress, STOP)
        elif kind == 'vulnerabilities':
            report = vulnerabilities.assess(config, progress, STOP)
        elif kind == 'containers':
            report = containers.assess(config, progress, STOP)
        elif kind == 'model_supply':
            report = model_tools.supply_chain(config, progress, STOP)
        elif kind == 'model_weights':
            report = model_weights.assess(config, progress, STOP)
        elif kind == 'model_behavior':
            report = model_behavior.assess(config, progress, STOP)
        elif kind == 'malware':
            report = model_tools.malware(config, progress, STOP)
        elif kind == 'traffic':
            report = traffic.assess(config, progress, STOP)
        elif kind == 'agent':
            report = agent_scanner.assess(config, progress, STOP)
        elif kind == 'redteam':
            report = redteam.assess(config, progress, STOP)
        elif kind == 'mcp':
            report = mcp_security.scan(config, progress, STOP)
        elif kind == 'deployment':
            report = deployment_audits.assess(config, progress, STOP)
        else:
            raise ValueError('Unknown assessment')
        if kind in ('redteam','validate','mcp'):
            for row in list(report.get('findings',[]))+list(report.get('tests',[])):
                row.setdefault('frameworkMapping',{'owaspLLM':['LLM01:2025'] if kind!='mcp' else ['LLM03:2025'],'owaspAgentic':['ASI01'] if kind!='mcp' else ['ASI04'],'mitreAtlas':['AML.T0051'],'note':'Broad assessment-family mapping; confirm relevance during finding triage.'})
        if kind in ('redteam','validate'):purple_team.ingest(report,config,kind)
        audit_trail.append('console','assessment-'+kind,report.get('status','complete'),report)
        with LOCK:
            STATE.update(report=report, progress='Assessment finished')
    except Exception as exc:
        with LOCK:
            STATE.update(error=str(exc), progress='Assessment could not complete')
    finally:
        config.pop('key', None)
        with LOCK:
            STATE['running'] = False

class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, *_):
        pass

    def respond(self, status, data, mime='application/json'):
        body = json.dumps(data).encode() if mime == 'application/json' else data.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', mime + '; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(body)

    def valid_host(self):
        return self.headers.get('Host') == f'127.0.0.1:{PORT}'

    def do_GET(self):
        if not self.valid_host():
            return self.respond(403, {'error': 'Use http://127.0.0.1:8765/.'})
        if self.path == '/':
            return self.respond(200, (ROOT / 'index.html').read_text(encoding='utf-8').replace('__TOKEN__', TOKEN), 'text/html')
        if self.path == '/monitor':
            return self.respond(200,(ROOT/'monitor.html').read_text(encoding='utf-8').replace('__TOKEN__',TOKEN),'text/html')
        if self.path == '/team-workspace.js':
            return self.respond(200,(ROOT/'team-workspace.js').read_text(encoding='utf-8'),'application/javascript')
        if self.path == '/model-assurance.js':
            return self.respond(200,(ROOT/'model-assurance.js').read_text(encoding='utf-8'),'application/javascript')
        if self.path == '/api/model-behavior/profile':
            return self.respond(200, model_behavior.builtin_profile())
        getters={'/api/live-monitor':live_monitor.snapshot,'/api/malware-intel/sources':malware_intel.catalogue,
                 '/api/engagements':lambda:security_store.all_items('engagements'),'/api/audit':audit_trail.snapshot,
                 '/api/defense':defense_ops.snapshot,'/api/team/corpus':team_suite.corpus,
                 '/api/purple':lambda:purple_team.snapshot(runtime_gateway.status()['running']),'/api/compliance':purple_team.compliance}
        if self.path in getters:
            try:return self.respond(200,getters[self.path]())
            except Exception:return self.respond(500,{'error':'Evidence unavailable. Check local data integrity and permissions.'})
        if self.path == '/api/state':
            with LOCK:
                return self.respond(200, STATE)
        if self.path == '/api/endpoint-providers':
            return self.respond(200, engine.inference_providers.catalog())
        if self.path == '/endpoint-providers.js':
            return self.respond(200, (ROOT / 'endpoint-providers.js').read_text(encoding='utf-8'), 'application/javascript')
        if self.path == '/api/environment':
            return self.respond(200, {'app': 'ray-i-security-hardening-agent', 'container': bool(os.environ.get('SHA_CONTAINER')), 'version': engine.VERSION, 'os': collector.platform.system()})
        if self.path == '/api/pqc/status':
            return self.respond(200, pqc_tools.status())
        if self.path == '/api/scan-center':
            return self.respond(200, scan_center.snapshot())
        if self.path == '/api/skillspector/status':
            return self.respond(200, skillspector_integration.status())
        if self.path == '/api/containers/status':
            return self.respond(200, containers.status())
        if self.path == '/api/model-tools/status':
            return self.respond(200, model_tools.status())
        if self.path == '/workspace.js':
            return self.respond(200, (ROOT / 'workspace.js').read_text(encoding='utf-8'), 'application/javascript')
        if self.path == '/api/assets':
            return self.respond(200, asset_registry.snapshot(runtime_gateway.status()['running']))
        if self.path == '/api/protection':
            return self.respond(200, {'gateway':runtime_gateway.status(), 'routes':runtime_gateway.routes(), 'redteam':redteam.catalogue()})
        if self.path == '/api/violations':
            return self.respond(200, security_store.events(1000))
        if self.path == '/api/monitors':
            return self.respond(200, {'monitors':[integrity_monitor.public(r) for r in security_store.all_items('monitors')], 'canaries':security_store.all_items('canaries')})
        return self.respond(404, {'error': 'Not found'})

    def do_POST(self):
        if not self.valid_host() or self.headers.get('Origin') != ORIGIN or not secrets.compare_digest(self.headers.get('X-App-Token', ''), TOKEN):
            return self.respond(403, {'error': 'Request rejected. Reload the local app.'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if length < 0 or length > 2_000_000:
                return self.respond(413, {'error': 'Request exceeds the 2 MB limit.'})
            config = json.loads(self.rfile.read(length) or b'{}')
            if not isinstance(config, dict):
                raise ValueError('Expected a JSON object.')
        except Exception:
            return self.respond(400, {'error': 'Invalid request body.'})
        operations = {
            '/api/scan-center/discover':scan_center.discover,
            '/api/scan-center/report':scan_center.saved_report,
            '/api/pqc/generate':pqc_tools.generate,
            '/api/vm/discover':vm_scan.discover,
            '/api/live-monitor/start':live_monitor.start,
            '/api/live-monitor/stop':lambda _:live_monitor.stop(),
            '/api/engagements/create':engagements.create,
            '/api/engagements/approve':engagements.approve,
            '/api/audit/configure':audit_trail.configure,
            '/api/audit/verify':audit_trail.verify,
            '/api/defense/token':defense_ops.mint,
            '/api/defense/revoke':defense_ops.revoke,
            '/api/defense/policy':defense_ops.configure,
            '/api/defense/approve':defense_ops.approve,
            '/api/defense/incident':defense_ops.incident,
            '/api/defense/memory-save':defense_ops.memory_save,
            '/api/defense/memory-restore':defense_ops.memory_restore,
            '/api/purple/test':purple_team.guardrail_test,
            '/api/purple/baseline':purple_team.baseline,
            '/api/assets/save':asset_registry.save,
            '/api/assets/discover':asset_registry.discover,
            '/api/assets/models':asset_registry.discover_models,
            '/api/assets/policy':asset_registry.assign,
            '/api/assets/report':asset_registry.attach_report,
            '/api/policies/save':guardrails.save,
            '/api/policies/preview':guardrails.preview,
            '/api/routes/save':runtime_gateway.save_route,
            '/api/routes/toggle':runtime_gateway.toggle_route,
            '/api/gateway/start':lambda _:runtime_gateway.start(),
            '/api/gateway/stop':lambda _:runtime_gateway.stop(),
            '/api/monitors/create':integrity_monitor.save,
            '/api/monitors/check':lambda c:integrity_monitor.check(c.get('id')),
            '/api/monitors/toggle':integrity_monitor.toggle,
            '/api/canaries/create':integrity_monitor.honey_create,
        }
        if self.path in operations:
            try:
                return self.respond(200, operations[self.path](config))
            except (ValueError, OSError) as exc:
                return self.respond(400, {'error': str(exc)[:400]})
            except Exception:
                return self.respond(500, {'error':'The operation could not complete. Check the selected input and local permissions.'})
            finally:
                config.pop('key',None)
                config.pop('passphrase',None)
        if self.path == '/api/discover':
            try:
                if config.get('authorized') is not True:
                    raise ValueError('Confirm that you are authorized to assess this endpoint.')
                return self.respond(200, engine.discover(config))
            except Exception as exc:
                return self.respond(400, {'error': str(exc)})
            finally:
                config.pop('key', None)
        if self.path == '/api/containers/discover':
            try:
                return self.respond(200, containers.discover())
            except Exception as exc:
                return self.respond(400, {'error': str(exc)})
        if self.path == '/api/cancel':
            STOP.set()
            return self.respond(200, {'ok': True})
        if self.path in ('/api/actions', '/api/traffic/interfaces'):
            try:
                return self.respond(200, actions.create(config) if self.path == '/api/actions' else traffic.interfaces())
            except Exception as exc:
                return self.respond(400, {'error': str(exc)})
        if self.path == '/api/run':
            kind = config.pop('assessment', '')
            if kind not in ('host', 'code', 'artifacts', 'validate', 'endpoint_check', 'skillspector', 'vulnerabilities', 'containers', 'model_supply', 'model_weights', 'model_behavior', 'malware', 'traffic', 'agent', 'redteam', 'mcp', 'deployment','vm','malware_intel','team_suite','scan_batch'):
                return self.respond(400, {'error': 'Unknown assessment.'})
            if kind == 'scan_batch':
                try:scan_center.validate(config)
                except ValueError as exc:return self.respond(400, {'error':str(exc)})
            if kind in ('validate','endpoint_check','redteam','team_suite','model_behavior'):
                try:engagements.require(config)
                except ValueError as exc:return self.respond(400,{'error':str(exc)})
            if kind in ('validate', 'endpoint_check', 'model_behavior') and config.get('authorized') is not True:
                return self.respond(400, {'error': 'Confirm that you are authorized to test this endpoint.'})
            if kind == 'containers' and config.get('authorized') is not True:
                return self.respond(400, {'error': 'Confirm that you are authorized to assess the selected container or image.'})
            if kind in ('code', 'artifacts') and not config.get('path', '').strip():
                return self.respond(400, {'error': 'Enter an absolute folder path.'})
            if kind == 'skillspector':
                try:
                    skillspector_integration.validate_input(config)
                except ValueError as exc:
                    return self.respond(400, {'error': str(exc)})
            with LOCK:
                if STATE['running']:
                    return self.respond(409, {'error': 'An assessment is already running.'})
                STOP.clear()
                STATE.update(running=True, progress='Starting assessment', error=None, report=None, cancellable=kind in ('validate','endpoint_check','skillspector','vulnerabilities','containers','model_supply','model_weights','model_behavior','malware','traffic','agent','redteam','mcp','deployment','vm','malware_intel','team_suite','scan_batch'))
            threading.Thread(target=job, args=(kind, config), daemon=True).start()
            return self.respond(202, {'ok': True})
        return self.respond(404, {'error': 'Not found'})

if __name__ == '__main__':
    address = '0.0.0.0' if os.environ.get('SHA_CONTAINER') == '1' else '127.0.0.1'
    server = ThreadingHTTPServer((address, PORT), Handler)
    integrity_monitor.start_scheduler()
    if '--open' in __import__('sys').argv:
        webbrowser.open(ORIGIN)
    print('The Security Hardening Agent: ' + ORIGIN, flush=True)
    server.serve_forever()
