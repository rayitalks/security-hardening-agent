"""Read-only Paperclip workspace discovery and explicit multi-target scan jobs."""
import ctypes
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import subprocess
import tempfile
import threading
import time
import uuid

import agent_scanner
import containers
import engine
import security_store

LOCK = threading.Lock()
CATALOGS = {}
CURRENT = None
MAX_FINDINGS = 180
ID = re.compile(r'[a-fA-F0-9-]{36}')


def text(value, limit=500):
    return str(value or '')[:limit]


def read_local(port, path):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=4)
    try:
        connection.request('GET', path, headers={'Accept': 'application/json'})
        response = connection.getresponse()
        raw = response.read(2_000_001)
        if response.status != 200 or len(raw) > 2_000_000:
            raise ValueError('Paperclip did not return accessible, bounded inventory. Check that the local service is running and permits this read.')
        value = json.loads(raw)
        if not isinstance(value, list):
            raise ValueError('Unsupported Paperclip inventory response.')
        return value
    finally:
        connection.close()


def map_workspace(value, distribution, windows=None):
    windows = os.name == 'nt' if windows is None else windows
    if not isinstance(value, str) or not value or len(value) > 1500 or any(ord(c) < 32 for c in value):
        raise ValueError('Missing or invalid workspace path.')
    if value.startswith('/'):
        parts = PurePosixPath(value).parts
        if len(parts) < 4 or parts[1] != 'home' or '..' in parts or '\\' in value:
            raise ValueError('Only explicit project paths below a Linux home directory are mapped automatically.')
        if windows:
            return '\\\\wsl.localhost\\' + distribution + '\\' + '\\'.join(parts[1:])
        return value
    if windows and re.fullmatch(r'[A-Za-z]:[\\/].+', value) and '..' not in re.split(r'[\\/]', value):
        return value
    raise ValueError('This workspace cannot be mapped on the current host.')


def fixed_drives():
    if os.name != 'nt' or os.environ.get('SHA_CONTAINER'):
        return []
    api = ctypes.windll.kernel32
    mask = api.GetLogicalDrives()
    result = []
    for n in range(26):
        root = chr(65 + n) + ':\\'
        if mask & (1 << n) and api.GetDriveTypeW(ctypes.c_wchar_p(root)) == 3:
            result.append({'id': root, 'path': root, 'name': root, 'kind': 'drive', 'available': Path(root).is_dir()})
    return result


def defender_binary():
    if os.name != 'nt':
        return None
    base = Path(os.environ.get('ProgramData', r'C:\ProgramData')) / 'Microsoft/Windows Defender/Platform'
    versions = sorted((p for p in base.glob('*') if re.fullmatch(r'[0-9.]+-\d+', p.name)),
                      key=lambda p: tuple(int(v) for v in re.findall(r'\d+', p.name)), reverse=True)
    candidates = [p / 'MpCmdRun.exe' for p in versions]
    candidates.append(Path(os.environ.get('ProgramFiles', r'C:\Program Files')) / 'Windows Defender/MpCmdRun.exe')
    return next((p for p in candidates if p.is_file()), None)


def defender_status():
    binary = defender_binary()
    result = {'available': bool(binary), 'mode': 'unknown', 'serviceEnabled': None,
              'antivirusEnabled': None, 'elevated': False, 'signatureUpdated': None}
    if not binary:
        return result
    result['elevated'] = bool(ctypes.windll.shell32.IsUserAnAdmin())
    ps = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    command = "$s=Get-MpComputerStatus -ErrorAction Stop; [pscustomobject]@{mode=$s.AMRunningMode;serviceEnabled=$s.AMServiceEnabled;antivirusEnabled=$s.AntivirusEnabled;signatureUpdated=$s.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o')} | ConvertTo-Json -Compress"
    try:
        code, raw, _ = containers.command([str(ps), '-NoProfile', '-NonInteractive', '-Command', command], timeout=15)
        if code == 0:
            data = json.loads(raw.decode('utf-8-sig'))
            result.update({k: data.get(k) for k in ('mode', 'serviceEnabled', 'antivirusEnabled', 'signatureUpdated')})
    except (OSError, ValueError):
        pass
    return result


def discover(config):
    port = config.get('port', 3100)
    distro = config.get('distribution', 'Ubuntu')
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('Enter a valid local Paperclip port.')
    if not isinstance(distro, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', distro):
        raise ValueError('Enter the exact WSL distribution name.')
    agents, warnings = [], []
    try:
        companies = read_local(port, '/api/companies')
        if len(companies) > 10:
            warnings.append('Only the first 10 companies were discovered.')
        for company in companies[:10]:
            cid = company.get('id') if isinstance(company, dict) else None
            if not isinstance(cid, str) or not ID.fullmatch(cid):
                continue
            rows = read_local(port, '/api/companies/' + cid + '/agents')
            if len(rows) > 200:
                warnings.append('A company exceeds the 200-agent discovery limit.')
            for row in rows[:200]:
                if not isinstance(row, dict) or not isinstance(row.get('id'), str) or not ID.fullmatch(row['id']):
                    continue
                adapter = text(row.get('adapterType'), 100)
                name = text(row.get('name'), 150)
                if 'hermes' not in adapter.lower() and 'hermes' not in name.lower():
                    continue
                cfg = row.get('adapterConfig') if isinstance(row.get('adapterConfig'), dict) else {}
                item = {'id': cid + ':' + row['id'], 'company': text(company.get('name'), 100), 'name': name,
                        'adapter': adapter, 'sourcePath': text(cfg.get('cwd'), 1500), 'kind': 'agent', 'available': False}
                try:
                    item['path'] = map_workspace(cfg.get('cwd'), distro)
                    path = Path(item['path'])
                    item['available'] = path.is_dir() and not path.is_symlink()
                    if not item['available']:
                        item['reason'] = 'Workspace is missing, inaccessible, or a symlink.'
                except (ValueError, OSError) as exc:
                    item['reason'] = text(exc, 200)
                agents.append(item)
    except (OSError, ValueError, http.client.HTTPException):
        warnings.append('Paperclip inventory could not complete. Check local port, access, and WSL availability; earlier discovered rows remain visible.')
    if len(agents) > 64:
        agents = agents[:64]
        warnings.append('Discovery is limited to 64 matching agents; narrow the Paperclip instance for remaining agents.')
    drives = fixed_drives()
    identity = secrets.token_urlsafe(24)
    result = {'discoveryId': identity, 'createdAt': containers.now(), 'agents': agents, 'drives': drives,
              'antivirus': defender_status(), 'warnings': warnings,
              'limits': 'Matching Hermes adapters and named Hermes agents; configured workspaces only. Shared runtime, global skills, mounted VM/WSL filesystem contents and every agent deployment are not automatically covered.'}
    with LOCK:
        now = time.monotonic()
        for key in list(CATALOGS):
            if now - CATALOGS[key]['time'] > 1800:
                del CATALOGS[key]
        if len(CATALOGS) >= 8:
            del CATALOGS[next(iter(CATALOGS))]
        CATALOGS[identity] = {'time': now, 'targets': {x['id']: dict(x) for x in agents + drives}}
    return result


def validate(config):
    requested = config.get('targets')
    if config.get('authorized') is not True:
        raise ValueError('Confirm authorization for the selected agent folders and drives.')
    if not isinstance(requested, list) or not requested or len(requested) > 90 or any(not isinstance(x, str) for x in requested) or len(set(requested)) != len(requested):
        raise ValueError('Select one or more unique discovered targets.')
    hours = config.get('driveHours', 4)
    if type(hours) is not int or hours not in (1, 4, 12):
        raise ValueError('Select a 1, 4, or 12 hour maximum per drive.')
    mode = config.get('agentMode', 'deep')
    if mode not in ('standard', 'deep'):
        raise ValueError('Choose standard or deep agent inspection.')
    with LOCK:
        cached = CATALOGS.get(config.get('discoveryId', ''))
        if not cached or time.monotonic() - cached['time'] > 1800:
            raise ValueError('Discovery expired. Refresh targets and review the selection.')
        if any(x not in cached['targets'] for x in requested):
            raise ValueError('A selected target was not present in this discovery.')
        targets = [dict(cached['targets'][x]) for x in requested]
    for row in targets:
        if not row.get('available'):
            raise ValueError('A selected target is unavailable; refresh and review the selection.')
    return targets, mode, hours


def _save(report):
    while len(json.dumps(report, ensure_ascii=True)) > 900_000 and report['findings']:
        report['findings'].pop()
        report['coverage']['omittedFindings'] += 1
    security_store.put('scan_batch_reports', report)
    security_store.put('scan_batch_index', {k: report[k] for k in ('id', 'createdAt', 'status', 'target', 'coverage')})
    global CURRENT
    with LOCK:
        CURRENT = {'id': report['id'], 'status': report['status'], 'rows': [dict(r) for r in report['batchAssessment']['targets']]}


def snapshot():
    with LOCK:
        active = dict(CURRENT) if CURRENT else None
    history = sorted(security_store.all_items('scan_batch_index'), key=lambda r: r['createdAt'], reverse=True)[:20]
    for row in history:
        if row['status'] == 'running' and (not active or row['id'] != active['id']):
            row['status'] = 'interrupted'
    return {'current': active, 'history': history}


def saved_report(config):
    identity = config.get('id', '')
    if not isinstance(identity, str) or not re.fullmatch('[a-f0-9]{32}', identity):
        raise ValueError('Select a saved batch report.')
    report = security_store.get('scan_batch_reports', identity)
    if report is None:
        raise ValueError('Saved report is unavailable.')
    with LOCK:
        active_id = CURRENT['id'] if CURRENT else None
    if report['status'] == 'running' and report['id'] != active_id:
        report['status'] = 'interrupted'
        report['limitations'].append('The app process ended before this batch completed. Remaining targets were not verified.')
    return report


def antivirus_drive(row, hours, progress, stop):
    if row['path'] not in {r['path'] for r in fixed_drives()}:
        raise ValueError('This drive is no longer an available fixed drive.')
    binary = defender_binary()
    if not binary:
        raise ValueError('Microsoft Defender command-line scanner is unavailable.')
    args = [str(binary), '-Scan', '-ScanType', '3', '-File', row['path'], '-DisableRemediation']
    started = time.monotonic()
    # Keep native detection output as bounded evidence: with DisableRemediation,
    # Defender does not put those detections in its normal UI/history.
    with tempfile.TemporaryFile() as output:
        proc = subprocess.Popen(args, stdout=output, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                shell=False, env=containers.environment(), creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        last_progress = -10
        halted = None
        try:
            while proc.poll() is None:
                elapsed = time.monotonic() - started
                if stop.is_set() or elapsed > hours * 3600 or output.tell() > 8 * 1024 * 1024:
                    halted = 'cancelled' if stop.is_set() else 'timed-out-or-output-limited'
                    break
                if elapsed - last_progress >= 10:
                    progress(f"Defender scanning {row['path']} · {int(elapsed // 60)} min elapsed · file percentage unavailable")
                    last_progress = elapsed
                stop.wait(.2)
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait()
        output.seek(0)
        raw = output.read(8 * 1024 * 1024).decode('utf-8', errors='replace')
    # Show HRESULTs and structured detection labels; omit arbitrary source content.
    codes = sorted(set(re.findall(r'0x[0-9a-fA-F]{8}', raw)))[:10]
    evidence = f'Exit code {proc.returncode}; duration {round(time.monotonic() - started, 1)} s. Remediation disabled for this invocation.'
    if codes:
        evidence += ' HRESULT: ' + ', '.join(codes) + '.'
    findings = [engine.finding('Drive scan ' + ('incomplete' if halted or proc.returncode else 'returned success'),
                 'unknown' if halted or proc.returncode else 'review', evidence,
                 'Review any detection evidence and coverage limits. A successful command is not a safety guarantee.', 'Drive malware')]
    detections = []
    for line in raw.splitlines():
        # Windows Defender prints Threat/Resources labels for no-remediation detections.
        if re.match(r'\s*(Threat(?: Name)?|Resources?|Resource Path|Path|file|containerfile)\s*:', line, re.I):
            detections.append(line.strip()[:600])
    if detections:
        findings.append(engine.finding('Defender detection details', 'attention', '\n'.join(detections[:12]),
                                      'Verify the reported files using the installed antivirus before taking remediation action.', 'Drive malware'))
    if proc.returncode == 2 and not detections:
        findings.append(engine.finding('Detection or scanner error requires review', 'unknown',
                       'Defender exit code 2 can mean an unremediated threat or a scanning error. No clean verdict is established; localized detection output may not be parsed.',
                       'Review the scanner output through an authorized local antivirus workflow; this invocation does not add detections to Defender history.', 'Drive malware'))
    if halted:
        findings.append(engine.finding('Drive scan stopped waiting', 'unknown',
                       'The command runner stopped: ' + halted + '. The Defender service may continue independently; remaining drives were not started.',
                       'Check Windows antivirus activity before starting another scan.', 'Drive malware'))
    return {'status': 'cancelled' if stop.is_set() else 'partial' if halted or proc.returncode else 'complete',
            'findings': findings, 'haltQueue': bool(halted), 'exitCode': proc.returncode, 'hresults': codes}


def assess(config, progress, stop):
    targets, mode, hours = validate(config)
    report = {'id': uuid.uuid4().hex, 'schema': 'sha-report-v1', 'type': 'Paperclip and drive scan batch',
              'createdAt': containers.now(), 'target': f'{len(targets)} selected workspaces/drives', 'status': 'running',
              'findings': [], 'coverage': {'planned': len(targets), 'finished': 0, 'omittedFindings': 0},
              'batchAssessment': {'agentMode': mode, 'driveHours': hours, 'targets': [dict(x, status='queued') for x in targets]},
              'limitations': ['Agent scans inspect selected configured workspaces offline. Shared Hermes skills/runtime and folders outside those workspaces are not automatically included.',
               'Drive scans are custom Microsoft Defender scans over selected fixed-drive roots, with remediation disabled. They do not inspect every running WSL/VM filesystem inside its virtual disk, prove absence of malware, or audit agent behavior.',
               'No cloud lookup or model semantic review is requested by the agent batch. Existing antivirus cloud and real-time protection policies remain independent.',
               'Native drive scan output can contain sensitive file paths. Only bounded detection labels and HRESULTs are retained; localized or excess output may be omitted. Unresolved detections and errors remain unknown.',
               f'Each drive has a {hours}-hour waiting limit; cancellation or timeout may leave a service scan running. Subsequent targets are then skipped. Keep the app process running.',
               f'At most {MAX_FINDINGS} findings are retained in this batch report. Review omitted counts; rerun a smaller target when needed.']}
    _save(report)
    halt = False
    try:
        for row in report['batchAssessment']['targets']:
            if stop.is_set() or halt:
                row['status'] = 'not-run'
                continue
            row['status'] = 'running'
            row['startedAt'] = containers.now()
            _save(report)
            progress(f"Scanning {row['name']} · target {report['coverage']['finished'] + 1}/{len(targets)}")
            try:
                if row['kind'] == 'drive':
                    result = antivirus_drive(row, hours, progress, stop)
                    halt = result.get('haltQueue', False)
                    row.update({k: result[k] for k in ('exitCode', 'hresults') if k in result})
                else:
                    result = agent_scanner.assess({'path': row['path'], 'mode': mode, 'online': False, 'semantic': False}, progress, stop)
                row['status'] = result.get('status', 'partial')
                row['findingCount'] = len(result.get('findings', []))
                for item in result.get('findings', []):
                    if len(report['findings']) >= MAX_FINDINGS:
                        report['coverage']['omittedFindings'] += 1
                        continue
                    report['findings'].append({'name': text(item.get('name'), 160), 'status': item.get('status') if item.get('status') in ('pass', 'review', 'attention', 'unknown') else 'unknown',
                        'evidence': text(row['path'], 1000) + '\n' + text(item.get('evidence'), 1400),
                        'recommendation': text(item.get('recommendation'), 700), 'area': text(row['name'], 100), 'targetId': row['id']})
            except (OSError, ValueError):
                row['status'] = 'failed'
                row['error'] = 'Scanner could not complete this target. Check engine availability, permissions and source-path access.'
            row['finishedAt'] = containers.now()
            report['coverage']['finished'] += 1
            _save(report)
    finally:
        for row in report['batchAssessment']['targets']:
            if row['status'] in ('running', 'queued'):
                row['status'] = 'not-run'
        report['status'] = 'cancelled' if stop.is_set() else 'complete' if all(x['status'] == 'complete' for x in report['batchAssessment']['targets']) and not report['coverage']['omittedFindings'] else 'partial'
        report['coverage']['completeTargets'] = sum(x['status'] == 'complete' for x in report['batchAssessment']['targets'])
        _save(report)
    return report
