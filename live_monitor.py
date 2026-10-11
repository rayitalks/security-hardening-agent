"""Opt-in supervised monitoring. No automatic startup, remediation, or file-content retention."""
import atexit
from collections import deque
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time
import containers
import deployment_audits as audits
import engine
import inference_metrics
import security_store

ROOT=Path(__file__).resolve().parent
_lock=threading.RLock();_process=None;_session=0;_state={'running':False,'status':'off','message':'Monitoring is off.'}
_history=deque(maxlen=600);_events=deque(maxlen=1000);_alerts=deque(maxlen=200)

def runtime():return ROOT/'.audit-runtime'/('Scripts/python.exe' if os.name=='nt' else 'bin/python')

def validate(config):
    if config.get('authorized') is not True:raise ValueError('Confirm monitoring of the selected local folders and telemetry.')
    roots=config.get('roots',[])
    if not isinstance(roots,list) or not 1<=len(roots)<=10:raise ValueError('Choose one to ten absolute folders to monitor.')
    selected=[]
    for value in roots:
        path=audits.target_path(value)
        if not path.is_dir() or path==Path(path.anchor):raise ValueError('Choose scoped folders rather than an entire drive/filesystem root.')
        if any(path.is_relative_to(p) or p.is_relative_to(path) for p in selected):raise ValueError('Use non-overlapping monitoring folders.')
        selected.append(path)
    threshold=config.get('burstThreshold',40)
    if isinstance(threshold,bool) or not isinstance(threshold,int) or not 10<=threshold<=5000:raise ValueError('Burst threshold must be 10–5,000 unique files in 20 seconds.')
    endpoints=config.get('endpoints',[])
    if not isinstance(endpoints,list) or len(endpoints)>4:raise ValueError('Choose up to four explicit AI telemetry endpoints.')
    peers=[]
    for peer in endpoints:
        if not isinstance(peer,dict) or peer.get('kind') not in ('ollama','vllm'):raise ValueError('Choose Ollama or vLLM telemetry.')
        url=engine.validate_target(peer.get('url',''));keyenv=peer.get('keyEnv','')
        if keyenv and not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,79}',keyenv):raise ValueError('Use a credential environment variable name.')
        peers.append({'kind':peer['kind'],'url':url,'keyEnv':keyenv})
    return {'roots':[str(p) for p in selected],'burstThreshold':threshold,'sampleContents':config.get('sampleContents') is True,'authEvents':config.get('authEvents') is True,'endpoints':peers}

def snapshot():
    with _lock:
        result=copy.deepcopy(_state)
        result.update(history=list(_history),events=list(_events)[-200:],alerts=list(_alerts),inference=inference_metrics.snapshot())
    result['limits']=['Native filesystem notifications within the selected folders; queues can overflow and network filesystems may have incomplete event support.',
                      'Encryption and baseline rules are heuristic. Optional entropy sampling reads the first 4 KiB of bounded files in memory only; no file bytes are saved.',
                      'Authentication events require readable enabled OS logs. Connections to SSH/admin ports are connection metadata, not proof of login or elevation.',
                      'No process-to-file attribution, prevention or OS-wide EDR claim. Monitoring sees only this process namespace, including inside a VM/container.',
                      'Up to 20 minutes of performance samples, 1,000 activity events and 200 alerts retained in memory. Off/restart ends collection. Alerts also appear as redacted rule IDs in Violations.']
    return result

def consume(process,session):
    global _state
    try:
        while True:
            line=process.stdout.readline(2_000_001)
            if not line:break
            if len(line)>2_000_000:raise ValueError('Worker message exceeded bounds')
            item=json.loads(line)
            with _lock:
                if session!=_session:return
                if item['type']=='ready':_state.update(status='watching',message='Native filesystem monitor active.',worker=item)
                elif item['type']=='error':_state.update(status='error',message=item['message'])
                elif item['type']=='sample':
                    _events.extend(item.pop('events',[]));alerts=item.pop('alerts',[]);_alerts.extend(alerts)
                    _state.update(sample=item,updatedAt=time.time())
                    _history.append({'timestamp':item['timestamp'],'performance':item['performance'],'fileEvents':item['filesystem']['eventsThisSample']})
                    for alert in alerts:security_store.event('local-monitor','behavior','alert',[alert['rule']])
    except Exception:
        with _lock:
            if session==_session:_state.update(status='error',message='Monitoring stream failed; coverage is incomplete.')
    finally:
        if process.stdout:process.stdout.close()
        if process.stdin:
            try:process.stdin.close()
            except OSError:pass
        if process.poll() is None:process.terminate()
        with _lock:
            if session==_session and _state.get('running'):
                _state.update(running=False,status='error',message='Monitoring worker stopped unexpectedly; no live coverage.')
                inference_metrics.enable(False)

def start(config):
    global _process,_session,_state
    selected=validate(config)
    if not runtime().is_file():raise ValueError('Install audit tools, including watchdog and psutil, before monitoring.')
    with _lock:
        if _process and _process.poll() is None:raise ValueError('Monitoring is already active. Stop it before changing scope.')
        env=containers.environment();env['PYTHONUNBUFFERED']='1';env['PYTHONDONTWRITEBYTECODE']='1'
        for endpoint in selected['endpoints']:
            name=endpoint['keyEnv']
            if name and name in os.environ:env[name]=os.environ[name]
        process=subprocess.Popen([str(runtime()),str(ROOT/'monitor_worker.py')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=env,cwd=ROOT,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        _process=process;_session+=1;_history.clear();_events.clear();_alerts.clear()
        _state={'running':True,'status':'starting','startedAt':time.time(),'config':selected,'message':'Starting observers and collecting initial evidence…'}
        process.stdin.write((json.dumps(selected)+'\n').encode());process.stdin.flush()
        inference_metrics.enable(True)
        threading.Thread(target=consume,args=(process,_session),daemon=True).start()
    return {'running':True,'status':'starting','dashboardUrl':'/monitor'}

def stop():
    global _process,_state
    with _lock:
        process=_process;_process=None;_state.update(running=False,status='off',message='Monitoring stopped. Last samples retained until the next start or app restart.')
        inference_metrics.enable(False)
    if process and process.poll() is None:
        try:process.stdin.write(b'stop\n');process.stdin.flush();process.wait(timeout=8)
        except (OSError,subprocess.TimeoutExpired):process.terminate();process.wait(timeout=5)
    return {'running':False,'status':'off'}

atexit.register(stop)
