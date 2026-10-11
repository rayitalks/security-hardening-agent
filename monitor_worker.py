"""Isolated live monitor: native filesystem events, sampled telemetry and redacted auth classes."""
from collections import deque,OrderedDict
import datetime as dt
import json
import math
import os
from pathlib import Path
import queue
import re
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.parse
import behavior_rules
import engine

STOP=threading.Event();OUT=threading.Lock()
EXCLUDE={'.git','node_modules','.venv','.runtime','.model-runtime','.audit-runtime','__pycache__'}

def emit(value):
    try:
        with OUT:print(json.dumps(value,ensure_ascii=True,allow_nan=False),flush=True)
    except (BrokenPipeError,OSError):STOP.set()

def safe_file(path,roots):
    path=Path(os.path.abspath(path))
    for root in roots:
        if path.is_relative_to(root):
            current=path
            while current!=root:
                if current.name in EXCLUDE or current.is_symlink() or getattr(current,'is_junction',lambda:False)():return None
                current=current.parent
            if root.is_symlink() or getattr(root,'is_junction',lambda:False)():return None
            if path.exists() and not path.resolve().is_relative_to(root):return None
            return path
    return None

def sample(path):
    try:
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size<1024:return None
        with path.open('rb') as handle:data=handle.read(4096)
        return behavior_rules.entropy(data)
    except OSError:return None

def run_command(args,timeout=8):
    try:
        result=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,timeout=timeout,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        return result.returncode,result.stdout[:2_000_000].decode('utf-8-sig',errors='replace')
    except (OSError,subprocess.TimeoutExpired):return -1,''

def numeric(value):
    try:
        n=float(value);return n if math.isfinite(n) else None
    except (TypeError,ValueError):return None

def gpu_sample():
    code,out=run_command(['nvidia-smi','--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw','--format=csv,noheader,nounits'])
    rows=[]
    if code==0:
        for line in out.splitlines()[:16]:
            values=line.split(',')
            if len(values)==6:rows.append(dict(zip(['name','utilizationPercent','memoryUsedMB','memoryTotalMB','temperatureC','powerW'],[values[0].strip()]+[numeric(v.strip()) for v in values[1:]])))
    return {'status':'available' if rows else 'unavailable','devices':rows,'scope':'NVIDIA devices visible to this process; other vendors are not sampled.'}

def read_endpoint(config,path):
    base=engine.validate_target(config['url']);key=os.environ.get(config.get('keyEnv',''),'')
    if config.get('keyEnv') and not key:raise ValueError('Credential environment variable missing')
    parsed=urllib.parse.urlsplit(base)
    if key and parsed.scheme!='https' and parsed.hostname not in ('localhost','127.0.0.1','::1'):raise ValueError('Remote credentials require HTTPS')
    headers={'Accept':'application/json,text/plain','User-Agent':'Ray-i-Live-Monitor/2.1'}
    if key:headers['Authorization']='Bearer '+key
    request=urllib.request.Request(base.rstrip('/')+path,headers=headers)
    with urllib.request.build_opener(urllib.request.ProxyHandler({}),engine.NoRedirect()).open(request,timeout=4) as response:
        raw=response.read(1_000_001)
    if len(raw)>1_000_000:raise ValueError('Metrics exceeded limit')
    return raw.decode('utf-8')

METRICS={'vllm:num_requests_running','vllm:num_requests_waiting','vllm:generation_tokens_total','vllm:prompt_tokens_total','vllm:kv_cache_usage_perc','vllm:gpu_cache_usage_perc','vllm:request_success_total','vllm:e2e_request_latency_seconds_sum','vllm:e2e_request_latency_seconds_count','vllm:time_to_first_token_seconds_sum','vllm:time_to_first_token_seconds_count'}
def parse_metrics(text):
    result={}
    for line in text.splitlines():
        match=re.fullmatch(r'([A-Za-z_:][A-Za-z0-9_:]*)(?:\{([^\n]*)\})?\s+([-+0-9.eE]+)(?:\s+\d+)?',line)
        if not match or match[1] not in METRICS:continue
        value=numeric(match[3])
        if value is None or value<0:continue
        label=re.search(r'(?:^|,)\s*model_name="([^"\\]{0,200})"',match[2] or '')
        model=label[1] if label else 'all-models'
        row=result.setdefault(model,{})
        if match[1].endswith('cache_usage_perc'):row[match[1]]=max(row.get(match[1],0),value)
        else:row[match[1]]=row.get(match[1],0)+value
    return result

def ai_sample(config,previous):
    output=[];now=time.monotonic()
    for endpoint in config.get('endpoints',[]):
        row={'kind':endpoint['kind'],'url':endpoint['url'],'status':'unavailable','observedAt':time.time()}
        try:
            if endpoint['kind']=='ollama':
                data=json.loads(read_endpoint(endpoint,'/api/ps'));models=data.get('models')
                if not isinstance(models,list):raise ValueError()
                row['models']=[{'model':str(m.get('name',''))[:200],'sizeBytes':numeric(m.get('size')),'vramBytes':numeric(m.get('size_vram')),'contextLength':numeric(m.get('context_length')),'quantization':str(m.get('details',{}).get('quantization_level',''))[:60]} for m in models[:100] if isinstance(m,dict)]
                row['scope']='Loaded model inventory; token throughput for Ollama comes from routed gateway calls.'
            else:
                metrics=parse_metrics(read_endpoint(endpoint,'/metrics'));row['models']=[]
                for model,values in list(metrics.items())[:100]:
                    key=(endpoint['url'],model);old=previous.get(key);delta={}
                    if old and now>old[0]:
                        for name in ('generation_tokens_total','prompt_tokens_total'):
                            full='vllm:'+name
                            if full in values and full in old[1] and values[full]>=old[1][full]:delta[name+'PerSecond']=(values[full]-old[1][full])/(now-old[0])
                    previous[key]=(now,values)
                    def mean(prefix):
                        n=values.get('vllm:'+prefix+'_count');total=values.get('vllm:'+prefix+'_sum')
                        return total/n if n and total is not None else None
                    row['models'].append({'model':model,'metrics':values,**delta,'meanLatencySeconds':mean('e2e_request_latency_seconds'),'meanTTFTSeconds':mean('time_to_first_token_seconds')})
                row['scope']='Read-only vLLM metrics; means are lifetime cumulative, rates need two samples. Counter resets produce unknown rates.'
            row['status']='available'
        except Exception:row['reason']='Endpoint unavailable, unauthorized or unsupported; no metrics inferred.'
        output.append(row)
    return output

def auth_loop(config,events,coverage):
    started=dt.datetime.now(dt.timezone.utc).isoformat();cursors={'Security':0,'OpenSSH/Operational':0};handles={}
    while not STOP.is_set():
        if os.name=='nt':
            code,out=run_command(['powershell.exe','-NoProfile','-NonInteractive','-File',str(Path(__file__).with_name('auth_events.ps1')),'-Since',started,'-SecurityCursor',str(cursors['Security']),'-SshCursor',str(cursors['OpenSSH/Operational'])],12)
            try:
                if code:raise ValueError()
                data=json.loads(out);coverage[:]=data['coverage']
                for event in data['events']:
                    cursors[event['source']]=max(cursors[event['source']],event['recordId'])
                    if isinstance(event.get('account'),str):event['account']=event['account'][:120]
                    events.put_nowait({'type':'auth',**event})
            except Exception:coverage[:]=[{'source':'Windows security/OpenSSH','status':'unavailable','reason':'PowerShell script execution may be disabled, event logs inaccessible/missing, or collector incomplete. No execution-policy settings were changed.'}]
        else:
            states=[]
            for name in ('/var/log/auth.log','/var/log/secure'):
                path=Path(name)
                try:
                    info=path.stat()
                    if not stat.S_ISREG(info.st_mode) or path.is_symlink():continue
                    row=handles.get(name)
                    if row is None:row={'inode':info.st_ino,'position':info.st_size,'tail':''};handles[name]=row
                    if info.st_ino!=row['inode'] or info.st_size<row['position']:row.update(inode=info.st_ino,position=0,tail='')
                    with path.open('r',encoding='utf-8',errors='replace') as handle:
                        handle.seek(row['position']);text=handle.read(128000);row['position']=handle.tell()
                    parts=(row['tail']+text).split('\n');row['tail']=parts.pop()[-10000:]
                    for line in parts:
                        kind=behavior_rules.classify_auth(line)
                        if kind:events.put_nowait({'type':'auth','kind':kind,'source':name,'time':dt.datetime.now(dt.timezone.utc).isoformat()})
                    states.append({'source':name,'status':'available','truncated':len(text)>=128000})
                except (OSError,queue.Full):states.append({'source':name,'status':'unavailable'})
            coverage[:]=states or [{'source':'Authentication logs','status':'unavailable','reason':'No readable auth.log/secure file; journald-only/macOS unified logs need an external collector.'}]
        STOP.wait(10)

def run(config):
    import psutil
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    roots=[Path(p) for p in config['roots']];events=queue.Queue(4000);dropped=[0];entropies=OrderedDict();auth_coverage=[]
    detector=behavior_rules.Detector(config['burstThreshold']);observer=Observer();start=time.time();last_io=None;last_net=None;last_sample=None;total=0
    if config.get('sampleContents'):
        baseline_started=time.monotonic()
        for root in roots:
            for current,dirs,names in os.walk(root,followlinks=False):
                dirs[:]=[d for d in dirs if d not in EXCLUDE and safe_file(Path(current)/d,roots)]
                for name in names:
                    path=safe_file(Path(current)/name,roots)
                    if path:
                        value=sample(path)
                        if value is not None:entropies[str(path)]=value
                    if len(entropies)>=3000 or time.monotonic()-baseline_started>5:break
                if len(entropies)>=3000 or time.monotonic()-baseline_started>5:break
    class Handler(FileSystemEventHandler):
        def on_any_event(self,event):
            if event.is_directory or event.event_type not in ('created','modified','deleted','moved'):return
            path=safe_file(event.dest_path if event.event_type=='moved' else event.src_path,roots)
            if not path:return
            record={'type':'filesystem','action':event.event_type,'path':str(path),'sourcePath':str(safe_file(event.src_path,roots) or '') if event.event_type=='moved' else None,'observedAt':time.time()}
            try:events.put_nowait(record)
            except queue.Full:dropped[0]+=1
    for root in roots:observer.schedule(Handler(),str(root),recursive=True)
    observer.start()
    if config.get('authEvents'):threading.Thread(target=auth_loop,args=(config,events,auth_coverage),daemon=True).start()
    psutil.cpu_percent();extras={'gpu':{'status':'pending','devices':[]},'ai':[],'connections':[]};previous={}
    def extra_loop():
        while not STOP.is_set():
            extras['gpu']=gpu_sample();extras['ai']=ai_sample(config,previous)
            if config.get('authEvents'):
                try:extras['connections']=[{'localPort':c.laddr.port,'remoteAddress':c.raddr.ip if c.raddr else None,'state':c.status,'pid':c.pid} for c in psutil.net_connections(kind='tcp') if c.laddr and (c.laddr.port in (22,3389,5985,5986) or c.raddr and c.raddr.port in (22,3389,5985,5986))][:100]
                except (psutil.AccessDenied,OSError):extras['connections']=[]
            STOP.wait(10)
    threading.Thread(target=extra_loop,daemon=True).start()
    emit({'type':'ready','startedAt':start,'backend':type(observer).__name__,'roots':config['roots'],'baselineEntropyFiles':len(entropies)})
    try:
        while not STOP.wait(2):
            now=time.monotonic();recent=[];alerts=[];count=0;sample_count=0
            while len(recent)<500:
                try:event=events.get_nowait()
                except queue.Empty:break
                if event['type']=='filesystem':
                    count+=1;total+=1;key=event['path']
                    if config.get('sampleContents') and sample_count<50 and event['action'] in ('modified','moved','created'):
                        path=safe_file(key,roots);value=sample(path) if path else None;sample_count+=1
                        if value is not None:
                            before=entropies.get(event.get('sourcePath')) if event.get('sourcePath') else entropies.get(key)
                            event['entropy']=value;event['entropyIncrease']=round(value-before,3) if before is not None else None
                            entropies[key]=value;entropies.move_to_end(key)
                            while len(entropies)>10000:entropies.popitem(last=False)
                    alerts+=detector.ingest_file(event,event['observedAt'])
                else:alerts+=detector.auth(event)
                recent.append(event)
            baseline=detector.interval(count)
            if baseline:alerts.append(baseline)
            memory=psutil.virtual_memory();disk=psutil.disk_io_counters();net=psutil.net_io_counters();elapsed=now-last_sample if last_sample else None
            perf={'cpuPercent':psutil.cpu_percent(),'ramPercent':memory.percent,'ramUsedBytes':memory.used,'ramTotalBytes':memory.total,
                  'diskReadBytesPerSecond':max(0,disk.read_bytes-last_io.read_bytes)/elapsed if disk and last_io and elapsed else None,
                  'diskWriteBytesPerSecond':max(0,disk.write_bytes-last_io.write_bytes)/elapsed if disk and last_io and elapsed else None,
                  'networkSentBytesPerSecond':max(0,net.bytes_sent-last_net.bytes_sent)/elapsed if net and last_net and elapsed else None,
                  'networkReceivedBytesPerSecond':max(0,net.bytes_recv-last_net.bytes_recv)/elapsed if net and last_net and elapsed else None}
            last_io=disk;last_net=net;last_sample=now
            processes=[]
            for process in psutil.process_iter(['pid','name','memory_info']):
                try:
                    info=process.info
                    if re.search(r'(?i)ollama|vllm|llama|lmstudio|comfy|python',info['name'] or ''):processes.append({'pid':info['pid'],'name':info['name'],'rssBytes':info['memory_info'].rss if info['memory_info'] else None})
                except (psutil.NoSuchProcess,psutil.AccessDenied):pass
            emit({'type':'sample','timestamp':time.time(),'performance':perf,'gpu':extras['gpu'],'ai':extras['ai'],'processes':processes[:40],
                  'filesystem':{'eventsThisSample':count,'totalObserved':total,'queuedEvents':events.qsize(),'droppedEvents':dropped[0],'observerAlive':observer.is_alive(),'baselineSamples':len(detector.baseline)},
                  'authCoverage':list(auth_coverage) if config.get('authEvents') else [{'source':'Authentication events','status':'disabled'}],
                  'adminConnections':extras['connections'],'events':recent,'alerts':alerts})
    finally:observer.stop();observer.join(timeout=5)

def listen():
    for line in sys.stdin:
        if line.strip()=='stop':break
    STOP.set()

if __name__=='__main__':
    try:
        config=json.loads(sys.stdin.readline())
        threading.Thread(target=listen,daemon=True).start();run(config)
    except Exception:
        emit({'type':'error','message':'Monitor worker could not continue. Check dependencies, selected roots and OS permissions.'});sys.exit(1)
