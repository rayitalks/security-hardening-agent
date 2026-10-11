"""Scoped deployment checks. Never issues model-management mutations or vector writes."""
import hashlib
from contextlib import closing
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import ssl
import stat
import subprocess
import threading
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import collector
import containers
import engine
import guardrails
import security_store as store

def report(kind,target,findings,limits,**extra):
    return {'schema':'sha-report-v1','type':kind,'target':str(target),'createdAt':store.now(),
            'status':'partial' if any(x['status']=='unknown' for x in findings) else 'complete',
            'findings':findings,'limitations':limits,**extra}

def item(name,status,evidence,fix,area='Deployment'):
    return engine.finding(name,status,evidence,fix,area)

def target_path(value):
    path=Path(value).expanduser()
    if not path.is_absolute() or not path.exists() or path.is_symlink() or getattr(path,'is_junction',lambda:False)():raise ValueError('Choose an existing absolute path, not a link or junction.')
    return path.resolve()

def http_probe(base,path='/',method='GET'):
    base=engine.validate_target(base).rstrip('/')
    request=urllib.request.Request(base+path,method=method,headers={'User-Agent':'Ray-i-Security-Assessment/2.0','Origin':'https://audit-origin.invalid','Accept':'application/json'})
    http=urllib.request.build_opener(urllib.request.ProxyHandler({}),engine.NoRedirect())
    try:
        with http.open(request,timeout=5) as response:
            raw=response.read(128000) if method=='GET' else b''
            try:body=json.loads(raw)
            except (ValueError,UnicodeError):body=None
            return {'status':response.status,'corsWildcard':response.headers.get('Access-Control-Allow-Origin')=='*','json':body}
    except urllib.error.HTTPError as exc:
        result={'status':exc.code,'corsWildcard':exc.headers.get('Access-Control-Allow-Origin')=='*','json':None};exc.close();return result
    except (OSError,urllib.error.URLError):return {'status':None,'corsWildcard':False,'json':None}

def version_tuple(value):
    match=re.search(r'(?<!\d)(\d+)\.(\d+)\.(\d+)',str(value))
    return tuple(map(int,match.groups())) if match else None

def inference(config,progress,stop):
    if config.get('authorized') is not True:raise ValueError('Confirm authorization for this inference endpoint.')
    base=engine.validate_target(config.get('url',''));findings=[];rows=[]
    service=config.get('service','ollama')
    paths={'ollama':['/api/version','/api/tags'],'vllm':['/version','/v1/models'],'lmstudio':['/v1/models'],'comfyui':['/system_stats'],'gradio':['/config']}
    if service not in paths:raise ValueError('Choose a supported inference service.')
    for path in paths[service]:
        if stop.is_set():break
        progress('Reading public endpoint evidence: '+path)
        result=http_probe(base,path);rows.append({'path':path,**{k:v for k,v in result.items() if k!='json'}})
        code=result['status']
        findings.append(item('Unauthenticated '+path,'review' if code==200 else 'pass' if code in (401,403) else 'unknown',f'No-credential request returned HTTP {code}.','Require authentication at intended protected paths; validate from a separate network vantage.'))
        if result['corsWildcard']:findings.append(item('Wildcard CORS','attention',path+' returned Access-Control-Allow-Origin: *.','Restrict allowed origins and review credential handling.'))
        if service=='ollama' and path=='/api/version':
            version=(result['json'] or {}).get('version') if isinstance(result['json'],dict) else None
            parsed=version_tuple(version)
            finding=item('Ollama binary CVE-2024-37032','attention' if parsed and parsed<(0,1,34) else 'pass' if parsed else 'unknown',
                         ('Observed version '+str(version)+'. ' if parsed else 'Server version unavailable. ')+'The recorded affected range is versions before 0.1.34. Backports are not verified.',
                         'Check the vendor advisory and move to a currently supported patched release; this is one historical advisory, not a full server CVE feed.')
            finding['reference']='https://cveawg.mitre.org/api/cve/CVE-2024-37032';findings.append(finding)
    if service=='ollama':
        for path in ('/api/pull','/api/push','/api/create','/api/delete'):
            if stop.is_set():break
            result=http_probe(base,path,'HEAD');code=result['status']
            findings.append(item('Management route '+path,'pass' if code in (401,403) else 'unknown',f'Unauthenticated HEAD returned HTTP {code}. No management operation was attempted.',
                                 'Review proxy authorization rules for the actual management methods. HEAD/405/200 cannot establish whether a modifying POST or DELETE is authorized.'))
    parsed=urllib.parse.urlsplit(base)
    if parsed.hostname in ('127.0.0.1','localhost','::1'):
        port=parsed.port or (443 if parsed.scheme=='https' else 80)
        if os.name=='nt':code,out=collector.command(['powershell.exe','-NoProfile','-NonInteractive','-Command',f'Get-NetTCPConnection -State Listen -LocalPort {port} | Select-Object -ExpandProperty LocalAddress'])
        else:code,out=collector.command(['ss','-H','-lnt',f'sport = :{port}'])
        wildcard=bool(re.search(r'(^|\s)(0\.0\.0\.0|::|\*|\[::\])(?::\d+)?(\s|$)',out))
        findings.append(item('Local bind address','attention' if code==0 and wildcard else 'review' if code==0 else 'unknown',
                             'Wildcard listener observed.' if code==0 and wildcard else 'No wildcard detected in available local listener evidence.' if code==0 else 'Local listener evidence unavailable.',
                             'Prefer loopback or a restricted interface behind an authenticating proxy; wildcard binding alone does not prove public reachability.'))
    else:findings.append(item('Remote bind address','unknown','A remote URL cannot establish the server bind configuration.','Collect host evidence or use the outside-in probe.'))
    findings.append(item('Authenticating reverse proxy','unknown','HTTP responses alone do not prove the identity or configuration of a reverse proxy.','Audit proxy configuration and require unauthenticated requests to be denied on all protected inference and management routes.'))
    return report('Inference exposure',base,findings,['Read-only GET and HEAD requests only; no pull/push/create/delete calls. No inference generated. Local observations do not establish internet reachability.'],exposure={'service':service,'requests':rows})

def files(root,limit=3000,strict=False):
    if root.is_file():yield root;return
    count=0
    def on_error(exc):
        if strict:raise OSError('Directory could not be inventoried.') from exc
    for current,dirs,names in os.walk(root,followlinks=False,onerror=on_error):
        dirs[:]=[d for d in dirs if d not in {'.git','node_modules','.venv','.runtime','.model-runtime','vendor'} and not (Path(current)/d).is_symlink() and not getattr(Path(current)/d,'is_junction',lambda:False)()]
        for name in names:
            count+=1
            if count>limit:
                if strict:raise OSError('Inventory entry limit reached.')
                return
            path=Path(current)/name
            if not path.is_symlink() and path.resolve().is_relative_to(root):yield path

CONFIG_RULES=[
 ('Public WebUI signup',r'(?im)\bENABLE_SIGNUP\b\s*[:=]\s*["\x27]?(?:true|1|yes)\b','Disable unneeded public signup and audit persistent database settings.'),
 ('Disabled WebUI authentication',r'(?im)\bWEBUI_AUTH\b\s*[:=]\s*["\x27]?(?:false|0|no)\b','Enable authentication before allowing non-loopback access.'),
 ('Default WebUI secret',r'(?im)\bWEBUI_SECRET_KEY\b\s*[:=]\s*["\x27]?(?:your-secret-key|changeme|secret|t0p-s3cr3t)\b','Replace placeholder secrets and plan session invalidation.'),
 ('Gradio public tunnel',r'(?i)\bshare\s*=\s*True\b','Disable public share tunnels unless deliberately required and authenticated.'),
 ('Disabled Jupyter token',r'(?i)(?:(?:ServerApp|NotebookApp)\.token|IdentityProvider\.token)\s*=\s*(?:["\x27]{2}|None)','Require authentication; token-empty settings need separate password/proxy verification.'),
 ('Wildcard Ollama CORS',r'(?im)\bOLLAMA_ORIGINS\b\s*[:=]\s*["\x27]?\*','Limit allowed origins.'),
 ('Wildcard server bind',r'(?im)(?:OLLAMA_HOST|--listen|server_name|host)\s*(?:[:=]|\s)\s*["\x27]?(?:0\.0\.0\.0|::)','Restrict bind addresses or enforce a reviewed authenticating proxy.'),
 ('ComfyUI manager presence',r'(?i)comfyui[-_]manager','Restrict manager access; its installation capabilities can execute code.'),
]

def configuration(config,progress,stop):
    root=target_path(config.get('path',''));findings=[];scanned=skipped=0
    texts=[];text_bytes=0
    for path in files(root):
        if stop.is_set():break
        if path.suffix.lower() not in ('.py','.env','.yaml','.yml','.json','.toml','.conf','.cfg','.ini','.txt','.service') and path.name not in ('Modelfile','Dockerfile','.env','Caddyfile','nginx.conf'):continue
        try:
            if path.stat().st_size>1_000_000:skipped+=1;continue
            content=path.read_text(encoding='utf-8',errors='replace');scanned+=1;texts.append(content);text_bytes+=len(content)
            if text_bytes>16_000_000:skipped+=1;break
            for name,pattern,fix in CONFIG_RULES:
                matches=list(re.finditer(pattern,content))[:10]
                for match in matches:
                    findings.append(item(name,'review' if 'presence' in name or 'token' in name else 'attention',f'{path.name}:{content.count(chr(10),0,match.start())+1}. Configuration pattern matched; value omitted.',fix,'AI UI configuration'))
            if len(findings)>=500:break
        except OSError:skipped+=1
    if config.get('databasePath'):
        dbpath=target_path(config['databasePath'])
        try:
            with closing(sqlite3.connect(dbpath.as_uri()+'?mode=ro',uri=True,timeout=2)) as db:
                count=db.execute('SELECT COUNT(*) FROM user WHERE role = ?',('admin',)).fetchone()[0]
            findings.append(item('WebUI administrator accounts','review',f'{count} account(s) have the admin role. Names, addresses and credentials were not collected.','Review administrators in the UI and remove stale access after confirming ownership.'))
        except sqlite3.Error:findings.append(item('WebUI administrator accounts','unknown','The supplied database could not provide the expected user/role evidence.','Use a consistent supported Open WebUI database backup.'))
    combined='\n'.join(texts)
    if config.get('resources'):
        for name,pattern in [('Context cap',r'(?im)(?:num_ctx|--max-model-len)\s*(?:[:=]|\s)\s*(\d+)'),('Ollama queue',r'(?im)OLLAMA_MAX_QUEUE\s*[:=]\s*["\x27]?(\d+)'),('Ollama parallelism',r'(?im)OLLAMA_NUM_PARALLEL\s*[:=]\s*["\x27]?(\d+)'),('Proxy rate limit',r'(?i)(limit_req|rate_limit|rate-limit)'),('Container memory limit',r'(?i)(mem_limit|memory\s*:|--memory)')]:
            found=re.search(pattern,combined)
            findings.append(item(name,'review' if found else 'unknown','Explicit setting found; evaluate against workload capacity.' if found else 'No explicit setting found in selected files. Runtime defaults and external proxy configuration are unknown.','Verify effective settings and load-test within a bounded resource budget.','Resource limits'))
    findings.append(item('Effective deployed configuration','unknown',f'{scanned} file(s) inspected; {skipped} oversized/unreadable candidates skipped. Stored text may differ from running settings.','Verify persistent WebUI configuration, proxy routes, current accounts and effective process/container settings.'))
    return report('AI UI and resource configuration',root,findings,['Static selected files only, up to 3,000 entries and 1 MB per file. Findings omit values. Absence of a pattern is not a safe configuration verdict.'])

def gpu(config,progress,stop):
    findings=[]
    code,out=collector.command(['nvidia-smi','--query-gpu=driver_version,mig.mode.current','--format=csv,noheader'])
    findings.append(item('NVIDIA driver and MIG inventory','review' if code==0 else 'unknown',out[:2000] if code==0 else 'nvidia-smi was unavailable or did not support these queries.','Compare the driver with current NVIDIA advisories; confirm tenant isolation separately.','GPU'))
    code,toolkit=collector.command(['nvidia-container-cli','--version']);version=version_tuple(toolkit) if code==0 else None
    for cve,fixed,url,note in [('CVE-2024-0132',(1,16,2),'https://nvidia.custhelp.com/app/answers/detail/a_id/5582','CDI mode is excluded in this advisory.'),('CVE-2025-23266',(1,17,8),'https://nvidia.custhelp.com/app/answers/detail/a_id/5659/kw/support','Before 1.17.5 only CDI mode is affected; crun is excluded. Runtime/configuration applicability is not established.')]:
        finding=item(cve+' toolkit version','review' if version and version<fixed else 'pass' if version else 'unknown',
                     ('Detected toolkit '+'.'.join(map(str,version))+'. ' if version else 'Toolkit version unavailable. ')+note,
                     'If applicable, update using the vendor bulletin. Passing this historic version boundary does not establish absence of newer CVEs.','GPU')
        finding['reference']=url;findings.append(finding)
    devices=[]
    if os.name!='nt':
        for path in list(Path('/dev').glob('nvidia*'))[:64]:
            info=path.stat();devices.append({'path':str(path),'mode':stat.filemode(info.st_mode),'uid':info.st_uid,'gid':info.st_gid})
        findings.append(item('GPU device permissions','review' if devices else 'unknown',json.dumps(devices),'Review device ACLs, supplementary groups and container device mappings; mode bits alone do not prove isolation.','GPU'))
        code,out=collector.command(['pgrep','-x','nvidia-cuda-mps-control'])
        findings.append(item('MPS process evidence','review' if code==0 else 'unknown','MPS control process observed.' if code==0 else 'No MPS process confirmed.','MPS presence is not a security boundary; use appropriate isolation for mutually untrusted tenants.','GPU'))
    if config.get('multiTenant'):
        findings.append(item('Shared GPU tenant isolation','unknown','Multi-tenant usage was selected. MIG/MPS and device evidence do not attest tenant separation.','Verify the actual allocation, process ownership, MIG partitions and supported isolation model.','GPU'))
    return report('GPU stack audit',__import__('platform').node(),findings,['No driver changes, GPU workloads or escape attempts. Toolkit checks cover the two named historical advisories with applicability caveats; this is not a current comprehensive driver CVE feed.'])

def rag(config,progress,stop):
    findings=[];target=config.get('url') or config.get('path') or ''
    if config.get('url'):
        if config.get('authorized') is not True:raise ValueError('Confirm authorization to inspect the vector database endpoint.')
        base=engine.validate_target(config['url']);kind=config.get('service','qdrant')
        paths={'qdrant':'/collections','chroma':'/api/v2/tenants/default_tenant/databases/default_database/collections','weaviate':'/v1/schema','milvus':'/v2/vectordb/collections/list'}
        if kind not in paths:raise ValueError('Choose a supported vector database.')
        result=http_probe(base,paths[kind]);code=result['status']
        findings.append(item('Unauthenticated vector inventory','review' if code==200 else 'pass' if code in (401,403) else 'unknown',f'{kind} read-only GET returned HTTP {code}. Collection/document contents were not retained.','Require authentication and scoped read/write permissions. Milvus POST-only deployments require separate configuration evidence.','RAG'))
        findings.append(item('Vector database write protection','unknown','No writes, deletes or insertions were attempted. Read access does not establish write permissions.','Review auth/RBAC configuration or use an isolated test collection with explicit permission.','RAG'))
    if config.get('path'):
        root=target_path(config['path']);checked=0;skipped=0
        for path in files(root,1000):
            if stop.is_set():break
            try:
                if path.stat().st_size>8_000_000:skipped+=1;continue
                if path.suffix.lower()=='.pdf':
                    try:
                        runtime=Path(__file__).parent/'.audit-runtime'/('Scripts/python.exe' if os.name=='nt' else 'bin/python')
                        if not runtime.is_file():skipped+=1;continue
                        code,raw,_=containers.command([str(runtime),str(Path(__file__).with_name('pdf_source_worker.py')),str(path)],stop,30,env=containers.environment())
                        if code:skipped+=1;continue
                        pdf=json.loads(raw);content=pdf['text']
                        if pdf['hiddenTextPages'] or pdf['whiteTextPages']:
                            findings.append(item('PDF concealed text indicator','review',path.name+': invisible text on pages '+str(pdf['hiddenTextPages'])+'; near-white text on pages '+str(pdf['whiteTextPages'])+'.','Inspect rendered pages and extracted content before indexing.','RAG'))
                        findings.append(item('PDF visual coverage','unknown',path.name+': '+pdf['limitations'],'Review complex page rendering and scanned/image-only documents.','RAG'))
                    except (ValueError,OSError):skipped+=1;continue
                elif path.suffix.lower() in ('.html','.htm','.md','.txt','.csv','.json'):
                    content=path.read_text(encoding='utf-8',errors='replace')[:1_000_000]
                else:continue
                checked+=1
                if re.search('[\u200b-\u200f\u2060\ufeff]',content):findings.append(item('Invisible Unicode in knowledge source','review',path.name+': zero-width/directional character found; text omitted.','Review the source and normalize untrusted indexed text.','RAG'))
                if re.search(r'(?i)(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|color\s*:\s*(?:white|#fff(?:fff)?).{0,80}background(?:-color)?\s*:\s*(?:white|#fff(?:fff)?))',content):findings.append(item('Hidden HTML content','review',path.name+': concealed-text styling indicator found.','Compare rendered and extracted text before indexing.','RAG'))
                rules=guardrails.inspect(content,{**guardrails.DEFAULT,'privacy':False,'safety':False,'maxInputChars':1000000})['rules']
                if rules:findings.append(item('Stored prompt-injection indicator','review',path.name+': '+', '.join(rules)+'. Source omitted.','Quarantine and review the document; keep retrieved text untrusted.','RAG'))
            except Exception:skipped+=1
        findings.append(item('Knowledge source coverage','unknown' if skipped else 'review',f'{checked} file(s) inspected; {skipped} oversized, unsupported PDF or unreadable file(s).','Review encrypted/scanned PDFs, renderer-only text and remaining documents.','RAG'))
    if not target:raise ValueError('Choose an endpoint, a knowledge-source path, or both.')
    return report('RAG and vector security',target,findings,['No database writes and no document bodies retained. Text heuristics can miss obfuscated injections. PDF text extraction requires optional pypdf; visual/OCR concealment remains a review task.'])

def at_rest(config,progress,stop):
    root=target_path(config.get('path',''));findings=[];checked=skipped=0
    rules=guardrails.PATTERNS['privacy']+[('assigned-secret',r'(?i)(?:api[_-]?key|password|secret|access[_-]?token)\s*[:=]\s*["\x27][A-Za-z0-9_+/=-]{16,}["\x27]')]
    def inspect_text(text,location):
        for label,pattern in rules:
            matches=list(re.finditer(pattern,text,re.I))[:20]
            if matches:findings.append(item('Stored '+label,'review',location+f': {len(matches)} potential match(es), values redacted.','Confirm locally, rotate exposed secrets, and apply retention/access controls to histories, logs, caches and traces.','Data at rest'))
    for path in files(root,2000):
        if stop.is_set() or len(findings)>=500:break
        try:
            if path.suffix.lower() in ('.db','.sqlite','.sqlite3'):
                with closing(sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=2)) as db:
                    db.execute('PRAGMA query_only=ON')
                    deadline=time.monotonic()+10
                    db.set_progress_handler(lambda:int(time.monotonic()>deadline or stop.is_set()),10000)
                    names=db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' LIMIT 20").fetchall()
                    for (name,) in names:
                        quoted='"'+name.replace('"','""')+'"'
                        columns=db.execute('PRAGMA table_info('+quoted+')').fetchall()[:100]
                        quoted_columns=['"'+c[1].replace('"','""')+'"' for c in columns]
                        selection=','.join('CASE WHEN typeof('+c+")='text' THEN substr("+c+',1,100000) ELSE NULL END' for c in quoted_columns)
                        if not selection:continue
                        for index,row in enumerate(db.execute('SELECT '+selection+' FROM '+quoted+' LIMIT 1000')):
                            text=' '.join(v[:100000] for v in row if isinstance(v,str))[:200000]
                            inspect_text(text,path.name+f': table {name}, sample row {index+1}')
                            if len(findings)>=500:break
                        if len(findings)>=500:break
                checked+=1
            elif path.suffix.lower() in ('.txt','.log','.json','.jsonl','.md','.csv','.env') or path.name=='.env':
                if path.stat().st_size>8_000_000:skipped+=1;continue
                inspect_text(path.read_text(encoding='utf-8',errors='replace'),path.name);checked+=1
        except (OSError,sqlite3.Error):skipped+=1
    findings.append(item('At-rest scan coverage','unknown',f'{checked} files/databases inspected; {skipped} skipped. SQLite inspection samples up to 20 tables and 1,000 rows per table; large logs are skipped.','Review remaining data, encrypted stores, binary caches and retention policies.','Data at rest'))
    if config.get('gitleaks'):
        local=Path(__file__).parent/'.tools'/'gitleaks'/('gitleaks.exe' if os.name=='nt' else 'gitleaks')
        binary=str(local) if local.is_file() else shutil.which('gitleaks')
        if not binary:findings.append(item('Gitleaks engine','unknown','Gitleaks executable is not installed on PATH. Built-in patterns still ran.','Install the official Gitleaks binary and rerun this optional engine.','Data at rest'))
        else:
            with tempfile.TemporaryDirectory(prefix='sha-gitleaks-') as temporary:
                temp=Path(temporary);output=temp/'report.json';configuration=temp/'scanner.toml';ignore=temp/'.gitleaksignore'
                configuration.write_text('[extend]\nuseDefault = true\n');ignore.write_text('')
                code,raw,_=containers.command([binary,'dir',str(root),'--no-banner','--redact=100','--ignore-gitleaks-allow','--gitleaks-ignore-path',str(ignore),'--config',str(configuration),'--report-format','json','--report-path','-','--exit-code','10','--max-target-megabytes','8','--timeout','170'],stop,180,env=containers.environment(),cwd=str(temp))
                if code not in (0,10) or not raw.strip():findings.append(item('Gitleaks coverage','unknown','Gitleaks could not complete. Raw output omitted.','Check the installed CLI version and access.','Data at rest'))
                else:
                    data=json.loads(raw) if len(raw)<8_000_000 else None
                    if not isinstance(data,list):findings.append(item('Gitleaks coverage','unknown','Report missing or over 8 MB.','Reduce the selected scope.','Data at rest'))
                    else:
                        for hit in data[:500]:findings.append(item('Gitleaks '+str(hit.get('RuleID','match'))[:100],'review',str(hit.get('File',''))[:500]+':'+str(hit.get('StartLine',''))+'. Secret and source omitted.','Review locally and rotate any confirmed exposed credential.','Data at rest'))
                        findings.append(item('Gitleaks engine coverage','review',f'Completed with {len(data)} match(es); first 500 retained. Per-file limit 8 MB; no archive expansion.','Review skipped/unsupported stores separately; completion is not proof of no secrets.','Data at rest'))
    return report('Secrets and personal data at rest',root,findings,['Built-in redacted patterns with optional installed Gitleaks; no secret verification or uploads. Potential matches may be false positives. SQLite is opened read-only; use a consistent backup for active databases.'])

EGRESS_CODE='''import json,socket,ssl,urllib.request,urllib.error
cfg=json.loads(__import__('sys').argv[1]);results=[]
for name,host,port in [('controlled-internet',cfg['host'],cfg['port']),('cloud-metadata','169.254.169.254',80)]:
    try:
        with socket.create_connection((host,port),timeout=3):pass
        results.append({'check':name,'reachable':True})
    except OSError:results.append({'check':name,'reachable':False})
try:
    socket.getaddrinfo(cfg['dns'],None);results.append({'check':'DNS-resolution','reachable':True})
except OSError:results.append({'check':'DNS-resolution','reachable':False})
print(json.dumps(results))
'''

def egress(config,progress,stop):
    if config.get('authorized') is not True:raise ValueError('Authorize bounded network probes inside the selected container.')
    reference=containers.valid_reference(config.get('container',''))
    endpoint=engine.validate_target(config.get('url',''));parsed=urllib.parse.urlsplit(endpoint)
    dns=config.get('dns',parsed.hostname)
    if not isinstance(dns,str) or not re.fullmatch(r'[A-Za-z0-9.-]{1,253}',dns):raise ValueError('Use a DNS name without URL or command syntax.')
    connection=containers.docker_endpoint()
    row=json.loads(containers.docker(['container','inspect',reference],connection,stop))[0]
    if not row.get('State',{}).get('Running'):raise ValueError('Select a running container.')
    immutable=row['Id'];progress('Running bounded socket and DNS probes inside the selected container…')
    payload=json.dumps({'host':parsed.hostname,'port':parsed.port or (443 if parsed.scheme=='https' else 80),'dns':dns})
    raw=containers.docker(['exec',immutable,'python3','-c',EGRESS_CODE,payload],connection,stop,20)
    checks=json.loads(raw);findings=[]
    for result in checks:
        findings.append(item(result['check'],'attention' if result['reachable'] else 'review',
                             'Connection/resolution succeeded from the selected container.' if result['reachable'] else 'Connection/resolution failed at this vantage; cause is not proven.',
                             'Compare with the intended egress policy; block metadata access and unnecessary destinations. A failed connection can also mean service/DNS failure.','Egress'))
    return report('Container egress lockdown',immutable,findings,['Executes a fixed Python standard-library probe via local Docker; requires python3 already in the container. Does not install software or alter configuration. Metadata is tested by TCP connect only: no HTTP request, token or credential retrieval. Tests only the chosen destination, DNS name and metadata port, not all routes or protocols.'])

def signature(config,progress,stop):
    path=target_path(config.get('path',''));signature_path=target_path(config.get('signature',''))
    identity=config.get('identity','');issuer=config.get('issuer','')
    if not isinstance(identity,str) or not identity or len(identity)>1000 or not isinstance(issuer,str) or not issuer.startswith('https://'):raise ValueError('Provide an expected signer identity and HTTPS OIDC issuer.')
    local=Path(__file__).parent/'.audit-runtime'/('Scripts/model_signing.exe' if os.name=='nt' else 'bin/model_signing')
    binary=str(local) if local.is_file() else shutil.which('model_signing')
    if not binary:return report('Model signature verification',path,[item('Model signing engine','unknown','model_signing is not installed.','Install the official model-signing package in a dedicated environment, then retry.')],['No signature verification was performed.'])
    if config.get('online') is not True:raise ValueError('Sigstore verification may access public trust services; enable the online verification option.')
    code,raw,err=containers.command([binary,'verify','sigstore',str(path),'--signature',str(signature_path),'--identity',identity,'--identity_provider',issuer],stop,180,env=containers.environment())
    return report('Model signature verification',path,[item('Sigstore identity and model signature','pass' if code==0 else 'unknown','Verification completed successfully for the expected identity.' if code==0 else 'Verification did not succeed; raw signer/tool output omitted.','Use an independently trusted signer identity and issuer; investigate any failed verification.')],['Uses an already-installed official model_signing CLI. A valid signature establishes signing identity/integrity for that signature, not model behavioral safety.'],signature={'identity':identity,'issuer':issuer,'verified':code==0})

def assess(config,progress,stop):
    functions={'inference':inference,'configuration':configuration,'gpu':gpu,'rag':rag,'at_rest':at_rest,'egress':egress,'signature':signature}
    mode=config.get('mode')
    if mode not in functions:raise ValueError('Choose a supported deployment assessment.')
    result=functions[mode](config,progress,stop)
    if stop.is_set():result['status']='cancelled'
    return result
