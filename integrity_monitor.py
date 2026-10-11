"""Explicit baselines, opt-in recurring drift checks and local canary evidence."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import threading
import time
import deployment_audits as audits
import engine
import security_store as store

_lock=threading.Lock()
_stop=threading.Event()
_thread=None

def snapshot(path,seconds=120):
    root=audits.target_path(path);records={};gaps=[];total=0;started=time.monotonic()
    iterator=iter(audits.files(root,10001,strict=True))
    while True:
        try:target=next(iterator)
        except StopIteration:break
        except OSError:gaps.append('Directory access or inventory entry limit prevented a complete inventory.');break
        if len(records)>=10000:gaps.append('10,000-file limit reached');break
        if _stop.is_set() or time.monotonic()-started>seconds:gaps.append('Time budget reached');break
        rel=target.name if root.is_file() else str(target.relative_to(root))
        try:
            before=target.stat()
            if before.st_size>128*1024**3 or total+before.st_size>256*1024**3:gaps.append('Size budget: '+rel);continue
            digest=hashlib.sha256()
            with target.open('rb') as handle:
                while True:
                    chunk=handle.read(1024*1024)
                    if not chunk:break
                    if time.monotonic()-started>seconds:raise TimeoutError()
                    digest.update(chunk);total+=len(chunk)
            after=target.stat()
            if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):gaps.append('Changed during hashing: '+rel);continue
            records[rel]={'sha256':digest.hexdigest(),'bytes':after.st_size}
        except (OSError,TimeoutError):gaps.append('Unable to finish: '+rel)
    return {'files':records,'gaps':gaps,'bytesHashed':total,'createdAt':store.now()}

def save(config):
    name=str(config.get('name','')).strip()[:200]
    if not name:raise ValueError('Name this monitor.')
    kind=config.get('kind','files')
    if kind not in ('files','behavior'):raise ValueError('Choose files or behavior.')
    interval=config.get('intervalSeconds',3600)
    if not isinstance(interval,int) or isinstance(interval,bool) or not 60<=interval<=604800:raise ValueError('Interval must be 60–604800 seconds.')
    row={'name':name,'kind':kind,'intervalSeconds':interval,'enabled':False,'lastRun':None,'nextRun':0}
    if kind=='files':
        row['path']=str(audits.target_path(config.get('path','')))
        result=snapshot(row['path'])
    else:
        if config.get('authorized') is not True:raise ValueError('Authorize fixed inference probes for this endpoint.')
        url=engine.validate_target(config.get('url',''));model=config.get('model','');provider=config.get('provider','ollama')
        prompts=config.get('prompts',['Reply with exactly the word READY.','What is 2 plus 2? Answer with one digit.'])
        engine.inference_providers.profile(provider)
        if not isinstance(model,str) or not model:raise ValueError('Choose a model and provider.')
        if not isinstance(prompts,list) or not 1<=len(prompts)<=5 or any(not isinstance(p,str) or not p or len(p)>1000 for p in prompts):raise ValueError('Choose 1–5 fixed prompts of at most 1,000 characters.')
        # No API keys saved in the monitor record. Authenticated endpoints require an env-name reference.
        keyenv=config.get('keyEnv','')
        if keyenv and not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,79}',keyenv):raise ValueError('Use a credential environment variable name.')
        row.update(url=url,model=model,provider=provider,prompts=prompts,keyEnv=keyenv)
        result=behavior(row)
    if result['gaps'] or not result['files']:raise ValueError('Baseline is incomplete; correct missing access, input size, time budget or inference failures before saving it.')
    row['baseline']=result;row['lastResult']={'status':'baseline-recorded','createdAt':store.now(),'changes':[]}
    return public(store.put('monitors',row))

def behavior(row):
    key=os.environ.get(row.get('keyEnv',''),'') if row.get('keyEnv') else ''
    if row.get('keyEnv') and not key:return {'files':{},'gaps':['Credential variable missing']}
    config={'url':row['url'],'kind':row['provider'],'model':row['model'],'key':key}
    inventory=engine.discover(config)
    if row['model'] not in [x['name'] for x in inventory['models']]:return {'files':{},'gaps':['Model identity not returned by inventory']}
    records={};gaps=[]
    for index,prompt in enumerate(row['prompts']):
        try:
            answer=engine.complete(config,[{'role':'system','content':'Answer the fixed diagnostic prompt briefly.'},{'role':'user','content':prompt}])
            normalized=' '.join(answer.split())
            records[str(index+1)]={'sha256':hashlib.sha256(normalized.encode()).hexdigest(),'bytes':len(normalized)}
        except Exception:gaps.append('Prompt '+str(index+1)+' inconclusive')
    return {'files':records,'gaps':gaps,'createdAt':store.now()}

def public(row):
    return {k:v for k,v in row.items() if k!='baseline'} | {'baselineEntries':len(row.get('baseline',{}).get('files',{}))}

def check(identity):
    if not _lock.acquire(blocking=False):raise ValueError('An integrity check is already running.')
    try:
        row=store.get('monitors',identity)
        if not row:raise ValueError('Unknown monitor.')
        current=snapshot(row['path']) if row['kind']=='files' else behavior(row)
        old=row['baseline']['files'];new=current['files'];changes=[]
        for name,value in new.items():
            if name not in old:changes.append({'path':name,'change':'added'})
            elif old[name]['sha256']!=value['sha256']:changes.append({'path':name,'change':'changed'})
        # Incomplete inventories cannot establish deletion.
        if not current['gaps']:
            changes.extend({'path':name,'change':'removed'} for name in old.keys()-new.keys())
        result={'status':'incomplete' if current['gaps'] else 'changed' if changes else 'unchanged','createdAt':store.now(),'changes':changes[:1000],'changesOmitted':max(0,len(changes)-1000),'gaps':current['gaps'][:100]}
        prior=row.get('lastResult',{})
        if result['status']!='unchanged' and (prior.get('status')!=result['status'] or prior.get('changes')!=result['changes'] or prior.get('gaps')!=result['gaps']):
            store.event(row['id'],'integrity-'+row['kind'],'alert',[result['status']])
        row['lastResult']=result;row['lastRun']=store.now();row['nextRun']=time.time()+row['intervalSeconds']
        # Preserve latest enable/disable setting if the user changed it during a scan.
        row['enabled']=(store.get('monitors',identity) or row)['enabled']
        store.put('monitors',row)
        return public(row)
    finally:_lock.release()

def toggle(config):
    row=store.get('monitors',config.get('id'))
    if not row or not isinstance(config.get('enabled'),bool):raise ValueError('Choose a monitor and enabled true/false.')
    row['enabled']=config['enabled'];row['nextRun']=time.time()+row['intervalSeconds']
    return public(store.put('monitors',row))

def run_scheduler():
    while not _stop.wait(10):
        for row in store.all_items('monitors'):
            if row.get('enabled') and time.time()>=row.get('nextRun',0):
                try:check(row['id'])
                except Exception:
                    row=store.get('monitors',row['id']) or row
                    row['lastResult']={'status':'incomplete','createdAt':store.now(),'changes':[],'gaps':['Monitor could not complete. Check target availability and dependencies.']}
                    row['nextRun']=time.time()+row['intervalSeconds'];store.put('monitors',row)
                    store.event(row['id'],'integrity','error',['monitor-failed'])

def start_scheduler():
    global _thread
    if not _thread or not _thread.is_alive():
        _stop.clear();_thread=threading.Thread(target=run_scheduler,daemon=True);_thread.start()

def honey_create(config):
    folder=audits.target_path(config.get('path',''))
    if not folder.is_dir():raise ValueError('Choose a directory for the fake .env canary file.')
    identity=secrets.token_hex(16);token='SHA_CANARY_'+identity
    filename=folder/('.env.canary-'+identity[:8])
    url='http://127.0.0.1:8766/canary/'+identity
    with filename.open('x',encoding='utf-8') as handle:
        handle.write('# Synthetic canary. Not a real provider credential.\nAPI_KEY='+token+'\nCANARY_URL='+url+'\n')
    record={'id':identity,'name':str(config.get('name','Local canary'))[:200],'path':str(filename),'url':url,'marker':token}
    return store.put('canaries',record)

def canary_hit(identity,point='canary-callback'):
    row=store.get('canaries',identity)
    if not row:return False
    store.event(identity,point,'alert',['canary-observed'])
    return True
