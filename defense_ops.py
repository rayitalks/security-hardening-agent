"""Scoped gateway credentials, human approval, behavioral baselines and local response."""
from collections import defaultdict,deque
import hashlib
import hmac
import json
import re
import secrets
import statistics
import threading
import time
from urllib.parse import urlsplit
import audit_trail as audit
import security_store as store

LOCK=threading.RLock();BASE=defaultdict(lambda:deque(maxlen=200));DOMAINS=defaultdict(set);ACTIONS=defaultdict(lambda:deque(maxlen=1000))
HIGH=re.compile(r'delet|remov|destroy|send.?mail|send.?email|payment|transfer|purchase|exec|shell|write|deploy',re.I)
def mint(config):
    route=store.get('routes',config.get('routeId'))
    if not route:raise ValueError('Choose a registered route.')
    ttl=int(config.get('ttlMinutes',60))
    if not 1<=ttl<=1440:raise ValueError('Token lifetime must be 1–1,440 minutes.')
    def label(name,default):
        value=config.get(name,default)
        if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,100}',value):raise ValueError('Agent, task and role use short identifiers only.')
        return value
    role=label('role','operator');agent=label('agentId',route['id']);task=label('taskId','interactive')
    sensitivity=config.get('sensitivity','public')
    if sensitivity not in ('public','internal','confidential','restricted'):raise ValueError('Invalid sensitivity.')
    tools=config.get('tools',[])
    if not isinstance(tools,list) or len(tools)>100 or any(not isinstance(t,str) or len(t)>100 for t in tools):raise ValueError('Provide a bounded list of tool names.')
    token=secrets.token_urlsafe(32);row={'id':secrets.token_hex(12),'routeId':route['id'],'agentId':agent,'taskId':task,'role':role,
        'sensitivity':sensitivity,'tools':tools,'expires':time.time()+ttl*60,'hash':hashlib.sha256(token.encode()).hexdigest(),'revoked':False}
    with LOCK:
        old=store.get('tokens',config.get('rotateId')) if config.get('rotateId') else None
        if old and old['routeId']!=route['id']:raise ValueError('Rotation must retain the same route.')
        audit.append(agent,'token-issue','allowed',{'id':row['id'],'task':task,'expires':row['expires']})
        store.put('tokens',row)
        if old:old['revoked']=True;store.put('tokens',old)
    return {'credential':public(row),'token':token,'rotation':'New task tokens expire automatically; explicit rotation revokes the selected predecessor. Provider credentials are not rotated.'}
def public(row):return {k:v for k,v in row.items() if k!='hash'}
def authenticate(route,token):
    digest=hashlib.sha256(token.encode()).hexdigest()
    with LOCK:
        for row in store.all_items('tokens'):
            if row['routeId']==route['id'] and hmac.compare_digest(row['hash'],digest):
                if row['revoked'] or row['expires']<=time.time():raise PermissionError('Scoped token expired or revoked.')
                return row
    if hmac.compare_digest(route.get('tokenHash',''),digest) and time.time()<route.get('tokenExpires',0):
        return {'agentId':route['id'],'taskId':'bootstrap','role':'operator','sensitivity':'public','tools':None}
    raise PermissionError('Invalid or expired gateway credential. Issue a scoped task token.')
def revoke(config):
    row=store.get('tokens',config.get('id'))
    if not row:raise ValueError('Unknown credential.')
    audit.append(row['agentId'],'token-revoke','allowed',{'id':row['id']});row['revoked']=True;store.put('tokens',row);return {'ok':True}
def configure(config):
    row={'id':str(config.get('routeId','')),'roles':config.get('roles',['operator']),'sensitivities':config.get('sensitivities',['public','internal']),
         'production':config.get('production') is True,'approvalTools':config.get('approvalTools',[]),'inputPrice':float(config.get('inputPrice',0)),'outputPrice':float(config.get('outputPrice',0))}
    if not store.get('routes',row['id']):raise ValueError('Choose a route.')
    for key in ('roles','sensitivities','approvalTools'):
        if not isinstance(row[key],list) or len(row[key])>100 or any(not isinstance(x,str) or len(x)>100 for x in row[key]):raise ValueError('Invalid policy list.')
    if any(not 0<=row[k]<=10000 for k in ('inputPrice','outputPrice')):raise ValueError('Provide nonnegative prices per million tokens.')
    audit.append(row['id'],'context-policy','changed',row);return store.put('context-policy',row)
def authorize(route,identity,tool,payload,trace):
    rule=store.get('context-policy',route['id']) or {'roles':['operator'],'sensitivities':['public','internal'],'production':False,'approvalTools':[]}
    if identity['role'] not in rule['roles'] or identity['sensitivity'] not in rule['sensitivities']:raise PermissionError('Role or declared task sensitivity is outside the route policy.')
    if identity.get('tools') is not None and tool and tool not in identity['tools']:raise PermissionError('Tool is outside this task token scope.')
    if not tool or not (rule['production'] or HIGH.search(tool) or tool in rule['approvalTools']):return
    fingerprint=hashlib.sha256(audit.canonical({'route':route['id'],'task':identity['taskId'],'agent':identity['agentId'],'tool':tool,'payload':payload})).hexdigest()
    with LOCK:
        row=store.get('approvals',fingerprint)
        if row and row['state']=='approved' and row['expires']>time.time():
            row['state']='used';store.put('approvals',row);audit.append(identity['agentId'],'approval-consumed','allowed',{'id':fingerprint},trace);return
        if not row or row['state']!='pending' or row['expires']<=time.time():
            row={'id':fingerprint,'routeId':route['id'],'agentId':identity['agentId'],'taskId':identity['taskId'],'tool':tool,'state':'pending','expires':time.time()+300,'payloadHash':hashlib.sha256(audit.canonical(payload)).hexdigest()}
            store.put('approvals',row)
        raise PermissionError('Human approval required. Review the exact request in Security operations, then retry within five minutes. Approval ID: '+fingerprint)
def approve(config):
    row=store.get('approvals',config.get('id'))
    if not row or row['state']!='pending' or row['expires']<=time.time():raise ValueError('Approval is missing, consumed or expired.')
    if config.get('confirmation')!='APPROVE EXACT REQUEST':raise ValueError('Type APPROVE EXACT REQUEST after reviewing its originating request and payload hash.')
    audit.append('console','human-tool-approval','approved',row);row['state']='approved';store.put('approvals',row);return row
def observe(agent,tool,payload,usage=None):
    now=time.time();text=json.dumps(payload);hosts={urlsplit(x).hostname for x in re.findall(r'https?://[^\s"<>]+',text)[:100]};rules=[]
    usage=usage or {};tokens=usage.get('tokens');cost=usage.get('cost')
    with LOCK:
        queue=ACTIONS[agent];queue.append((now,tool));recent=[t for t in queue if t[0]>now-60]
        if len([t for t in recent if re.search('read|fetch|search',t[1] or '',re.I)])>=30:rules.append('bulk-read-burst')
        samples=BASE[agent]
        if len(samples)>=20:
            if hosts-DOMAINS[agent]:rules.append('new-external-domain')
            if tool and tool not in {s['tool'] for s in samples}:rules.append('new-tool-after-baseline')
            for metric,value in [('tokens',tokens),('cost',cost)]:
                known=[s[metric] for s in samples if isinstance(s[metric],(int,float))]
                if len(known)>=20 and isinstance(value,(int,float)) and value>max(statistics.mean(known)*3,statistics.mean(known)+4*statistics.pstdev(known),0):rules.append(metric+'-anomaly')
        samples.append({'tool':tool,'tokens':tokens,'cost':cost});DOMAINS[agent].update(hosts)
        if len(DOMAINS[agent])>500:DOMAINS[agent]=set(sorted(DOMAINS[agent])[-500:])
    if rules:store.event(agent,'behavior','alert',rules)
    return rules
def incident(config):
    asset=config.get('assetId');action=config.get('action')
    if not store.get('assets',asset):raise ValueError('Choose a registered asset.')
    if action not in ('quarantine','revoke','preserve'):raise ValueError('Choose quarantine, revoke or preserve.')
    audit.append(asset,'incident-'+action,'started',{'assetId':asset})
    if action in ('quarantine','revoke'):
        route=store.get('routes',asset)
        if route:route['enabled']=False;route['tokenExpires']=0;store.put('routes',route)
        for row in store.all_items('tokens'):
            if row['routeId']==asset:row['revoked']=True;store.put('tokens',row)
    evidence={'id':secrets.token_hex(12),'assetId':asset,'action':action,'createdAt':store.now(),'anchor':audit.verify()['anchor'],'events':[e for e in store.events(1000)['events'] if e['assetId']==asset]}
    store.put('incidents',evidence)
    return dict(evidence,scope='Gateway quarantine/revocation only. Direct upstream sessions and external credentials require their owner to revoke them.')
def memory_save(config):
    asset=config.get('assetId')
    if not store.get('assets',asset):raise ValueError('Choose an asset.')
    state=config.get('state')
    if not isinstance(state,dict) or len(audit.canonical(state))>100000:raise ValueError('Managed memory must be a JSON object below 100 KB.')
    # Memory snapshots are always encrypted with the supplied audit key, including when normal capture is disabled.
    cipher=audit.capture_key(audit.settings()['keyEnv']);nonce=secrets.token_bytes(12)
    import base64
    identity=secrets.token_hex(12);raw=audit.canonical(state)
    row={'id':identity,'assetId':asset,'nonce':base64.b64encode(nonce).decode(),'ciphertext':base64.b64encode(cipher.encrypt(nonce,raw,asset.encode())).decode(),'hash':hashlib.sha256(raw).hexdigest()}
    audit.append(asset,'managed-memory-snapshot','saved',{'id':identity,'hash':row['hash']});store.put('memory-snapshots',row);store.put('managed-memory',{'id':asset,'snapshotId':identity})
    return {'id':identity,'assetId':asset,'hash':row['hash']}
def memory_restore(config):
    row=store.get('memory-snapshots',config.get('id'))
    if not row or config.get('confirmation')!='RESTORE MANAGED MEMORY':raise ValueError('Select a snapshot and confirm RESTORE MANAGED MEMORY.')
    decrypt_memory(row)
    before=store.get('managed-memory',row['assetId']);audit.append(row['assetId'],'managed-memory-rollback','approved',{'before':before,'after':row['id']})
    store.put('managed-memory',{'id':row['assetId'],'snapshotId':row['id']});return {'ok':True,'previous':before,'scope':'App-managed encrypted memory pointer only; external agents must integrate this memory store.'}
def decrypt_memory(row):
    import base64
    try:
        cipher=audit.capture_key(audit.settings()['keyEnv'])
        raw=cipher.decrypt(base64.b64decode(row['nonce']),base64.b64decode(row['ciphertext']),row['assetId'].encode())
        if hashlib.sha256(raw).hexdigest()!=row['hash']:raise ValueError()
        return json.loads(raw)
    except Exception:raise ValueError('Managed snapshot integrity/key validation failed.') from None
def memory_read(asset):
    pointer=store.get('managed-memory',asset)
    if not pointer:raise ValueError('No managed memory snapshot for this agent.')
    return decrypt_memory(store.get('memory-snapshots',pointer['snapshotId']))
def snapshot():
    return {'tokens':[public(r) for r in store.all_items('tokens')],'approvals':store.all_items('approvals'),'policies':store.all_items('context-policy'),
            'incidents':store.all_items('incidents'),'memory':[{'id':r['id'],'assetId':r['assetId'],'hash':r['hash']} for r in store.all_items('memory-snapshots')],
            'baselines':[{'agent':k,'samples':len(v),'ready':len(v)>=20,'domains':len(DOMAINS[k])} for k,v in list(BASE.items())]}
