"""Explicit-scope local AI discovery, asset controls, and transparent risk prioritization."""
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.parse
import engine
import guardrails
import security_store as store

SKIP={'.git','.venv','venv','node_modules','vendor','dist','build','__pycache__','.runtime','.model-runtime','.data','.tools'}
KINDS={'model','agent','mcp','repository'}

def clean_target(value):
    if not isinstance(value,str) or not value.strip() or len(value)>2000:
        raise ValueError('Provide a target path or endpoint of at most 2,000 characters.')
    if value.startswith(('http://','https://')):
        url=urllib.parse.urlsplit(value)
        if url.username or url.password or url.query or url.fragment:
            raise ValueError('Do not store credential-bearing URLs, query strings or fragments.')
    return value.strip()

def save(config):
    kind=config.get('kind','agent')
    if kind not in KINDS:raise ValueError('Choose model, agent, mcp or repository.')
    target=clean_target(config.get('target',''))
    name=str(config.get('name','')).strip()[:200]
    if not name:raise ValueError('Give this asset a name.')
    identity=hashlib.sha256((kind+'\0'+target+'\0'+str(config.get('model',''))).encode()).hexdigest()[:24]
    previous=store.get('assets',identity) or {}
    result={**previous,'id':identity,'name':name,'kind':kind,'target':target,'model':str(config.get('model',''))[:300],
            'owner':str(config.get('owner',previous.get('owner','')))[:200],
            'environment':str(config.get('environment',previous.get('environment','local')))[:100],
            'source':str(config.get('source','Manual registration'))[:500],
            'discoveredAt':store.now(),'policyId':config.get('policyId',previous.get('policyId','default'))}
    guardrails.policy(result['policyId'])
    if 'transport' in config:result['transport']=str(config['transport'])[:80]
    return store.put('assets',result)

def assign(config):
    item=store.get('assets',config.get('assetId'))
    if not item:raise ValueError('Select an asset.')
    guardrails.policy(config.get('policyId','default'))
    item['policyId']=config.get('policyId','default')
    item['owner']=str(config.get('owner',item.get('owner','')))[:200]
    return store.put('assets',item)

def discover(config):
    raw=config.get('roots',[])
    if not isinstance(raw,list) or not 1<=len(raw)<=10:raise ValueError('Choose 1–10 local folders or config files.')
    items=[]; gaps=[]; visited=0; seen=set()
    def add(kind,target,name,source,**extra):
        try:
            item=save(dict(kind=kind,target=str(target),name=name,source=source,**extra))
            if item['id'] not in seen:seen.add(item['id']);items.append(item)
        except ValueError:gaps.append('One asset had an invalid or credential-bearing target and was omitted.')
    for value in raw:
        root=Path(value).expanduser()
        if not root.is_absolute() or not root.exists() or root.is_symlink() or getattr(root,'is_junction',lambda:False)():
            raise ValueError('Discovery roots must be existing absolute paths, not links or junctions.')
        root=root.resolve()
        paths=[]
        if root.is_file():paths=[root]
        else:
            for current,dirs,files in os.walk(root,followlinks=False,onerror=lambda _:gaps.append('A folder could not be read.')):
                dirs[:]=[d for d in dirs if d not in SKIP and not (Path(current)/d).is_symlink() and not getattr(Path(current)/d,'is_junction',lambda:False)() and (Path(current)/d).resolve().is_relative_to(root)]
                for name in files:
                    visited+=1
                    if visited>5000:break
                    if name in ('AGENTS.md','SKILL.md','CLAUDE.md','.cursorrules','mcp.json','.mcp.json','claude_desktop_config.json','config.toml'):
                        paths.append(Path(current)/name)
                if visited>5000:gaps.append('Discovery stopped at 5,000 entries.');break
        for path in paths:
            if path.is_symlink() or not path.resolve().is_relative_to(root if root.is_dir() else root.parent):continue
            if path.name in ('AGENTS.md','SKILL.md','CLAUDE.md','.cursorrules'):
                add('agent',path.parent,path.parent.name,'Instruction file: '+str(path));continue
            try:
                if path.stat().st_size>1_000_000:gaps.append('Config over 1 MB was skipped.');continue
                if path.suffix=='.toml':
                    try:import tomllib
                    except ImportError:gaps.append('TOML discovery requires Python 3.11+.');continue
                    data=tomllib.loads(path.read_text(encoding='utf-8-sig'))
                else:data=json.loads(path.read_text(encoding='utf-8-sig'))
                entries=data.get('mcpServers',data.get('mcp_servers',data.get('servers',{})))
                if not isinstance(entries,dict):continue
                for name,entry in list(entries.items())[:200]:
                    if not isinstance(entry,dict):continue
                    url=entry.get('url')
                    target=url if isinstance(url,str) else str(path)+'#'+str(name)
                    add('mcp',target,str(name),'MCP config: '+str(path),transport='http' if url else 'stdio (configuration only)')
            except (ValueError,OSError,TypeError):gaps.append('One configuration file could not be parsed.')
    return {'assets':items,'coverage':{'entriesExamined':visited,'assetsFound':len(items),'gaps':gaps},
            'limitations':['Only selected roots and recognized configuration/instruction names were inspected. Discovered configuration is not proof of a running service. Commands, arguments and environment values were not retained or executed.']}

def discover_models(config):
    if config.get('authorized') is not True:raise ValueError('Confirm authorization for model discovery.')
    inventory=engine.discover(config)
    items=[]
    for model in inventory['models']:
        item=save({'kind':'model','target':inventory['target'],'model':model['name'],'name':model['name'],'source':'Live model inventory','transport':inventory['kind']})
        item['endpointChecks']=inventory['checks'];items.append(store.put('assets',item))
    return {'assets':items,'checks':inventory['checks'],'limitations':['Model enumeration checks the selected endpoint only. It does not inventory a cloud account.']}

def attach_report(config):
    item=store.get('assets',config.get('assetId'));report=config.get('report')
    if not item or not isinstance(report,dict):raise ValueError('Choose an asset and an assessment report.')
    if str(report.get('target','')).rstrip('/') != item['target'].rstrip('/'):
        raise ValueError('Report target must exactly match the asset target. Register the correct target first.')
    if item.get('model') and report.get('model') != item['model']:
        raise ValueError('The assessment model must match this asset model.')
    rows=list(report.get('findings',[]))+list(report.get('tests',[]))
    counts={s:sum(isinstance(r,dict) and r.get('status')==s for r in rows) for s in ('attention','review','unknown','pass')}
    item['assessment']={'createdAt':str(report.get('createdAt',''))[:80],'type':str(report.get('type',''))[:100],
                        'status':str(report.get('status',''))[:30],'counts':counts,'source':'User-linked report; exact target checked'}
    return store.put('assets',item)

def controls(item,gateway_running=False):
    selected=guardrails.policy(item.get('policyId','default'))
    routes=[r for r in store.all_items('routes') if r['assetId']==item['id'] and r.get('enabled')]
    route=routes[0] if routes else None
    assessment=item.get('assessment')
    fresh=False
    if assessment:
        try:
            import datetime as dt
            age=(dt.datetime.now(dt.timezone.utc)-dt.datetime.fromisoformat(assessment['createdAt'].replace('Z','+00:00'))).total_seconds()
            fresh=0<=age<=7*86400 and assessment['status']=='complete'
        except (ValueError,TypeError):pass
    records=[]
    def check(name,state,weight,evidence):records.append(dict(name=name,status=state,weight=weight,evidence=evidence))
    check('Accountable owner','pass' if item.get('owner') else 'attention',5,'Owner recorded' if item.get('owner') else 'No owner assigned')
    check('Gateway route','pass' if route and gateway_running else 'attention',20,'Gateway listening with an enabled route; direct traffic bypasses it' if route and gateway_running else 'No active gateway route')
    for category,weight in [('security',15),('privacy',15),('safety',10)]:
        enabled=bool(route and gateway_running and selected.get(category) and selected['mode']=='block')
        check(category.title()+' enforcement','pass' if enabled else 'attention',weight,'Configured for routed requests only' if enabled else 'Not currently enforced by this app')
    endpoint=item.get('endpointChecks',[])
    auth=next((x for x in endpoint if x['name']=='Unauthenticated model inventory'),None)
    check('Upstream authentication','pass' if auth and auth['status']=='pass' else 'review' if auth else 'unknown',10,auth['evidence'] if auth else 'Upstream authentication has not been observed')
    parsed=urllib.parse.urlsplit(item['target'])
    secure=parsed.scheme=='https' or parsed.hostname in ('localhost','127.0.0.1','::1')
    check('Transport','pass' if secure else 'unknown',10,'HTTPS or loopback target' if secure else 'Transport not verified from asset metadata')
    check('Recent complete assessment','pass' if fresh else 'unknown',15,'Complete report within seven days' if fresh else 'No recent complete linked report')
    penalties={'pass':0,'review':.5,'unknown':.5,'attention':1}
    posture=sum(r['weight']*penalties[r['status']] for r in records)
    counts=assessment.get('counts',{}) if assessment else {}
    findings=min(40,20*counts.get('attention',0)+5*counts.get('review',0)) if fresh else 20
    score=round(.6*posture+findings)
    return {'checks':records,'risk':{'score':score,'label':'High' if score>=65 else 'Moderate' if score>=30 else 'Lower',
            'evidenceCoveragePercent':round(100*sum(r['weight'] for r in records if r['status']!='unknown')/100),
            'components':{'controlDeficit':round(.6*posture,1),'findingContribution':findings},
            'rubric':'0–100 prioritization index = 60% of weighted control deficits + up to 40 finding points. Unknown controls count half; missing/stale assessment contributes 20. Fresh attention=20 and review=5 per finding, capped at 40. Not probability, CVSS or safety certification.'}}

def snapshot(gateway_running=False):
    return {'assets':[dict(item,**controls(item,gateway_running)) for item in store.all_items('assets')],
            'policies':[guardrails.policy()]+[p for p in store.all_items('policies') if p['id']!='default'],
            'scope':'Local and explicitly registered assets. No cloud account connector or whole-network discovery.'}
