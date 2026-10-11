"""Evidence-driven remediation records, AI-BOM drift and reporting crosswalks."""
import datetime as dt
import hashlib
import json
import secrets
import audit_trail as audit
import security_store as store
import guardrails
import asset_registry

SOURCES={'OWASP LLM 2025':'https://genai.owasp.org/llm-top-10/','OWASP Agentic':'https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/',
 'MITRE ATLAS':'https://atlas.mitre.org/techniques/AML.T0051','NIST AI RMF 1.0':'https://www.nist.gov/itl/ai-risk-management-framework',
 'ISO/IEC 42001:2023':'https://www.iso.org/standard/42001','EU AI Act':'https://eur-lex.europa.eu/eli/reg/2024/1689/oj'}
def ingest(report,config,assessment='team_suite'):
    cases=report.get('findings',[]) if assessment=='team_suite' else report.get('tests',[])
    for index,original in enumerate(cases):
        case=dict(original)
        case.setdefault('id',('VAL-' if assessment=='validate' else 'RT-')+str(index+1))
        case.setdefault('mapping',{'owaspLLM':['LLM01:2025'],'owaspAgentic':['ASI01'],'mitreAtlas':['AML.T0051']})
        identity=hashlib.sha256(audit.canonical([report['target'],report.get('model'),case['id']])).hexdigest()[:24]
        previous=store.get('remediations',identity)
        if case['status']!='attention' and not previous:continue
        row=previous or {'id':identity,'caseId':case['id'],'target':report['target'],'model':report.get('model'),'firstSeen':store.now(),'state':'open',
                        'guardrailTest':{'input':case['prompt'],'expectedDecision':'block'},'mapping':case.get('frameworkMapping',case['mapping']),'detectionProposal':'Alert on untrusted instruction override or forbidden tool proposal; validate against benign cases before enforcement.'}
        row['lastRetest']=store.now();row['lastResult']=case['status']
        if case['status']=='pass':row['state']='resolved';row['resolvedAt']=store.now()
        elif case['status']=='attention':row['state']='open';row.pop('resolvedAt',None)
        row['retestAssessment']=assessment
        row['retest']={k:config[k] for k in ('kind','url','model','keyEnv','engagementId','seed','maxCases','adaptive','budgetSeconds','authorized') if k in config}
        if assessment=='team_suite':row['retest']['caseIds']=[case['id']];row['retest']['maxCases']=1
        store.put('remediations',row)
def guardrail_test(config):
    row=store.get('remediations',config.get('id'))
    if not row:raise ValueError('Select a remediation.')
    decision=guardrails.inspect(row['guardrailTest']['input'],guardrails.policy(config.get('policyId','default')))
    row['guardrailResult']={'time':store.now(),'policyId':config.get('policyId','default'),'pass':decision['decision']=='block','decision':decision};store.put('remediations',row)
    return row['guardrailResult']
def inventory():
    assets=store.all_items('assets');policies=store.all_items('policies')
    return {'schema':'ray-i-ai-bom-v1','assets':[{k:v for k,v in a.items() if k not in ('updatedAt','assessment','endpointChecks')} for a in assets],
            'policies':[guardrails.DEFAULT]+policies,'routes':[{k:v for k,v in r.items() if k not in ('tokenHash','updatedAt','tokenExpires')} for r in store.all_items('routes')],
            'integrityMonitors':[{'id':r['id'],'name':r.get('name'),'assetId':r.get('assetId'),'status':r.get('status')} for r in store.all_items('monitors')]}
def bom(config=None):
    value=inventory();digest=hashlib.sha256(audit.canonical(value)).hexdigest();baseline=store.get('settings','ai-bom')
    return {'inventory':value,'sha256':digest,'baseline':baseline,'drift':None if not baseline else digest!=baseline['sha256'],
            'scope':'Registered models, agents, prompt policies, tool descriptor pins, routes and linked monitors. No undeclared deployments discovered by this export.'}
def baseline(config):
    value=bom();audit.append('console','ai-bom-baseline','accepted',{'sha256':value['sha256']})
    return store.put('settings',{'id':'ai-bom','sha256':value['sha256'],'inventory':value['inventory']})
def snapshot(gateway=False):
    rem=store.all_items('remediations');assets=asset_registry.snapshot(gateway)['assets'];rows=[]
    for a in assets:
        relevant=[r for r in rem if r['target'].rstrip('/')==a['target'].rstrip('/') and (not a.get('model') or a['model']==r['model'])]
        fixed=[(dt.datetime.fromisoformat(r['resolvedAt'])-dt.datetime.fromisoformat(r['firstSeen'])).total_seconds()/3600 for r in relevant if r.get('resolvedAt')]
        policy=guardrails.policy(a.get('policyId','default'))
        from defense_ops import HIGH
        rows.append({'id':a['id'],'name':a['name'],'risk':a['risk'],'target':a['target'],'privilegedTools':len([t for t in policy['allowedTools'] if HIGH.search(t)]),'openFindings':sum(r['state']=='open' for r in relevant),'meanHoursToFix':sum(fixed)/len(fixed) if fixed else None})
    return {'posture':rows,'remediations':rem,'aiBom':bom(),'sources':SOURCES}
def compliance(config=None):
    rows=[('Asset and prompt inventory','MAP','AI system inventory and organizational context','Technical documentation / risk management'),
          ('Red-team results and retests','MEASURE','AI risk assessment and performance evaluation','Accuracy, robustness and cybersecurity'),
          ('Roles, approvals and scoped tokens','GOVERN','Roles, responsibilities and operational controls','Human oversight'),
          ('Audit records and incident response','MANAGE','Monitoring, corrective action and improvement','Record-keeping and post-market monitoring')]
    return {'title':'AI governance evidence crosswalk','createdAt':store.now(),'sources':SOURCES,'mappings':[{'control':a,'nistAIRMF':b,'iso42001Theme':c,'euAIActTheme':d} for a,b,c,d in rows],
            'evidence':snapshot(),'audit':audit.verify(),'limitations':['Indicative topic-level mappings, not a clause-level audit, legal applicability assessment, ISO certification or EU AI Act compliance determination.','An owner must establish scope, risk classification, lawful processing, oversight and organizational evidence. Missing controls remain gaps.']}
