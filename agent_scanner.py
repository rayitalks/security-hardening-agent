"""Read-only agent assessments composed from the installed local scanners."""
from pathlib import Path

import containers
import engine
import skillspector_integration
import vulnerabilities


def assess(config, progress, stop):
    mode=config.get('mode','standard')
    if mode not in ('standard','deep'):
        raise ValueError('Choose Scan agent or Deep scan.')
    value=config.get('path','')
    if not isinstance(value,str) or not value.strip():
        raise ValueError('Enter the absolute path to the agent folder.')
    path=Path(value).expanduser()
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise ValueError('Choose an existing absolute local agent folder, not a URL or symlink.')
    path=str(path.resolve())
    skill_config={'target':path,'semantic':mode=='deep' and config.get('semantic') is True,
                  'endpoint':config.get('endpoint',''),'model':config.get('model','')}
    # Validate optional local-model settings before starting any scan.
    skillspector_integration.validate_input(skill_config)
    stages=[('Agent skills and instructions',lambda:skillspector_integration.run(skill_config,progress,stop))]
    if mode=='deep':
        stages += [
            ('Source-code checks',lambda:engine.scan_code(path)),
            ('Dependencies and exposure',lambda:vulnerabilities.assess({'path':path,'online':config.get('online') is True,'exposure':True},progress,stop)),
            ('Model-file inventory',lambda:engine.scan_artifacts(path))]
    findings=[];components=[];limits=[]
    for name,scan in stages:
        if stop.is_set():break
        progress(f'Agent scanner: {name} ({len(components)+1}/{len(stages)})…')
        try:
            report=scan()
            components.append({'name':name,'status':report.get('status','partial'),'report':report})
            for original in report.get('findings',[]):
                finding=dict(original);finding['component']=name;findings.append(finding)
            limits.extend(f'{name}: {x}' for x in report.get('limitations',[]))
        except Exception:
            if stop.is_set():break
            components.append({'name':name,'status':'failed'})
            findings.append(engine.finding(name+' could not complete','unknown',
                'The selected scanner was unavailable, failed, or could not process this input. Other completed stages remain available.',
                'Check the scanner installation and input permissions, then retry this stage separately. Do not treat missing coverage as a clean scan.','Agent scan coverage'))
    complete=len(components)==len(stages) and all(x['status']=='complete' for x in components)
    if stop.is_set():
        findings.append(engine.finding('Agent scan cancelled','unknown','Only completed stages are retained.','Run the remaining stages before drawing a conclusion.','Agent scan coverage'))
    return {'schema':'sha-report-v1','type':'Agent deep scan' if mode=='deep' else 'Agent scan',
        'target':path,'createdAt':containers.now(),'status':'cancelled' if stop.is_set() else 'complete' if complete else 'partial',
        'findings':findings,'agentAssessment':{'mode':mode,'stagesPlanned':len(stages),'stagesFinished':len(components),
            'publicLookups':mode=='deep' and config.get('online') is True,'localSemantic':skill_config['semantic'],
            'components':components},
        'coverage':{'stagesPlanned':len(stages),'stagesFinished':len(components),'findings':len(findings)},
        'limitations':['Inspects the selected on-disk agent project. It does not start the agent, invoke its tools, change files, or prove deployed permissions and runtime behavior.',
            'Static instruction/behavior indicators are not live prompt-injection tests. Use AI endpoints for synthetic model boundary testing.',
            'Deep scan adds source checks, dependency/exposure review and model-file inventory; it is not a malware or learned-backdoor verdict. Use the dedicated model and file scanners for those checks.',
            'Each stage retains its own limits and evidence. Partial/failed stages remain unknown. Cancellation may wait for a bounded source/inventory stage to finish.',
            'Public lookup sends only package identities/versions when enabled. Optional semantic analysis sends selected contents only to your configured local Ollama model.',*limits]}
