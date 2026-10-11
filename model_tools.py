"""Model supply-chain and native antivirus integration."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sys
import tempfile
import time

import containers
import engine
import vulnerabilities

ROOT=Path(__file__).resolve().parent


def runtime():
    return ROOT/'.model-runtime'/('Scripts/python.exe' if os.name=='nt' else 'bin/python')


def status():
    defender=Path(os.environ.get('ProgramFiles',r'C:\Program Files'))/'Windows Defender'/'MpCmdRun.exe'
    return {'modelInstalled':runtime().is_file(),'modelVersion':'0.2.52','packetInstalled':runtime().is_file(),
        'antivirus':'Microsoft Defender' if os.name=='nt' and defender.is_file() else ('ClamAV' if shutil.which('clamscan') else None)}


def target(value):
    path=Path(value).expanduser()
    if not path.is_absolute() or not path.exists() or path.is_symlink():
        raise ValueError('Choose an existing absolute local file/folder path, not a URL or symlink.')
    return path.resolve()


def worker(script,config,stop,timeout=210):
    if not runtime().is_file():
        raise ValueError('Model/packet runtime is missing. Run install_model_tools.py with Python 3.10–3.13.')
    with tempfile.TemporaryDirectory(prefix='sha-model-') as tmp:
        temp=Path(tmp);output=temp/'result.json';request=temp/'request.json'
        config=dict(config,output=str(output))
        request.write_text(json.dumps(config),encoding='utf-8')
        env=containers.environment()
        env.update(HOME=tmp,USERPROFILE=tmp,XDG_CACHE_HOME=tmp,XDG_CONFIG_HOME=tmp,TEMP=tmp,TMP=tmp,TMPDIR=tmp,
            PROMPTFOO_DISABLE_TELEMETRY='1',MODELAUDIT_DISABLE_TELEMETRY='1',DO_NOT_TRACK='1',PYTHONDONTWRITEBYTECODE='1')
        code,_,_=containers.command([str(runtime()),str(ROOT/script),str(request)],stop,timeout,env,temp)
        if code or not output.is_file():
            if script=='packet_worker.py':
                raise ValueError('Traffic analysis could not complete. Check capture format, interface permissions and installed capture support (Npcap for Windows). No traffic verdict is available.')
            raise ValueError('Local scanner could not complete. Check supported formats, optional dependencies and size limits; no safety verdict is available.')
        return vulnerabilities.read_json(output,16*1024*1024)


def normalize(data,path):
    findings=[]
    for issue in data.get('issues',[])[:1000]:
        severity=str(issue.get('severity','unknown'))
        findings.append(engine.finding(f"{severity.upper()} · {issue.get('name','Model scanner finding')}",
            'attention' if severity=='critical' else ('review' if severity in ('warning','info','debug') else 'unknown'),
            f"{issue.get('location','')}\n{issue.get('description','')}\nMatched source text and payloads were omitted.",
            'Review the model source and indicated file before loading it. Use trusted non-executable formats where possible, verify provenance, and rescan a patched artifact.',
            'Model supply chain',str(issue.get('code') or 'ModelAudit')))
    complete=data.get('success') is True and not data.get('hasErrors') and data.get('filesScanned',0)>0 and data.get('issueCount',0)<=1000
    if not complete:
        findings.append(engine.finding('Model scan coverage is incomplete','unknown','The scanner reported incomplete/failed coverage, no scanned files, or findings beyond the limit. This may include missing optional format dependencies.','Check format support and scan smaller sets; do not treat incomplete coverage as a clean model.','Model coverage'))
    if not findings:
        findings.append(engine.finding('No model scanner issues returned','review','The static scanner returned no issues within its supported coverage.','Static checks cannot certify that weights are free of learned backdoors, poisoning or harmful behavior. Run behavioral tests separately.','Model coverage'))
    return findings,complete


def supply_chain(config,progress,stop):
    path=target(config.get('path',''));findings=[]
    expected=config.get('sha256','').strip().lower()
    if expected and (not path.is_file() or not re.fullmatch(r'[a-f0-9]{64}',expected)):
        raise ValueError('Digest verification needs a single file and a 64-character SHA-256 from a trusted source.')
    progress('Running offline static model supply-chain analysis…')
    data=worker('model_worker.py',{'path':str(path)},stop)
    findings,complete=normalize(data,path)
    digest=None
    if expected and not stop.is_set():
        progress('Comparing the artifact with the expected SHA-256…')
        if path.stat().st_size>16*1024**3:
            findings.append(engine.finding('Digest verification skipped','unknown','File exceeds the 16 GB hashing limit.','Verify this artifact with a trusted large-file workflow.','Model provenance'));complete=False
        else:
            sha=hashlib.sha256()
            with path.open('rb') as file:
                for chunk in iter(lambda:file.read(1024*1024),b''):
                    if stop.is_set(): break
                    sha.update(chunk)
            if not stop.is_set():
                digest=sha.hexdigest()
                findings.append(engine.finding('Trusted digest comparison','pass' if digest==expected else 'attention',f'Observed SHA-256: {digest}. '+('Matches' if digest==expected else 'Does not match')+' the digest supplied by you.','Confirm the expected digest came from a trusted independent source. A match establishes identity, not model safety.','Model provenance'))
    dependency=None
    if config.get('dependencies') is True and path.is_dir() and not stop.is_set():
        dependency=vulnerabilities.assess({'path':str(path),'online':config.get('online') is True},progress,stop)
        findings.extend(dependency['findings']);complete=complete and dependency['status']=='complete'
    return {'schema':'sha-report-v1','type':'Model supply-chain assessment','createdAt':containers.now(),'target':str(path),
        'status':'cancelled' if stop.is_set() else ('complete' if complete else 'partial'),'findings':findings,
        'coverage':{k:v for k,v in data.items() if k!='issues'},'modelAssessment':{'engine':'ModelAudit','version':data.get('version'),'files':data.get('filesScanned'),'checks':data.get('checks'),'sha256':digest},
        'dependencyEvidence':dependency,
        'limitations':['Offline static ModelAudit analysis; model files are not intentionally loaded or executed. No model download or telemetry is enabled.',
            'Static findings can include unsafe serialization/opcodes, metadata, archive and model-configuration indicators. They do not establish training-data provenance, absence of learned backdoors, poisoning, or safe model behavior.',
            'Format coverage depends on installed optional dependencies. Missing/unsupported analysis remains incomplete. Python network guard is not a malware sandbox.',
            'Up to 180 seconds, 8 GB per file, 16 GB total scanned data, 10,000 inventory entries and 1,000 model findings. Large/complex inputs may be partial.',
            'Source payloads and free-text scanner details are omitted; report file locations may be sensitive. Dependency lookups are separate and send only package identities/versions when selected.',
            'User-provided expected hashes are not authenticated. A matching hash is not a malware or model-safety verdict.']}


def malware(config,progress,stop):
    path=target(config.get('path',''))
    engine_name=status()['antivirus']
    if not engine_name:
        raise ValueError('No supported antivirus engine is available. Use Microsoft Defender on Windows or install ClamAV on Linux/macOS.')
    findings=[];complete=False
    with tempfile.TemporaryDirectory(prefix='sha-av-') as tmp:
        if engine_name=='Microsoft Defender':
            binary=Path(os.environ.get('ProgramFiles',r'C:\Program Files'))/'Windows Defender'/'MpCmdRun.exe'
            args=[str(binary),'-Scan','-ScanType','3','-File',str(path),'-DisableRemediation']
            progress('Running a Microsoft Defender custom scan with remediation disabled…')
            code,out,err=containers.command(args,stop,330,cwd=tmp)
            text=(out+err).decode('utf-8',errors='replace')
            complete=code==0
            if code==0:
                findings.append(engine.finding('Defender scan completed','review','Microsoft Defender returned success for the requested custom scan. Remediation was disabled for this invocation. Raw logs are not included.','Review Defender history for any engine-specific exclusions; no findings does not guarantee a file is safe.','File malware'))
            else:
                findings.append(engine.finding('Defender needs review','unknown',f'Defender returned code {code}. This can indicate an unresolved detection or a scan failure; a clean result is not established.','Review Windows Security threat history and engine status. This app did not request remediation.','File malware'))
        else:
            database=ROOT/'.data/clamav' if not os.environ.get('SHA_CONTAINER') else Path('/data/clamav')
            database.mkdir(parents=True,exist_ok=True)
            if config.get('update') is True:
                updater=shutil.which('freshclam')
                if not updater:raise ValueError('ClamAV updater is unavailable. Install freshclam or provide current definitions in the app data directory.')
                progress('Downloading official ClamAV definitions; no scanned files are sent…')
                settings=Path(tmp)/'freshclam.conf'
                settings.write_text('DatabaseDirectory "'+str(database)+'"\nDatabaseMirror database.clamav.net\nConnectTimeout 10\nReceiveTimeout 60\nMaxAttempts 2\n',encoding='utf-8')
                result,_,_=containers.command([updater,'--config-file='+str(settings),'--stdout'],stop,240,cwd=tmp)
                if result:
                    findings.append(engine.finding('Definition update incomplete','unknown','The official signature download did not complete. Existing definitions may be stale.','Check network access to the official ClamAV database service and retry later.','File malware'))
            definitions=[database/x for x in ('daily.cvd','daily.cld') if (database/x).is_file()]
            fresh=bool(definitions) and time.time()-max(x.stat().st_mtime for x in definitions)<=7*86400
            progress('Running local ClamAV signature checks…')
            args=[shutil.which('clamscan'),'--database='+str(database),'--recursive','--infected','--no-summary','--max-filesize=512M','--max-scansize=1G','--max-recursion=20','--alert-exceeds-max=yes','--follow-dir-symlinks=0','--follow-file-symlinks=0',str(path)]
            code,out,err=containers.command(args,stop,330,cwd=tmp)
            complete=code in (0,1) and not err.strip() and fresh and not findings
            for line in out.decode('utf-8',errors='replace').splitlines()[:1000]:
                if line.endswith(' FOUND'):
                    findings.append(engine.finding('Antivirus signature / scan-limit alert','attention',line[:1000],'Do not execute this file. Verify the signature with your antivirus provider and investigate before quarantining or deleting it.','File malware','ClamAV'))
            if not complete:
                findings.append(engine.finding('ClamAV coverage incomplete','unknown',f'Scanner returned code {code}, warnings, or missing/older-than-seven-day daily definition files. Definition file age is a freshness indicator, not authenticated publication time.','Select the official definition update and retry supported files.','File malware'))
            elif not findings:
                findings.append(engine.finding('No ClamAV signatures returned','review','The scan returned no matching malware signatures within its configured limits.','Confirm definitions are current; no antivirus can rule out all malware.','File malware'))
    return {'schema':'sha-report-v1','type':'File malware scan','createdAt':containers.now(),'target':str(path),'status':'cancelled' if stop.is_set() else ('complete' if complete else 'partial'),'findings':findings,
        'coverage':{'engine':engine_name,'automaticRemediation':False,'scanCompleted':complete},
        'limitations':['This is a local antivirus scan, not a model behavior or learned-backdoor detector. Definitions, engine exclusions and format/size limits affect coverage.',
            'This app requests no deletion, quarantine or remediation. Existing real-time antivirus policies remain active independently.',
            'The app does not enable cloud sample submission or upload files. Existing antivirus cloud policies are controlled by the operating system.',
            'Five-minute scan budget; ClamAV limits individual files to 512 MB and expanded data to 1 GB. Use the model supply-chain scanner for larger weights.',
            'Cancellation stops the app from waiting. A Windows Defender service scan may continue independently; the app does not cancel unrelated system scans.',
            'A success code or absence of signature matches is not a guarantee that a file is safe.']}
