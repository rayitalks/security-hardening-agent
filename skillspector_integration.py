"""Pinned SkillSpector subprocess adapter and report normalization."""
import datetime as dt
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
VERSION = '2.12.0'
COMMIT = '35270064e42230dbc566e4134c55b5d581355db3'
SOURCE = 'https://github.com/NVIDIA/SkillSpector'

def python_path():
    if os.environ.get('SHA_CONTAINER') == '1':
        return sys.executable
    return str(ROOT / '.runtime' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python'))

def clean_environment(temp):
    # Do not pass cloud credentials, global provider settings, proxies, or tracing keys.
    keep = ('PATH','SYSTEMROOT','WINDIR','COMSPEC','PATHEXT','LD_LIBRARY_PATH')
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env.update(HOME=str(temp), USERPROFILE=str(temp), TMP=str(temp), TEMP=str(temp), TMPDIR=str(temp),
               PYTHONUTF8='1', PYTHONIOENCODING='utf-8', PYTHONDONTWRITEBYTECODE='1',
               GIT_TERMINAL_PROMPT='0', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
               LANGSMITH_TRACING='false', LANGCHAIN_TRACING_V2='false', AWS_EC2_METADATA_DISABLED='true')
    return env

def status():
    python = python_path()
    if not Path(python).is_file():
        return {'installed':False, 'expectedVersion':VERSION, 'source':SOURCE, 'message':'Run Install-SkillSpector.bat (Windows) or python3 install_skillspector.py.'}
    try:
        result = subprocess.run([python,'-c','import importlib.metadata as m; import yara; print(m.version("skillspector"))'],capture_output=True,text=True,timeout=20,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        version = result.stdout.strip()
        return {'installed':result.returncode == 0 and version == VERSION,'version':version if result.returncode == 0 else None,
                'expectedVersion':VERSION,'commit':COMMIT,'source':SOURCE,
                'message':'NVIDIA SkillSpector is ready.' if result.returncode == 0 and version == VERSION else 'Scanner installation is missing or incompatible. Run its installer.'}
    except (OSError,subprocess.TimeoutExpired):
        return {'installed':False,'expectedVersion':VERSION,'source':SOURCE,'message':'Could not start the scanner runtime. Run its installer.'}

def validate_input(config):
    target = config.get('target','')
    if not isinstance(target,str) or not target.strip():
        raise ValueError('Enter a local folder, file, ZIP, or public GitHub repository URL.')
    target = target.strip()
    if target.startswith('https://'):
        if not re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?',target):
            raise ValueError('Remote scans support a public GitHub repository URL: https://github.com/owner/repository. Clone other repositories locally first.')
        if config.get('allowDownload') is not True:
            raise ValueError('Allow downloading this public repository, or choose a local path for a fully offline scan.')
    else:
        path = Path(target).expanduser()
        if not path.is_absolute() or not path.exists():
            raise ValueError('Enter an existing absolute local path, or a public GitHub repository URL.')
        target = str(path.resolve())
    semantic = config.get('semantic') is True
    endpoint, model = '', ''
    if semantic:
        endpoint = str(config.get('endpoint','')).strip().rstrip('/')
        p = urlsplit(endpoint)
        hosts = {'127.0.0.1','localhost','::1'}
        if os.environ.get('SHA_CONTAINER') == '1':
            hosts.add('host.docker.internal')
        if p.scheme != 'http' or p.hostname not in hosts or p.username or p.password or p.query or p.fragment or p.path not in ('','/v1') or p.port == 8765:
            raise ValueError('Local semantic analysis requires a local Ollama HTTP endpoint, e.g. http://127.0.0.1:11434/v1.')
        endpoint = endpoint if endpoint.endswith('/v1') else endpoint+'/v1'
        model = str(config.get('model','')).strip()
        if not model or len(model)>200 or any(c.isspace() for c in model):
            raise ValueError('Enter an installed local model name for semantic analysis.')
    return target,semantic,endpoint,model

def wait_process(args, cwd, env, stop, timeout, log):
    with open(log,'wb') as output:
        proc = subprocess.Popen(args,cwd=cwd,env=env,stdout=output,stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        started=time.monotonic()
        while proc.poll() is None:
            if stop.is_set() or time.monotonic()-started>timeout:
                proc.terminate()
                try: proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill();proc.wait()
                raise ValueError('SkillSpector scan cancelled; no complete report is available.' if stop.is_set() else 'SkillSpector exceeded its time limit. Narrow the scan to one skill or smaller repository.')
            time.sleep(.15)
        return proc.returncode

def normalize(raw, target, semantic, elapsed, repository_commit=None):
    issues = raw.get('issues')
    if not isinstance(issues,list) or not isinstance(raw.get('metadata'),dict) or 'analysis_completeness' not in raw:
        raise ValueError('SkillSpector returned an unsupported report schema.')
    metadata=raw['metadata']; completeness=raw['analysis_completeness']
    if not isinstance(completeness,dict):
        raise ValueError('SkillSpector returned invalid completeness evidence.')
    findings=[]
    # Do not propagate source snippets or provider messages into the app/report.
    for issue in issues[:1000]:
        if not isinstance(issue,dict):
            continue
        severity=str(issue.get('severity','UNKNOWN')).upper()
        rule=str(issue.get('id','unknown'))[:100]
        category=str(issue.get('category') or 'Security finding')[:120]
        loc=issue.get('location',{}) if isinstance(issue.get('location'),dict) else {}
        location=str(loc.get('file',''))[:1000]
        if repository_commit:
            # Upstream often returns absolute paths under a temporary clone.
            location=location.split('repository'+os.sep,1)[-1]
        line=loc.get('start_line',1)
        findings.append({'name':f'{rule} · {category}', 'status':'attention' if severity in ('HIGH','CRITICAL') else 'review',
                         'evidence':f'NVIDIA SkillSpector severity: {severity}; confidence: {issue.get("confidence","unspecified")}. Location: {location}:{line}. Source snippets are omitted.',
                         'recommendation':remediation(rule), 'area':'SkillSpector', 'mapping':rule,
                         'file':location,'line':line,'severity':severity,'confidence':issue.get('confidence')})
    llm_used = metadata.get('llm_used')
    # Actual upstream counters are preserved rather than claiming a requested LLM ran.
    semantic_info={k:metadata[k] for k in ('llm_requested','llm_available','llm_degraded','llm_used','meta_analysis_applied','llm_calls_attempted','llm_calls_succeeded') if k in metadata}
    incomplete = completeness.get('is_complete') is not True or raw.get('execution_successful') is not True or len(issues)>1000
    if incomplete:
        findings.append({'name':'Incomplete SkillSpector coverage','status':'unknown','evidence':'The scanner reported partial or unverified coverage. Review the coverage counters and limitations.','recommendation':'Review excluded files, missing analyzers, and scan limits; rerun with a narrower scope where needed.','area':'SkillSpector'})
    if semantic and (metadata.get('llm_degraded') or not metadata.get('llm_available')):
        incomplete=True
        findings.append({'name':'Local semantic analysis unavailable or degraded','status':'unknown','evidence':'The requested local LLM did not complete all expected semantic analysis. Static findings may still be available.','recommendation':'Start the local Ollama model, verify its endpoint, and rerun.','area':'SkillSpector'})
    coverage={k:completeness[k] for k in ('status','coverage_percent','fully_inspected_files','partially_inspected_files','entirely_uninspected_files') if k in completeness}
    coverage.update(reportedFindings=len(issues),displayedFindings=min(1000,len(issues)))
    limitations=['NVIDIA SkillSpector scans agent skills and code. It does not analyze model weights or certify model behavior.',
                 'Live OSV dependency lookup is disabled; only the upstream bundled fallback is available. Missing CVE evidence is not a clean dependency verdict.',
                 'No cloud LLM or cloud tracing. Static scans block network access during analysis; optional semantic scans allow only the selected local model endpoint.',
                 'Source snippets and upstream free-text payloads are omitted from exported findings to reduce accidental secret disclosure.',
                 'A clean or low-score scan is not a guarantee. Upstream file, format, time, and analyzer coverage limits apply.',
                 'Transitive URL following, author-supplied suppression baselines, and skill execution are disabled.']
    if not semantic:
        limitations.append('Static-only scan: LLM semantic analysis was not requested.')
    # Content-free reason codes/counts retained, instead of raw attacker-controlled payloads.
    reasons=[]
    for row in completeness.get('limitations',[])[:40]:
        if isinstance(row,dict):
            reasons.append({k:row[k] for k in ('reason','reason_code','analyzer_id','status','limit_bytes','limit_seconds') if k in row})
    return {'schema':'sha-report-v1','type':'skillspector','createdAt':dt.datetime.now(dt.timezone.utc).isoformat(),
            'target':target,'status':'partial' if incomplete else 'complete','findings':findings,'limitations':limitations,'coverage':coverage,
            'scanner':{'name':'NVIDIA SkillSpector','version':VERSION,'commit':COMMIT,'source':SOURCE,'license':'Apache-2.0',
                       'mode':'local semantic + static' if semantic else 'offline static','durationSeconds':round(elapsed,1),
                       'semantic':semantic_info,'coverageReasons':reasons,'repositoryCommit':repository_commit}}

def remediation(rule):
    prefix=re.match('[A-Za-z]+',rule)
    prefix=prefix.group(0).upper() if prefix else ''
    fixes={'P':'Inspect instructions at the reported location. Remove attempts to override system policy or trust untrusted content.',
           'DE':'Review data access and outbound destinations; minimize permissions and prohibit unapproved transfer of secrets.',
           'PE':'Remove unnecessary privilege escalation and require explicit authorization for privileged actions.',
           'SC':'Verify dependency provenance, pin reviewed versions, and perform an up-to-date vulnerability review.',
           'DC':'Review the flagged executable-code pattern and trace untrusted inputs before using the skill.',
           'TP':'Review tool descriptions and schemas for injected instructions or mismatched behavior.',
           'MCP':'Review MCP tool permissions and descriptions; grant only the access needed.'}
    return fixes.get(prefix,'Inspect the reported file and line against the SkillSpector rule. Validate the finding in context before installing or using this skill.')

def run(config, progress, stop):
    target,semantic,endpoint,model=validate_input(config)
    installed=status()
    if not installed['installed']:
        raise ValueError(installed['message'])
    started=time.monotonic()
    with tempfile.TemporaryDirectory(prefix='ray-i-skillspector-') as folder:
        tmp=Path(folder); env=clean_environment(tmp); local_target=target; repo_commit=None
        if target.startswith('https://'):
            git=shutil.which('git')
            if not git:
                raise ValueError('Git is required to download public repositories. Install Git or scan a local copy.')
            progress('Downloading the selected public GitHub repository…')
            destination=tmp/'repository'
            code=wait_process([git,'-c','core.hooksPath='+os.devnull,'clone','--depth','1','--no-tags','--',target,str(destination)],tmp,env,stop,100,tmp/'download.log')
            if code:
                raise ValueError('Could not download the public repository. Check its URL and network access; private repository authentication is not enabled.')
            size=0
            for path in destination.rglob('*'):
                if path.is_file() and not path.is_symlink():
                    size+=path.stat().st_size
                    if size>100*1024*1024:
                        raise ValueError('Repository exceeds the 100 MiB intake limit. Scan a smaller local folder.')
            commit=subprocess.run([git,'-C',str(destination),'rev-parse','HEAD'],capture_output=True,text=True,env=env,timeout=10,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            repo_commit=commit.stdout.strip() if commit.returncode==0 else None
            local_target=str(destination)
        output=tmp/'report.json'; config_file=tmp/'worker.json'
        config_file.write_text(json.dumps({'target':local_target,'output':str(output),'semantic':semantic,'endpoint':endpoint,'model':model}),encoding='utf-8')
        progress('NVIDIA SkillSpector: '+('static + local semantic analysis…' if semantic else 'offline static analysis…'))
        code=wait_process([python_path(),str(ROOT/'skillspector_worker.py'),str(config_file)],tmp,env,stop,300,tmp/'scanner.log')
        if not output.is_file() or output.stat().st_size>16*1024*1024:
            raise ValueError('SkillSpector did not produce a usable report. The input may be unsupported or exceed scanner limits.')
        raw=json.loads(output.read_text(encoding='utf-8'))
        if code not in (0,1,2):
            raise ValueError('SkillSpector stopped unexpectedly. No complete assessment is claimed.')
        result=normalize(raw,target,semantic,time.monotonic()-started,repo_commit)
        if code==2:
            result['status']='partial'
        return result
