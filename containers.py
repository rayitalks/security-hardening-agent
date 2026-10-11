"""Scoped container security assessments. No exec, exploit payloads, or mutations."""
import datetime as dt
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time

import engine
import install_trivy
import vulnerabilities

ROOT = Path(__file__).resolve().parent
MAX_FINDINGS = 1000
REFERENCE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,249}')
LINUX_CAPS = {'ALL','SYS_ADMIN','SYS_PTRACE','SYS_MODULE','SYS_RAWIO','DAC_READ_SEARCH','DAC_OVERRIDE','NET_ADMIN','BPF','PERFMON'}


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def environment():
    allowed = {'PATH','SYSTEMROOT','WINDIR','COMSPEC','PATHEXT','TEMP','TMP','HOME','USERPROFILE','APPDATA','LOCALAPPDATA','PROGRAMDATA',
               'PROGRAMFILES','PROGRAMFILES(X86)','PROGRAMW6432','COMMONPROGRAMFILES','COMMONPROGRAMFILES(X86)','COMMONPROGRAMW6432',
               'SYSTEMDRIVE','ALLUSERSPROFILE','USERNAME','USERDOMAIN','COMPUTERNAME'}
    return {k:v for k,v in os.environ.items() if k.upper() in allowed}


def command(args, stop=None, timeout=20, env=None, cwd=None):
    """Bounded stdout/stderr, cancellation, no shell. Never expose raw errors."""
    stop = stop or threading.Event()
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(args, stdout=out, stderr=err, stdin=subprocess.DEVNULL, shell=False,
                                env=env or environment(), cwd=cwd or ROOT,
                                creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        start=time.monotonic()
        try:
            while proc.poll() is None:
                if stop.is_set() or time.monotonic()-start>timeout or out.tell()>32*1024*1024 or err.tell()>2*1024*1024:
                    raise ValueError('Container tool cancelled, timed out, or exceeded its output limit.')
                time.sleep(.1)
            out.seek(0);err.seek(0)
            stdout=out.read(32*1024*1024+1);stderr=err.read(2*1024*1024+1)
            if len(stdout)>32*1024*1024 or len(stderr)>2*1024*1024:
                raise ValueError('Container tool output exceeded its limit.')
            return proc.returncode,stdout,stderr
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait()


def docker_endpoint():
    binary=shutil.which('docker')
    if not binary:
        raise ValueError('Docker CLI is unavailable here. Use a saved image archive or collected container evidence.')
    configured=os.environ.get('DOCKER_HOST')
    if configured:
        endpoint=configured
    else:
        args=[binary,'context','inspect']
        if os.environ.get('DOCKER_CONTEXT'):
            args.append(os.environ['DOCKER_CONTEXT'])
        code,raw,_=command(args)
        if code:
            raise ValueError('Could not read the local Docker context. Start Docker or import saved evidence.')
        try:
            endpoint=json.loads(raw)[0]['Endpoints']['docker']['Host']
        except (ValueError,KeyError,IndexError,TypeError):
            raise ValueError('Docker context did not identify a supported local endpoint.')
    if not isinstance(endpoint,str) or not (endpoint.startswith('unix:///') or endpoint.startswith('npipe:////./pipe/')):
        raise ValueError('Live assessment requires a local Docker socket/pipe. Remote TCP/SSH contexts must be assessed through exported evidence on the remote host.')
    return binary,endpoint


def docker(args, connection=None, stop=None, timeout=20):
    binary,endpoint=connection or docker_endpoint()
    code,raw,_=command([binary,'--host',endpoint,*args],stop,timeout)
    if code:
        raise ValueError('Local Docker request failed. Check Docker access and the selected container/image; no target was pulled or changed.')
    return raw


def discover():
    connection=docker_endpoint()
    raw=docker(['container','ls','--all','--no-trunc','--format','{{json .}}'],connection)
    rows=[]
    for line in raw.decode('utf-8').splitlines()[:200]:
        row=json.loads(line)
        rows.append({'id':row.get('ID'),'name':row.get('Names'),'image':row.get('Image'),'state':row.get('State')})
    return {'containers':rows,'limit':200,'local':True}


def cache_dir():
    return Path(os.environ.get('SHA_TRIVY_CACHE',str(ROOT/'.data'/'trivy'))).resolve()


def status():
    db={}
    try:
        db=vulnerabilities.read_json(cache_dir()/'db'/'metadata.json',128*1024)
    except (OSError,ValueError):
        pass
    return {'installed':install_trivy.executable().is_file(),'version':install_trivy.VERSION,
            'dockerCli':bool(shutil.which('docker')),'container':os.environ.get('SHA_CONTAINER')=='1',
            'databaseUpdatedAt':db.get('UpdatedAt'),'databasePresent':bool(db),
            'message':('Trivy '+install_trivy.VERSION+' ready' if install_trivy.executable().is_file() else 'Install Trivy with Install-Trivy.bat or python install_trivy.py.')}


def valid_reference(value):
    if not isinstance(value,str) or not REFERENCE.fullmatch(value):
        raise ValueError('Choose a container name/ID or a local image reference without spaces, credentials or command options.')
    return value


def inspect_container(value,connection=None,stop=None):
    data=json.loads(docker(['container','inspect',valid_reference(value)],connection,stop))
    if not isinstance(data,list) or len(data)!=1:
        raise ValueError('Expected exactly one container.')
    return sanitize(data[0])


def inspect_image(value,connection=None,stop=None):
    data=json.loads(docker(['image','inspect',valid_reference(value)],connection,stop))
    if not isinstance(data,list) or len(data)!=1:
        raise ValueError('Expected exactly one local image.')
    row=data[0]
    return {'id':row.get('Id'),'os':row.get('Os'),'architecture':row.get('Architecture'),'size':row.get('Size'),
            'user':row.get('Config',{}).get('User',''),'repoDigests':row.get('RepoDigests',[])[:20]}


def sanitize(raw):
    """Allowlist inspect fields. Drop env values, labels, command args and health logs."""
    if not isinstance(raw,dict) or not isinstance(raw.get('HostConfig'),dict) or not isinstance(raw.get('Config'),dict):
        raise ValueError('Container evidence must contain Config and HostConfig objects.')
    host_keys=('Privileged','CapAdd','CapDrop','ReadonlyRootfs','NetworkMode','PidMode','IpcMode','UsernsMode','SecurityOpt','PidsLimit','Memory','NanoCpus','CpuQuota','CpuPeriod','DeviceRequests','Devices','MaskedPaths','ReadonlyPaths')
    cfg=raw['Config']
    names=[]
    if isinstance(cfg.get('Env'),list):
        names=[str(x).split('=',1)[0][:160] for x in cfg['Env'][:2000]]
    elif isinstance(cfg.get('EnvNames'),list):
        names=[str(x)[:160] for x in cfg['EnvNames'][:2000]]
    result={'Id':str(raw.get('Id',''))[:100],'Name':str(raw.get('Name',''))[:250],
            'Image':str(raw.get('Image',''))[:250],'Platform':str(raw.get('Platform',''))[:40],
            'Config':{'User':str(cfg.get('User',''))[:150],'Image':str(cfg.get('Image',''))[:250],'EnvNames':names,
                      'HealthcheckConfigured':bool(cfg.get('HealthcheckConfigured') or (cfg.get('Healthcheck',{}).get('Test', ['NONE'])[0]!='NONE'))},
            'HostConfig':{k:raw['HostConfig'][k] for k in host_keys if k in raw['HostConfig']},
            'State':{k:raw.get('State',{}).get(k) for k in ('Running','Status','Pid','OOMKilled')},
            'NetworkSettings':{'Ports':raw.get('NetworkSettings',{}).get('Ports',{})},
            'Mounts':[{k:m.get(k) for k in ('Type','Source','Destination','RW')} for m in raw.get('Mounts',[])[:500]],
            'AppArmorProfile':str(raw.get('AppArmorProfile',''))[:250]}
    if not isinstance(result['NetworkSettings']['Ports'],dict):
        raise ValueError('Invalid published port evidence.')
    return result


def read_evidence(path):
    p=Path(path).expanduser()
    if not p.is_absolute() or not p.is_file():
        raise ValueError('Choose an existing absolute path to saved container evidence.')
    data=vulnerabilities.read_json(p,4*1024*1024)
    stamp=None
    if isinstance(data,dict) and data.get('schema')=='sha-container-evidence-v1':
        stamp=data.get('createdAt')
        data=data.get('container')
    elif isinstance(data,list) and len(data)==1:
        data=data[0]
    return sanitize(data),stamp


def configuration_checks(row,platform='linux'):
    findings=[]
    h=row['HostConfig'];c=row['Config']
    def add(name,status,evidence,fix):
        findings.append(engine.finding(name,status,evidence,fix,'Container configuration'))
    linux=platform=='linux'
    user=c.get('User','')
    if linux:
        root=user.split(':')[0] in ('','0','root')
        add('Configured container user','attention' if root else 'review',
            'Root/default-root is configured.' if root else f'Configured user: {user}. Runtime UID and entrypoint privilege changes were not inspected.',
            'Use a dedicated non-root UID; verify the running process identity when investigating.')
        for key,title,bad,fix in (
            ('Privileged','Privileged mode',lambda x:x is True,'Remove privileged mode and grant only necessary individual capabilities.'),
            ('PidMode','Host process namespace',lambda x:x=='host','Use a private process namespace.'),
            ('IpcMode','Host IPC namespace',lambda x:x=='host','Use private IPC unless sharing is required and reviewed.'),
            ('NetworkMode','Host network namespace',lambda x:x=='host','Use a dedicated container network and narrowly scoped published ports.'),
            ('UsernsMode','Host user namespace override',lambda x:x=='host','Review user namespace remapping/rootless deployment. Empty mode alone does not prove remapping.'),
        ):
            value=h.get(key)
            add(title,'unknown' if key not in h else ('attention' if bad(value) else 'pass'),f'{key}: {value!s}. This is configuration evidence, not a kernel isolation test.',fix)
        caps=[str(x).upper().removeprefix('CAP_') for x in h.get('CapAdd') or []]
        drops=[str(x).upper().removeprefix('CAP_') for x in h.get('CapDrop') or []]
        danger=sorted(set(caps)&LINUX_CAPS)
        add('Linux capability configuration','attention' if danger else 'review',f'Added: {", ".join(caps) or "none explicitly"}; dropped: {", ".join(drops) or "none explicitly"}. Default and effective process capabilities were not enumerated.',
            'Drop ALL capabilities, then add only those required. Review SYS_ADMIN, host tracing, device and network privileges first.')
        opts=[str(x) for x in h.get('SecurityOpt') or []]
        unconfined=any(x in ('seccomp=unconfined','apparmor=unconfined','label=disable') for x in opts)
        add('Security profile overrides','attention' if unconfined else 'review',f'Explicit options: {", ".join(opts) or "none"}. AppArmor profile: {row.get("AppArmorProfile") or "not reported"}. Default profiles were not independently tested.',
            'Use the default or a reviewed seccomp/LSM profile and avoid unconfined overrides.')
        nnp=any(x in ('no-new-privileges','no-new-privileges:true','no-new-privileges=true') for x in opts)
        add('No-new-privileges setting','pass' if nnp else 'review','Explicit no-new-privileges is '+('configured.' if nnp else 'not present in inspected options.'),'Enable no-new-privileges unless the workload requires a reviewed exception.')
        devices=h.get('Devices') or []
        requests=h.get('DeviceRequests') or []
        add('Host device access','review' if devices or requests else 'pass',f'{len(devices)} direct device mapping(s); {len(requests)} device request(s), which can include legitimate GPU access.','Limit device access to the specific accelerators needed; review GPU driver and runtime advisories separately.')
    else:
        add('Platform-specific isolation checks','unknown',f'Image platform is {platform or "unknown"}. Linux capability, namespace, user and seccomp checks were not applied.','Review Windows container isolation/host patching with platform-specific tooling.')
    readonly=h.get('ReadonlyRootfs')
    add('Read-only root filesystem','unknown' if readonly is None else ('pass' if readonly else 'review'),f'ReadonlyRootfs: {readonly}. Volumes can still be writable.','Use a read-only root filesystem with explicit writable temporary/data mounts.')
    for key,title in (('Memory','Memory limit'),('PidsLimit','Process limit')):
        value=h.get(key)
        add(title,'pass' if isinstance(value,(int,float)) and value>0 else 'review',f'{key}: {value}. Unset/zero/unlimited limits can permit resource exhaustion.','Set a workload-appropriate resource limit; no exhaustion test was run.')
    cpu=h.get('NanoCpus',0) or h.get('CpuQuota',0) or 0
    add('CPU quota','pass' if isinstance(cpu,(int,float)) and cpu>0 else 'review','A positive CPU quota is '+('present.' if isinstance(cpu,(int,float)) and cpu>0 else 'not reported.'),'Set a CPU quota appropriate for inference and isolate critical services.')
    mounts=row.get('Mounts',[])
    if not mounts:
        add('Host mounts','pass','No mounts are listed in this evidence.','Keep mounts minimal and prefer read-only access.')
    for mount in mounts:
        source=str(mount.get('Source') or '');dest=str(mount.get('Destination') or '')
        socket_mount=any(token in (source+' '+dest).lower() for token in ('docker.sock','containerd.sock','docker_engine'))
        sensitive=source.rstrip('/') in ('','/','/etc','/proc','/sys','/dev','/var/run') or bool(re.fullmatch(r'[A-Za-z]:[\\/]?',source))
        status='attention' if socket_mount or (sensitive and mount.get('Type')=='bind') else 'review'
        add('Container control socket mount' if socket_mount else 'Mounted filesystem access',status,
            f'{mount.get("Type")} mount: {source} → {dest}; writable={mount.get("RW")}. '+('A read-only socket mount can still permit control API operations.' if socket_mount else ''),
            'Remove control-socket and broad host mounts. Scope necessary mounts to dedicated data paths and use read-only access where possible.')
    sensitive_names=[x for x in c.get('EnvNames',[]) if re.search(r'(?i)(?:password|secret|token|api[_-]?key|credential)',x)]
    add('Secret-like environment variable names','review' if sensitive_names else 'pass',
        f'{len(sensitive_names)} secret-like variable name(s) detected. Values and names are omitted from the report.' if sensitive_names else 'No common secret-like environment variable names were detected. Values were not retained.',
        'Use a scoped secret mechanism and rotate any confirmed exposure; variable names alone do not establish leaked credentials.')
    bindings=published_ports(row)
    if not bindings:
        add('Published ports','review','No supported published bindings were reported. Host-network, internal, UDP or overlay reachability can still exist.','Review network memberships and host firewall rules separately.')
    for binding in bindings:
        wildcard=binding['host'] in ('','0.0.0.0','::')
        local=binding['host'] in ('127.0.0.1','::1','localhost')
        add('Published service binding','review' if wildcard or not local else 'pass',f"{binding['host'] or 'all interfaces'}:{binding['port']} → {binding['containerPort']}. Binding does not prove internet reachability or effective authentication.",
            'Bind administrative and AI services to loopback or a trusted interface; review firewall and authentication policy.')
    return findings


def published_ports(row):
    result=[]
    for container_port,bindings in list(row.get('NetworkSettings',{}).get('Ports',{}).items())[:100]:
        if not isinstance(bindings,list):
            continue
        for binding in bindings[:20]:
            try:
                port=int(binding.get('HostPort',''))
                if not 1<=port<=65535:
                    continue
                result.append({'host':str(binding.get('HostIp',''))[:100],'port':port,'containerPort':str(container_port)[:40]})
            except (TypeError,ValueError):
                continue
    return result


def active_checks(row,protocol,stop,connector=socket.create_connection):
    if row.get('State',{}).get('Running') is not True:
        return [engine.finding('Published-port tests skipped','unknown','The selected container is not running in the current inspect evidence.','Start the intended workload separately, then repeat the test.','Active verification')],0
    results=[];tested=set()
    for binding in published_ports(row):
        if stop.is_set() or len(tested)>=8:
            break
        if not binding['containerPort'].endswith('/tcp'):
            continue
        source=binding['host']
        host='::1' if source in ('::','::1') else '127.0.0.1'
        if source not in ('','0.0.0.0','::','::1','127.0.0.1','localhost'):
            results.append(engine.finding('Non-loopback binding not probed','unknown',f'Published binding {source}:{binding["port"]} was not contacted.','Test this interface from an explicitly scoped network vantage point.','Active verification'))
            continue
        address=(host,binding['port'])
        if address in tested:
            continue
        tested.add(address)
        try:
            with connector(address,timeout=2):
                pass
        except OSError:
            results.append(engine.finding('TCP connection not established','unknown',f'{host}:{address[1]} did not accept this connection within two seconds. This does not prove it is unreachable from all networks.','Check service state, protocol and the intended network path.','Active verification'))
            continue
        results.append(engine.finding('Published TCP service reachable','review',f'A TCP connection to {host}:{address[1]} succeeded from the scanner host. No protocol exploit was sent.','Verify the service needs this binding and that authentication is enforced at sensitive routes.','Active verification'))
        if protocol not in ('http','https') or stop.is_set():
            continue
        conn=None
        try:
            conn=(http.client.HTTPSConnection(host,address[1],timeout=3,context=ssl.create_default_context()) if protocol=='https' else http.client.HTTPConnection(host,address[1],timeout=3))
            conn.request('HEAD','/',headers={'User-Agent':'Ray-i-Container-Assessment/'+engine.VERSION,'Connection':'close'})
            response=conn.getresponse()
            code=response.status
            html='text/html' in (response.getheader('Content-Type') or '').lower()
            absent=[header for header in ('Content-Security-Policy','X-Content-Type-Options') if not response.getheader(header)] if html else []
            details=f'{protocol.upper()} HEAD / returned {code}. Redirects were not followed; no credentials or body were sent/read. A public root response does not prove an authentication bypass.'
            if absent:
                details+=' HTML response lacks '+', '.join(absent)+'.'
            results.append(engine.finding('Unauthenticated HTTP surface','review',details,'Review authentication at the application’s sensitive routes and security headers for browser-facing pages.','Active verification'))
            if protocol=='https' and not response.getheader('Strict-Transport-Security'):
                results.append(engine.finding('HTTPS response lacks HSTS','review','The checked HTTPS root response did not include HSTS.','Review HSTS with your TLS/reverse-proxy deployment; a local IP test may differ from the public virtual host.','Active verification'))
        except (OSError,http.client.HTTPException):
            results.append(engine.finding('HTTP/TLS verification inconclusive','unknown',f'{protocol.upper()} verification of {host}:{address[1]} failed, timed out, or did not pass certificate validation.','Select the correct protocol. Use the intended hostname when investigating TLS; verification was not disabled.','Active verification'))
        finally:
            if conn:
                conn.close()
    if not tested:
        results.append(engine.finding('No eligible published TCP ports','unknown','No loopback/wildcard published TCP bindings were eligible for active checks.','Review explicit published bindings; this tool does not sweep networks or probe container-internal addresses.','Active verification'))
    return results,len(tested)


def trivy_args(target,archive,online,connection,scratch):
    args=[str(install_trivy.executable()),'image','--format','json','--quiet','--no-progress','--disable-telemetry',
          '--skip-version-check','--offline-scan','--skip-check-update','--skip-vex-repo-update',
          '--scanners','vuln,secret','--image-config-scanners','secret','--list-all-pkgs=false',
          '--exit-code','0','--timeout','5m','--parallel','2','--max-image-size','8GB',
          '--config','', '--ignorefile','', '--secret-config','', '--cache-dir',str(cache_dir()),
          '--db-repository','ghcr.io/aquasecurity/trivy-db:2','--java-db-repository','ghcr.io/aquasecurity/trivy-java-db:1',
          '--module-dir',str(scratch/'empty-modules')]
    if not online:
        args+=['--skip-db-update','--skip-java-db-update']
    if archive:
        args+=['--input',str(target)]
    else:
        args+=['--image-src','docker','--docker-host',connection[1],'--',target]
    return args


def normalize_trivy(data,db,warnings=False):
    if not isinstance(data,dict) or data.get('SchemaVersion')!=2 or data.get('ArtifactType')!='container_image':
        raise ValueError('Trivy did not return a supported container-image report.')
    findings=[];vulns=secrets=0
    results=data.get('Results',[])
    if not isinstance(results,list):
        raise ValueError('Invalid scanner results.')
    for result in results:
        target=str(result.get('Target',''))[:500]
        for item in result.get('Vulnerabilities') or []:
            vulns+=1
            if len(findings)>=MAX_FINDINGS:
                continue
            identifier=str(item.get('VulnerabilityID',''))[:160]
            severity=str(item.get('Severity','UNKNOWN'))[:40]
            installed=str(item.get('InstalledVersion',''))[:150]
            fixed=str(item.get('FixedVersion') or '')[:500]
            pkg=str(item.get('PkgName',''))[:200]
            row=engine.finding(f'{severity} · {identifier} · {pkg}','attention' if severity in ('CRITICAL','HIGH') else 'review',
                f'{target}\nPackage {pkg} {installed}. Provider state: {item.get("Status","unspecified")}. Package match does not prove reachability or exploitation.',
                f'Provider fixed version(s): {fixed}. Verify the applicable vendor branch and rebuild the image.' if fixed else 'No fixed version is listed. Review vendor mitigations, reduce exposure and track an update.',
                'Container image CVEs','Trivy')
            row.update(advisoryId=identifier,severity=severity,packageName=pkg,installedVersion=installed,fixedVersion=fixed,source=str(item.get('DataSource',{}).get('Name',''))[:150])
            if vulnerabilities.CVE.fullmatch(identifier):
                row['cves']=[identifier]
                row['reference']='https://nvd.nist.gov/vuln/detail/'+identifier
            elif re.fullmatch(r'[A-Za-z0-9._-]+',identifier):
                row['reference']='https://osv.dev/vulnerability/'+identifier
            findings.append(row)
        for item in result.get('Secrets') or []:
            secrets+=1
            if len(findings)>=MAX_FINDINGS:
                continue
            # Never preserve Match, Code, raw Layer values, or environment contents.
            findings.append(engine.finding('Potential secret in image','attention',
                f'{target}: line {item.get("StartLine","unknown")}. Rule {str(item.get("RuleID","unknown"))[:120]}. Matched text and secret values were discarded.',
                'Verify locally, rotate confirmed credentials, and rebuild without secrets in any image layer.','Container image secrets','Trivy'))
    metadata=data.get('Metadata',{})
    osdata=metadata.get('OS') or {}
    if osdata.get('EOSL'):
        findings.append(engine.finding('Image operating system is end-of-life','attention',f'{osdata.get("Family")} {osdata.get("Name")} is marked end-of-life by the scanner.','Move to a supported base image and rebuild.','Container image'))
    stale=vulnerabilities.old(db.get('UpdatedAt'))
    if stale:
        findings.append(engine.finding('Image vulnerability database is missing or stale','unknown',f'Database UpdatedAt: {db.get("UpdatedAt") or "unavailable"}. Current coverage is not established.','Allow database downloads and repeat the scan.','Container image coverage'))
    if not results:
        findings.append(engine.finding('No analyzable package/secret targets reported','unknown','The scanner returned no result targets. This is not a clean-image verdict.','Verify image format, supported operating system and available package metadata.','Container image coverage'))
    elif not vulns and not secrets:
        findings.append(engine.finding('No image findings returned','review','No vulnerabilities or secrets were returned within this scan’s supported coverage.','Retain the image digest and database date; absence of findings does not certify safety.','Container image'))
    if warnings:
        findings.append(engine.finding('Scanner emitted diagnostic warnings','unknown','The scanner completed with diagnostic output; payload text was withheld to avoid disclosing secrets. Some analysis may be incomplete.','Review the image format and supported analyzers; retry with updated tooling.','Container image coverage'))
    if vulns+secrets>MAX_FINDINGS:
        findings.append(engine.finding('Image finding limit reached','unknown','More than 1,000 image findings were returned; the report is truncated.','Assess smaller image layers/components and prioritize remediation.','Container image coverage'))
    coverage={'engine':'Trivy','version':install_trivy.VERSION,'targetsAnalyzed':len(results),'vulnerabilityMatches':vulns,'secretMatches':secrets,'databaseUpdatedAt':db.get('UpdatedAt'),'databaseDownloadedAt':db.get('DownloadedAt'),
              'osFamily':osdata.get('Family'),'osVersion':osdata.get('Name'),'complete':bool(results) and not stale and not warnings and vulns+secrets<=MAX_FINDINGS}
    return findings,coverage


def scan_image(target,archive,online,connection,progress,stop):
    if not install_trivy.executable().is_file():
        return [engine.finding('Image scanner unavailable','unknown','Pinned Trivy is not installed.','Run Install-Trivy.bat or python install_trivy.py, then repeat.','Container image coverage')],{'complete':False}
    cache_dir().mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='sha-image-') as tmp:
        scratch=Path(tmp)
        env=environment()
        env.update(HOME=tmp,USERPROFILE=tmp,XDG_CONFIG_HOME=tmp,TMPDIR=tmp,TMP=tmp,TEMP=tmp,DOCKER_CONFIG=tmp)
        progress('Scanning image locally; '+('updating public vulnerability databases if needed…' if online else 'using cached databases only…'))
        try:
            code,raw,err=command(trivy_args(target,archive,online,connection,scratch),stop,330,env,scratch)
            if code:
                raise ValueError('Image scan failed. Check image access, cache/database availability and the 8 GB image limit.')
            data=json.loads(raw)
            try:
                db=vulnerabilities.read_json(cache_dir()/'db'/'metadata.json',128*1024)
            except (OSError,ValueError):
                db={}
            return normalize_trivy(data,db,bool(err.strip()))
        except (ValueError,OSError,TypeError,KeyError) as exc:
            return [engine.finding('Image scan incomplete','unknown',str(exc) if isinstance(exc,ValueError) and not isinstance(exc,json.JSONDecodeError) else 'Scanner output could not be read safely.',
                'Confirm the target and scanner installation. First use needs a database download; offline mode needs an existing cache.','Container image coverage')],{'complete':False}


def assess(config,progress,stop):
    mode=config.get('mode','container')
    if mode not in ('container','image','archive','evidence'):
        raise ValueError('Choose a supported container assessment target.')
    if config.get('authorized') is not True:
        raise ValueError('Confirm authorization for this container/image assessment.')
    active=config.get('active') is True
    if active and mode!='container':
        raise ValueError('Active checks are supported only for a live local Docker container.')
    protocol=config.get('protocol','tcp')
    if protocol not in ('tcp','http','https'):
        raise ValueError('Choose TCP only, HTTP, or HTTPS.')
    findings=[];row=None;image=None;connection=None;image_coverage=None;tested=0
    limitations=['This is a scoped container assessment with optional connection/HTTP checks, not a complete penetration test or a container-escape proof.',
        'No docker exec, exploit payload, credential guessing, network sweep, privilege change, container start/stop, image pull, or destructive test is performed.',
        'Inspect evidence does not establish effective process UIDs/capabilities, kernel escape resistance, host firewall reachability, or application authorization.',
        'Active tests contact at most eight loopback/wildcard published TCP bindings of the selected live local container. Optional HEAD / requests send no credentials, follow no redirects, and preserve no response body.',
        'Image scans cover the immutable image, not changes in a running writable layer or mounted volumes. Runtime secrets in memory and undisclosed zero-days remain outside coverage.',
        'Trivy matches supported image OS and application packages locally. Database downloads are optional; no source/image upload or telemetry is enabled. Offline dependency resolution can reduce Java coverage.',
        'Trivy has an 8 GB image limit, five-minute scan timeout, and 1,000 image findings. Cached CVE data older than seven days is unknown. Windows image/kernel/driver coverage is not established.',
        'Environment values, command arguments, health logs and scanner secret matches are excluded from saved reports. Findings may still contain internal file paths and package identities.']
    progress('Reading selected container/image evidence…')
    if mode in ('container','image'):
        connection=docker_endpoint()
        if mode=='container':
            row=inspect_container(config.get('target',''),connection,stop)
            image=inspect_image(row['Image'],connection,stop)
            target=row['Name'].lstrip('/')+' / '+row['Id'][:12]
            findings.extend(configuration_checks(row,image.get('os')))
        else:
            image=inspect_image(config.get('target',''),connection,stop)
            target=config.get('target')+' / '+str(image.get('id'))[:19]
        if not re.fullmatch(r'sha256:[a-f0-9]{64}',str(image.get('id',''))):
            raise ValueError('Docker did not return an immutable image ID.')
    elif mode=='evidence':
        row,stamp=read_evidence(config.get('path',''))
        target='Saved evidence: '+row['Name'].lstrip('/')
        platform=row.get('Platform','').split('/')[0]
        findings.extend(configuration_checks(row,platform))
        findings.append(engine.finding('Imported container evidence','unknown' if vulnerabilities.old(stamp) else 'review',f'Collected at {stamp or "unknown"}. User-supplied evidence is not independently authenticated and describes a past snapshot.','Recollect on the intended Docker host when investigating current exposure.','Coverage'))
        limitations.append('Imported evidence triggers no Docker connection or active probes. Image CVEs need a separate image/archive scan.')
    else:
        path=Path(config.get('path','')).expanduser()
        if not path.is_absolute() or not path.is_file() or path.suffix.lower() not in ('.tar','.gz','.tgz'):
            raise ValueError('Choose an existing absolute path to a Docker/OCI image tar archive.')
        if path.stat().st_size>8*1024**3:
            raise ValueError('Image archive exceeds the 8 GB limit.')
        target=str(path)
    scan_requested=mode in ('image','archive') or (mode=='container' and config.get('imageScan') is True)
    if scan_requested and not stop.is_set():
        extra,image_coverage=scan_image(str(path) if mode=='archive' else image['id'],mode=='archive',config.get('online') is True,connection,progress,stop)
        findings.extend(extra)
        if config.get('online') is True and not stop.is_set():
            progress('Matching image CVEs to the CISA known-exploited catalog…')
            kev=vulnerabilities.load_kev()
            if kev.get('available'):
                for f in findings:
                    hits=[c for c in f.get('cves',[]) if c in kev.get('entries',{})]
                    if hits:
                        f.update(knownExploited=True,mapping='CISA KEV + Trivy')
                        f['name']='KNOWN EXPLOITED · '+f['name']
                        f['status']='attention'
                        f['evidence']+='\nCISA KEV lists '+', '.join(hits)+' as exploited in the wild. This does not establish exploitation on this container.'
                image_coverage['kevReleasedAt']=kev.get('dateReleased')
                if vulnerabilities.old(kev.get('dateReleased')):
                    findings.append(engine.finding('Known-exploitation catalog is stale','unknown','CISA release date is older than seven days or invalid.','Refresh public intelligence.','Container image coverage'))
            else:
                findings.append(engine.finding('Known-exploitation lookup unavailable','unknown','The CISA KEV catalog could not be retrieved. Image CVE findings remain available.','Retry the exploitation lookup later.','Container image coverage'))
    elif mode=='container':
        findings.append(engine.finding('Image CVE scan not performed','unknown','Only container runtime configuration and selected probes were assessed.','Select the image scan option to assess image package vulnerabilities and secrets.','Coverage'))
    if active and not stop.is_set():
        progress('Testing selected published service bindings…')
        # Re-read by immutable container ID before probing; only current inspected ports are eligible.
        row=inspect_container(row['Id'],connection,stop)
        extra,tested=active_checks(row,protocol,stop)
        findings.extend(extra)
    findings.sort(key=lambda f:(not f.get('knownExploited',False),f['status']!='attention'))
    partial=any(f['status']=='unknown' for f in findings) or (image_coverage and not image_coverage.get('complete'))
    return {'schema':'sha-report-v1','type':'Container assessment','createdAt':now(),'target':target,
        'status':'cancelled' if stop.is_set() else ('partial' if partial else 'complete'),'findings':findings,'limitations':limitations,
        'coverage':{'mode':mode,'configurationChecks':sum(f['area']=='Container configuration' for f in findings),'activePortsTested':tested,'activeProtocol':protocol if active else 'not requested','imageScanRequested':scan_requested,'image':image_coverage},
        'containerAssessment':{'image':image,'name':row['Name'] if row else None,'containerId':row['Id'] if row else None,'imageScan':image_coverage,'activePortsTested':tested,'mode':mode}}


def collect(value):
    connection=docker_endpoint()
    row=inspect_container(value,connection)
    image=inspect_image(row['Image'],connection)
    row['Platform']=image.get('os') or row['Platform']
    return {'schema':'sha-container-evidence-v1','createdAt':now(),'container':row,'image':image}
