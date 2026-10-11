"""Read-only VMware Workstation and Proxmox VE collectors."""
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
from urllib import request
from urllib.parse import urlsplit
import engine
import deployment_audits

class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None

def pve_get(config,path):
    base=engine.validate_target(config.get('url','')).rstrip('/')
    if urlsplit(base).scheme!='https':raise ValueError('Proxmox requires HTTPS and a trusted server certificate.')
    env=config.get('keyEnv','')
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,79}',env):raise ValueError('Supply the environment variable containing USER@REALM!TOKENID=SECRET.')
    key=os.environ.get(env,'')
    if not key or '\n' in key or '\r' in key:raise ValueError('Proxmox token environment variable is missing or invalid.')
    req=request.Request(base+'/api2/json/'+path,headers={'Authorization':'PVEAPIToken='+key})
    try:
        with request.build_opener(request.ProxyHandler({}),NoRedirect(),request.HTTPSHandler(context=ssl.create_default_context())).open(req,timeout=15) as response:
            raw=response.read(2_000_001)
        if len(raw)>2_000_000:raise ValueError('Response too large')
        return json.loads(raw)['data']
    except Exception:raise ValueError('Proxmox read failed. Check the URL, certificate, token and VM.Audit/Sys.Audit permissions.') from None

def discover(config):
    if config['provider']=='proxmox':
        rows=pve_get(config,'cluster/resources?type=vm')
        return [{'id':str(r['vmid']),'name':r.get('name',str(r['vmid'])),'node':r['node'],'state':r.get('status')} for r in rows if r.get('type')=='qemu'][:200]
    import vm_scan
    raw=vm_scan.command([vm_scan.executable('vmrun'),'list'])
    rows=[]
    for value in raw.splitlines()[1:201]:
        path=Path(value.strip())
        if path.is_absolute() and path.suffix.lower()=='.vmx':
            rows.append({'id':hashlib.sha256(str(path).encode()).hexdigest(),'name':path.stem,'path':str(path),'state':'running'})
    return rows

def collect(config):
    import vm_scan
    selected=next((r for r in discover(config) if r['id']==config.get('id')),None)
    if not selected:raise ValueError('Select a VM returned by current discovery.')
    if config['provider']=='vmware':
        path=deployment_audits.target_path(selected['path'])
        if path.stat().st_size>2_000_000:raise ValueError('VMX exceeds 2 MB.')
        return vm_scan.pairs_evidence(path.read_text(encoding='utf-8-sig'),'vmware',selected['name'])
    node=selected['node'];vmid=selected['id']
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}',node) or not re.fullmatch(r'\d{1,10}',vmid):raise ValueError('Unexpected Proxmox VM identity.')
    raw=pve_get(config,f'nodes/{node}/qemu/{vmid}/config')
    controls={'secureBoot':None if 'efidisk0' not in raw else 'pre-enrolled-keys=1' in raw['efidisk0'],
              'tpm':'tpmstate0' in raw,'hostDevicePassthrough':any(k.startswith(('hostpci','usb')) for k in raw),
              'sharedFolders':any(k.startswith('virtiofs') for k in raw),'bridgedNetwork':any('bridge=' in str(v) for k,v in raw.items() if re.fullmatch(r'net\d+',k))}
    return {'schema':'sha-vm-evidence-v1','provider':'proxmox','id':vmid,'name':selected['name'],'controls':controls,
            'details':{'memoryMB':raw.get('memory'),'vcpus':raw.get('cores'),'firmware':raw.get('bios'),'state':selected.get('state')}}
