"""Read-only VM control-plane/configuration review. Never boots, mounts or enters a guest."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import threading
import uuid
import xml.etree.ElementTree as ET
import containers
import deployment_audits as audits

ROOT=Path(__file__).resolve().parent
UUID=re.compile(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}')

def command(args,stop=None):
    code,out,_=containers.command(args,stop,45)
    if code:raise ValueError('VM collection failed. Check hypervisor permissions and, for Hyper-V, whether local PowerShell scripts may run. No guest, hypervisor or execution-policy settings were changed.')
    return out.decode('utf-8-sig',errors='replace')

def hyperv(mode,identity='',stop=None):
    if os.name!='nt':raise ValueError('Hyper-V collection requires its Windows host.')
    args=['powershell.exe','-NoProfile','-NonInteractive','-File',str(ROOT/'vm_hyperv.ps1'),'-Mode',mode]
    if identity:args+=['-Id',identity]
    return json.loads(command(args,stop))

def executable(name):
    found=shutil.which(name)
    if not found and name=='VBoxManage' and os.name=='nt':
        candidate=Path(os.environ.get('ProgramFiles',r'C:\Program Files'))/'Oracle'/'VirtualBox'/'VBoxManage.exe'
        if candidate.is_file():found=str(candidate)
    if not found:raise ValueError(name+' is unavailable on this host. Import configuration or collected evidence instead.')
    return found

def discover(config):
    provider=config.get('provider','hyperv')
    if provider in ('vmware','proxmox'):
        import vm_remote
        rows=vm_remote.discover(config)
    elif provider=='hyperv':rows=hyperv('list')
    elif provider=='virtualbox':
        raw=command([executable('VBoxManage'),'list','vms']);rows=[]
        for line in raw.splitlines()[:200]:
            m=re.fullmatch(r'"(.*)"\s+\{([a-fA-F0-9-]+)\}',line)
            if m:rows.append({'id':m[2],'name':m[1]})
    elif provider=='libvirt':
        raw=command([executable('virsh'),'--readonly','--connect','qemu:///system','list','--all','--uuid'])
        rows=[{'id':x.strip(),'name':x.strip()} for x in raw.splitlines() if UUID.fullmatch(x.strip())][:200]
    else:raise ValueError('Choose Hyper-V, VMware, VirtualBox, KVM/libvirt or Proxmox VE.')
    if isinstance(rows,dict):rows=[rows]
    return {'provider':provider,'vms':rows or [],'limit':200,'scope':'Local hypervisor only. Discovery does not establish guest OS security.'}

def scalar(value):
    if value is None:return None
    text=str(value).strip().strip('"')
    if text.lower() in ('true','on','yes','enabled','enable','1'):return True
    if text.lower() in ('false','off','no','disabled','disable','0'):return False
    return text[:500]

def parse_pairs(text):
    result={}
    for line in text.splitlines()[:10000]:
        m=re.match(r'^\s*([A-Za-z0-9_.()-]+)\s*=\s*(.*?)\s*$',line)
        if m:result[m[1]]=m[2].strip('"')
    return result

def pairs_evidence(text,provider,name):
    raw=parse_pairs(text);controls={};details={}
    if provider=='vmware':
        mapping={'secureBoot':'uefi.secureBoot.enabled','tpm':'vtpm.present','nestedVirtualization':'vhv.enable','sharedFolders':'sharedFolder.maxNum'}
        for field,key in mapping.items():
            if key in raw:controls[field]=scalar(raw[key]) if field!='sharedFolders' else raw[key]!='0'
        for field,key in [('clipboardCopyDisabled','isolation.tools.copy.disable'),('clipboardPasteDisabled','isolation.tools.paste.disable'),('dragDropDisabled','isolation.tools.dnd.disable')]:
            controls[field]=scalar(raw.get(key))
        controls['remoteConsole']=scalar(raw.get('RemoteDisplay.vnc.enabled'))
        details={'memoryMB':raw.get('memsize'),'vcpus':raw.get('numvcpus'),'firmware':raw.get('firmware')}
        controls['bridgedNetwork']=any(v.lower()=='bridged' for k,v in raw.items() if re.fullmatch(r'ethernet\d+\.connectionType',k))
    else:
        controls.update(secureBoot=scalar(raw.get('secureboot')),tpm=None if 'tpm-type' not in raw else raw['tpm-type'].lower() not in ('none','disabled',''),
                        clipboardCopyDisabled=None if 'clipboard' not in raw else raw['clipboard']=='disabled',
                        dragDropDisabled=None if 'draganddrop' not in raw else raw['draganddrop']=='disabled',remoteConsole=scalar(raw.get('vrde')))
        controls['bridgedNetwork']=any(v=='bridged' for k,v in raw.items() if re.fullmatch(r'nic\d+',k))
        controls['sharedFolders']=any(k.startswith('SharedFolderPath') for k in raw)
        details={'memoryMB':raw.get('memory'),'vcpus':raw.get('cpus'),'firmware':raw.get('firmware'),'state':raw.get('VMState')}
    return {'schema':'sha-vm-evidence-v1','provider':provider,'name':name,'id':name,'controls':controls,'details':details}

def xml_evidence(text,name):
    if re.search(r'<!DOCTYPE|<!ENTITY',text,re.I):raise ValueError('DTD/entity declarations are not accepted in VM configuration.')
    root=ET.fromstring(text)
    for element in root.iter():element.tag=element.tag.rsplit('}',1)[-1]
    if root.tag!='domain':raise ValueError('Expected libvirt domain XML. Use VirtualBox live discovery or exported evidence for VirtualBox.')
    controls={};details={'type':root.get('type'),'vcpus':root.findtext('vcpu'),'memoryValue':root.findtext('memory')}
    loader=root.find('./os/loader');features=root.findall('./os/firmware/feature')
    secure=next((x.get('enabled') for x in features if x.get('name')=='secure-boot'),loader.get('secure') if loader is not None else None)
    controls['secureBoot']=scalar(secure);controls['tpm']=root.find('./devices/tpm') is not None
    controls['sharedFolders']=root.find('./devices/filesystem') is not None
    controls['hostDevicePassthrough']=root.find('./devices/hostdev') is not None
    graphics=root.findall('./devices/graphics')
    controls['remoteConsole']=any(g.get('listen') in ('0.0.0.0','::') or any(n.get('address') in ('0.0.0.0','::') for n in g.findall('listen')) for g in graphics)
    controls['bridgedNetwork']=any(n.get('type') in ('bridge','direct') for n in root.findall('./devices/interface'))
    controls['selinuxDisabled']=any(s.get('type')=='none' or s.get('model')=='none' for s in root.findall('seclabel'))
    return {'schema':'sha-vm-evidence-v1','provider':'libvirt','name':root.findtext('name') or name,'id':root.findtext('uuid') or name,'controls':controls,'details':details}

def collect(config,stop=None):
    provider=config.get('provider','hyperv');identity=config.get('id','')
    if provider in ('vmware','proxmox'):
        import vm_remote
        return vm_remote.collect(config)
    if not isinstance(identity,str) or not UUID.fullmatch(identity):raise ValueError('Select a VM UUID returned by discovery.')
    if provider=='hyperv':return hyperv('inspect',identity,stop)
    if provider=='virtualbox':return pairs_evidence(command([executable('VBoxManage'),'showvminfo',identity,'--machinereadable'],stop),'virtualbox',identity)
    if provider=='libvirt':return xml_evidence(command([executable('virsh'),'--readonly','--connect','qemu:///system','dumpxml',identity],stop),identity)
    raise ValueError('Unsupported local hypervisor.')

def normalize(data,target,imported=False):
    if not isinstance(data,dict) or data.get('schema')!='sha-vm-evidence-v1' or not isinstance(data.get('controls'),dict):raise ValueError('Unsupported VM evidence schema.')
    findings=[];controls=data['controls']
    def flag(key,label,good,fix):
        value=controls.get(key);known=isinstance(value,bool)
        findings.append(audits.item(label,'pass' if known and value==good else 'review' if known else 'unknown',
            ('Observed enabled.' if value else 'Observed disabled.') if known else 'No supported evidence available.',fix,'Virtual machines'))
    for key,label in [('secureBoot','Guest secure boot'),('tpm','Virtual TPM'),('clipboardCopyDisabled','Clipboard copy isolation'),('clipboardPasteDisabled','Clipboard paste isolation'),('dragDropDisabled','Drag-and-drop isolation')]:
        flag(key,label,True,'Review guest requirements and enable the applicable isolation or boot control without disrupting the guest.')
    for key,label in [('remoteConsole','Wildcard or enabled remote console'),('sharedFolders','Host/guest shared folders'),('bridgedNetwork','Bridged/external network'),('hostDevicePassthrough','Host device passthrough'),('nestedVirtualization','Nested virtualization'),('selinuxDisabled','Disabled libvirt security label')]:
        flag(key,label,False,'Confirm this integration is required, restrict access and review the associated host/guest boundary.')
    details=data.get('details',{})
    safe_details={k:details[k] for k in ('memoryMB','memoryValue','vcpus','firmware','state','generation','checkpointCount','dynamicMemory','memoryMaximum','shielded','type') if k in details and isinstance(details[k],(str,int,bool,type(None)))}
    findings.append(audits.item('VM resources and recovery','review',json.dumps(safe_details)[:2000],'Review memory/CPU capacity, checkpoint age and independent backups. A checkpoint is not a backup.','Virtual machines'))
    findings.append(audits.item('Guest OS and application security','unknown','Hypervisor settings do not establish guest patching, accounts, firewall, malware or inference-service exposure.','Run collector.py inside the guest and import its host report; assess its explicitly selected AI endpoints separately.','Virtual machines'))
    return audits.report('Virtual machine security',target,findings,[
        'Read-only control-plane/configuration evidence. No boot, guest login, disk mount, memory extraction, snapshots or configuration changes.',
        'Disabled or absent evidence may depend on guest generation/platform. Review findings in context; no isolation certification or hypervisor CVE feed.',
        'Imported files are user-supplied, unauthenticated evidence and may differ from the running VM.' if imported else 'Local hypervisor metadata only; inaccessible fields remain unknown.'
    ],vmAssessment={'provider':str(data.get('provider','unknown'))[:50],'id':str(data.get('id',''))[:100],'name':str(data.get('name',''))[:200],'controls':{k:v for k,v in controls.items() if isinstance(v,bool) and k in ('secureBoot','tpm','remoteConsole','sharedFolders','bridgedNetwork','hostDevicePassthrough','nestedVirtualization')},'details':safe_details})

def assess(config,progress,stop):
    if config.get('mode','live')=='live':
        progress('Reading the selected local VM configuration…');data=collect(config,stop);target=data.get('name') or config['id'];imported=False
    else:
        path=audits.target_path(config.get('path',''))
        if not path.is_file() or path.stat().st_size>2_000_000:raise ValueError('Choose a VMX, libvirt XML or VM evidence JSON file under 2 MB.')
        text=path.read_text(encoding='utf-8-sig');imported=True;target=str(path)
        if path.suffix.lower()=='.vmx':data=pairs_evidence(text,'vmware',path.stem)
        elif path.suffix.lower()=='.xml':data=xml_evidence(text,path.stem)
        elif path.suffix.lower()=='.json':data=json.loads(text)
        else:raise ValueError('Choose .vmx, libvirt .xml, or .json evidence.')
    result=normalize(data,target,imported)
    if stop.is_set():result['status']='cancelled'
    return result

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--provider',choices=['hyperv','virtualbox','libvirt'],required=True)
    parser.add_argument('--id',required=True);parser.add_argument('--output',required=True)
    args=parser.parse_args();data=collect(vars(args));Path(args.output).write_text(json.dumps(data,indent=2),encoding='utf-8')
    print('Saved reduced read-only VM evidence.')
