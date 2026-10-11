"""Portable host evidence collector. Run: python collector.py > host-report.json"""
import datetime as dt
import json
import platform
import shutil
import subprocess
from pathlib import Path

def command(args):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=20)
        return p.returncode, (p.stdout + p.stderr).strip()[:8000]
    except (OSError, subprocess.TimeoutExpired):
        return -1, 'Command unavailable, access denied, or timed out.'

def collect():
    system = platform.system()
    report = {'schema':'sha-host-v1', 'type':'host', 'createdAt':dt.datetime.now(dt.timezone.utc).isoformat(),
              'target':platform.node(), 'os':system, 'release':platform.release(), 'status':'complete', 'findings':[],
              'limitations':['Point-in-time local evidence. Missing permissions produce unknown results.', 'No remote operating-system assertions are inferred from an HTTP endpoint.', 'No exploitation, password auditing, comprehensive benchmark, or live CVE lookup.']}
    def add(name, status, evidence, recommendation):
        report['findings'].append(dict(name=name,status=status,evidence=evidence,recommendation=recommendation,area='Host'))
    if system == 'Windows':
        flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        try:
            p = subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(Path(__file__).with_name('scan.ps1'))],capture_output=True,timeout=100,creationflags=flags)
            if p.returncode:
                raise ValueError('Windows collection failed.')
            data = json.loads(p.stdout.decode('utf-8-sig', errors='replace'))
            for c in data['checks']:
                add(c['name'],c['status'],c['detail'],c['recommendation'])
        except Exception:
            add('Windows configuration','unknown','Windows collection failed or timed out.','Retry in a terminal with appropriate permissions.')
    elif system == 'Darwin':
        probes = [
            ('System Integrity Protection',['/usr/bin/csrutil','status'],'enabled','Keep SIP enabled.'),
            ('Gatekeeper',['/usr/sbin/spctl','--status'],'assessments enabled','Keep Gatekeeper assessment enabled.'),
            ('FileVault',['/usr/bin/fdesetup','status'],'FileVault is On','Review disk encryption and store the recovery key safely.'),
            ('Application firewall',['/usr/libexec/ApplicationFirewall/socketfilterfw','--getglobalstate'],'enabled','Review the application firewall in System Settings.'),
        ]
        for name,args,good,fix in probes:
            code,out = command(args)
            add(name,'unknown' if code else ('pass' if good.lower() in out.lower() else 'review'),out,fix)
        code,out = command(['/usr/sbin/lsof','-nP','-iTCP','-sTCP:LISTEN'])
        add('Listening TCP services','review' if code == 0 else 'unknown',out,'Check wildcard listeners and restrict AI services to trusted interfaces. Listing is limited by current-user access.')
    elif system == 'Linux':
        if shutil.which('ufw'):
            code,out = command(['ufw','status'])
            status = 'pass' if code == 0 and 'Status: active' in out else ('review' if code == 0 else 'unknown')
            add('UFW firewall',status,out,'Review the rules, default policies, and allowed AI server ports. Active does not establish adequate rules.')
        elif shutil.which('firewall-cmd'):
            code,out = command(['firewall-cmd','--state'])
            add('firewalld','pass' if code == 0 and out == 'running' else 'unknown',out,'Review zones and allowed services. Running does not establish adequate rules.')
        else:
            add('Host firewall','unknown','No supported UFW or firewalld frontend detected. nftables or other controls may still be active.','Review nftables/iptables rules with your administrator.')
        code,out = command(['ss','-lnt'])
        add('Listening TCP services','review' if code == 0 else 'unknown',out,'Check wildcard listeners and restrict inference APIs to trusted networks.')
        code,out = command(['lsblk','-o','NAME,TYPE,FSTYPE,MOUNTPOINT'])
        add('Storage encryption evidence','review' if code == 0 else 'unknown',out,'Review encrypted root/data volumes. This inventory cannot establish effective encryption for every volume.')
        sshd = shutil.which('sshd') or '/usr/sbin/sshd'
        code,out = command([sshd,'-T'])
        if code == 0:
            relevant = '\n'.join(x for x in out.splitlines() if x.startswith(('permitrootlogin ','passwordauthentication ','pubkeyauthentication ')))
            add('SSH configuration','review',relevant or 'No relevant values returned.','Disable unnecessary root/password login after verifying working key access. Match blocks may alter effective policy for a connection.')
        else:
            add('SSH configuration','unknown','Effective sshd configuration could not be read; SSH may not be installed.','Review effective SSH settings with appropriate access if SSH is used.')
    else:
        add('Operating system','unknown',system,'This collector supports Windows, macOS, and Linux.')
    if any(f['status'] == 'unknown' for f in report['findings']):
        report['status'] = 'partial'
    return report

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Read-only host evidence collector')
    parser.add_argument('--output', help='Write a UTF-8 JSON report to this file')
    args = parser.parse_args()
    data = json.dumps(collect(), indent=2)
    if args.output:
        Path(args.output).write_text(data, encoding='utf-8')
    else:
        print(data)
