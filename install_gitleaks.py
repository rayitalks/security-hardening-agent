"""Install a checksum-pinned official Gitleaks binary without extracting archive paths."""
from pathlib import Path
import hashlib
import io
import os
import platform
import tarfile
import urllib.request
import zipfile

ROOT=Path(__file__).resolve().parent
VERSION='8.30.1'
ARCHIVES={
    ('Windows','AMD64'):('windows_x64.zip','d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e'),
    ('Linux','x86_64'):('linux_x64.tar.gz','551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb'),
    ('Linux','aarch64'):('linux_arm64.tar.gz','e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080'),
    ('Darwin','x86_64'):('darwin_x64.tar.gz','dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709'),
    ('Darwin','arm64'):('darwin_arm64.tar.gz','b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5'),
}

def install():
    suffix,digest=ARCHIVES[(platform.system(),platform.machine())]
    url=f'https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/gitleaks_{VERSION}_{suffix}'
    with urllib.request.urlopen(url,timeout=90) as response:data=response.read(80_000_001)
    if len(data)>80_000_000 or hashlib.sha256(data).hexdigest()!=digest:raise RuntimeError('Gitleaks archive checksum mismatch or oversized download.')
    destination=ROOT/'.tools'/'gitleaks';destination.mkdir(parents=True,exist_ok=True)
    wanted='gitleaks.exe' if os.name=='nt' else 'gitleaks'
    extracted={}
    if suffix.endswith('.zip'):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for member in archive.infolist():
                if member.filename in (wanted,'LICENSE') and member.file_size<80_000_000:extracted[member.filename]=archive.read(member)
    else:
        with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
            for member in archive:
                if member.name in (wanted,'LICENSE') and member.isfile() and member.size<80_000_000:extracted[member.name]=archive.extractfile(member).read()
    if wanted not in extracted:raise RuntimeError('Expected Gitleaks binary missing.')
    for name,value in extracted.items():(destination/name).write_bytes(value)
    (destination/wanted).chmod(0o755)
    print('Gitleaks '+VERSION+' installed; official archive SHA-256 verified.')

if __name__=='__main__':install()
