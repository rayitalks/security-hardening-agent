"""Install pinned official Trivy into this app, verifying the release archive hash."""
import hashlib
import io
import os
from pathlib import Path
import platform
import tarfile
import urllib.request
import zipfile

VERSION = '0.75.0'
ROOT = Path(__file__).resolve().parent
ASSETS = {
    ('Windows','AMD64'): ('windows-64bit.zip','4e43bd71a30f51aee39525f60f2b47043af77eb8df8fe082aae4372b69c6660f'),
    ('Linux','x86_64'): ('Linux-64bit.tar.gz','c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f'),
    ('Linux','aarch64'): ('Linux-ARM64.tar.gz','a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3'),
    ('Darwin','x86_64'): ('macOS-64bit.tar.gz','291edaa9778acbe4693d067b5ad60ee11570e5ac68296e85595417528ca641e4'),
    ('Darwin','arm64'): ('macOS-ARM64.tar.gz','4a77108cccf8e55c8d6823e1e759939a622277e66cd0daa3c1fc621ed69e4568'),
}


def executable():
    return ROOT/'.tools'/'trivy'/('trivy.exe' if os.name=='nt' else 'trivy')


def install():
    system = platform.system()
    asset = ASSETS.get((system, platform.machine()))
    if not asset:
        raise SystemExit('This platform is not in the supported pinned Trivy release list. Use the Docker build.')
    filename, expected = asset
    url = f'https://github.com/aquasecurity/trivy/releases/download/v{VERSION}/trivy_{VERSION}_{filename}'
    print(f'Downloading official Trivy {VERSION} for {system}...', flush=True)
    with urllib.request.urlopen(url, timeout=90) as response:
        archive = response.read(150*1024*1024 + 1)
    if len(archive)>150*1024*1024 or hashlib.sha256(archive).hexdigest()!=expected:
        raise SystemExit('Release checksum verification failed; nothing installed.')
    binary = 'trivy.exe' if system=='Windows' else 'trivy'
    if filename.endswith('.zip'):
        with zipfile.ZipFile(io.BytesIO(archive)) as z:
            if z.getinfo(binary).file_size > 250*1024*1024:
                raise SystemExit('Unexpected binary size.')
            content = z.read(binary)
            license_text = z.read('LICENSE')
    else:
        with tarfile.open(fileobj=io.BytesIO(archive),mode='r:gz') as z:
            member = z.getmember(binary)
            if not member.isfile() or member.size>250*1024*1024:
                raise SystemExit('Unexpected binary entry.')
            content = z.extractfile(member).read()
            license_text = z.extractfile('LICENSE').read()
    destination = executable()
    destination.parent.mkdir(parents=True, exist_ok=True)
    staged = destination.with_suffix('.pending')
    staged.write_bytes(content)
    staged.chmod(0o755)
    staged.replace(destination)
    (ROOT/'licenses').mkdir(exist_ok=True)
    (ROOT/'licenses'/'Trivy-LICENSE.txt').write_bytes(license_text)
    print(f'Trivy {VERSION} installed; archive SHA-256 verified. Database downloads occur only when selected in the app.')


if __name__=='__main__':
    install()
