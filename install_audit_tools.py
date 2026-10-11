"""Install optional PDF and Sigstore engines in an isolated local runtime."""
from pathlib import Path
import os
import subprocess
import sys
import venv

ROOT=Path(__file__).resolve().parent

if __name__=='__main__':
    runtime=ROOT/'.audit-runtime'
    venv.EnvBuilder(with_pip=True).create(runtime)
    python=runtime/('Scripts/python.exe' if os.name=='nt' else 'bin/python')
    subprocess.run([str(python),'-m','pip','install','--disable-pip-version-check','pypdf==6.19.0','model-signing==1.1.1','watchdog==6.0.0','psutil==7.2.2','cryptography==50.0.2'],check=True)
    import install_gitleaks
    install_gitleaks.install()
    print('Optional PDF and model-signing tools installed.')
