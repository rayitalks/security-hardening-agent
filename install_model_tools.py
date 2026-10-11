"""Install isolated, pinned static model and packet tools (Python 3.12/3.13)."""
import hashlib
from pathlib import Path
import subprocess
import sys
import venv

ROOT=Path(__file__).resolve().parent
WHEEL=ROOT/'vendor/modelaudit-0.2.52-py3-none-any.whl'
EXPECTED='79f3a1c33acc04f8d3dc04fa0cf7ba6fc0823054f1196662d3aed64805e9aa08'

if __name__=='__main__':
    if not (3,12)<=sys.version_info[:2]<(3,14):
        raise SystemExit('Use Python 3.12 (recommended), Python 3.13, or Docker to install the model runtime. Main app can use other Python versions.')
    if not WHEEL.is_file() or hashlib.sha256(WHEEL.read_bytes()).hexdigest()!=EXPECTED:
        raise SystemExit('Bundled ModelAudit package is missing or its checksum does not match.')
    folder=ROOT/'.model-runtime'
    venv.EnvBuilder(with_pip=True).create(folder)
    python=folder/('Scripts/python.exe' if sys.platform=='win32' else 'bin/python')
    subprocess.run([str(python),'-m','pip','install','-c',str(ROOT/'constraints-model.txt'),str(WHEEL)+'[h5,onnx,safetensors]',
                    'scapy==2.7.0','psutil==7.1.3'],check=True)
    subprocess.run([str(python),'-c','import modelaudit,scapy,psutil; print("Local model and packet tools installed.")'],check=True)
