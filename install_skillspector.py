"""Install the bundled, pinned SkillSpector release into an app-only runtime."""
import hashlib
from pathlib import Path
import subprocess
import sys
import venv

ROOT=Path(__file__).resolve().parent
WHEEL=ROOT/'vendor/skillspector-2.12.0-py3-none-any.whl'
EXPECTED='c158e965bca8cd7efea821ce973a19a858026041b3e999369f7bdf66ea93a213'

if __name__=='__main__':
    if not (3,12)<=sys.version_info[:2]<(3,15):
        raise SystemExit('SkillSpector needs Python 3.12, 3.13, or 3.14. Use Docker if this Python version is unsupported.')
    if not WHEEL.is_file() or hashlib.sha256(WHEEL.read_bytes()).hexdigest()!=EXPECTED:
        raise SystemExit('Bundled SkillSpector package is missing or its checksum does not match.')
    runtime=ROOT/'.runtime'
    venv.EnvBuilder(with_pip=True).create(runtime)
    python=runtime/('Scripts/python.exe' if sys.platform=='win32' else 'bin/python')
    subprocess.run([str(python),'-m','pip','install','--find-links',str(ROOT/'vendor'),'-c',str(ROOT/'constraints-skillspector.txt'),str(WHEEL)],check=True)
    subprocess.run([str(python),'-c','import yara; import skillspector; print("NVIDIA SkillSpector installed successfully.")'],check=True)
