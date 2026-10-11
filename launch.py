"""Start the console without a persistent terminal, or open its existing instance."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request
import webbrowser

ROOT = Path(__file__).resolve().parent
URL = 'http://127.0.0.1:8765/'

def ready():
    try:
        with urllib.request.urlopen(URL+'api/environment',timeout=1) as r:
            return json.load(r).get('app') == 'ray-i-security-hardening-agent'
    except Exception:
        return False

if not ready():
    log = open(ROOT/'launcher.log','ab')
    options = {'cwd':str(ROOT),'stdin':subprocess.DEVNULL,'stdout':log,'stderr':log}
    if os.name == 'nt':
        options['creationflags'] = subprocess.CREATE_NO_WINDOW
    else:
        options['start_new_session'] = True
    enhanced=ROOT/'.audit-runtime'/('Scripts/python.exe' if os.name=='nt' else 'bin/python')
    child = subprocess.Popen([str(enhanced) if enhanced.is_file() else sys.executable,str(ROOT/'app.py')],**options)
    for _ in range(30):
        if ready():
            break
        if child.poll() is not None:
            raise SystemExit('The app could not start. Port 8765 may be occupied. Check launcher.log.')
        time.sleep(.2)
    else:
        raise SystemExit('The app did not become ready. Check launcher.log.')
webbrowser.open(URL)
