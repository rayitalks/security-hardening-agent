"""Local post-quantum key generation through the installed Node/OpenSSL runtime."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
import audit_trail

ROOT=Path(__file__).resolve().parent
KEY_LOCK=threading.Lock()
ALGORITHMS=('ml-kem-768','ml-kem-1024','ml-dsa-65','ml-dsa-87')

def worker(config):
    executable=os.environ.get('SHA_PQC_NODE') or shutil.which('node')
    if not executable or not Path(executable).is_file():
        raise ValueError('Node.js 24.7+ with OpenSSL ML-KEM/ML-DSA support is required. Set SHA_PQC_NODE to its absolute executable path if needed.')
    try:
        process=subprocess.run([executable,str(ROOT/'pqc_worker.cjs')],input=json.dumps(config),capture_output=True,text=True,timeout=30,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    except (OSError,subprocess.TimeoutExpired):
        raise ValueError('The local cryptography runtime is unavailable or timed out.') from None
    if process.returncode:
        # Raw provider errors can contain input; never relay them to the UI or logs.
        raise ValueError('Cryptography operation failed. Check the supported runtime, selected algorithm, profile and protection passphrase.')
    return json.loads(process.stdout)

def status():
    try:
        result=worker({'operation':'status'})
        parts=tuple(int(v) for v in result['node'].lstrip('v').split('.')[:2])
        if parts<(24,7):raise ValueError('Node.js 24.7 or newer is required for this key generator.')
        return result
    except ValueError as exc:
        return {'available':False,'moduleValidation':'not-established','governmentReady':False,'message':str(exc),'algorithms':list(ALGORITHMS)}

def generate(config):
    algorithm=config.get('algorithm')
    if algorithm not in ALGORITHMS:raise ValueError('Choose a supported ML-KEM or ML-DSA parameter set.')
    if config.get('profile')!='evaluation':
        raise ValueError('Government key generation is blocked: no verified CMVP module integration is configured. Use an approved KMS/HSM, or choose local evaluation for non-government test keys.')
    phrase=config.get('passphrase')
    if not isinstance(phrase,str) or not 24<=len(phrase) or len(phrase.encode('utf-8'))>1024:
        raise ValueError('Use a unique protection passphrase of at least 24 characters and at most 1024 UTF-8 bytes.')
    if not KEY_LOCK.acquire(blocking=False):raise ValueError('A key-generation operation is already running. Try again after it finishes.')
    try:
        result=worker({'operation':'generate','algorithm':algorithm,'profile':'evaluation','passphrase':phrase})
        # Even when full audit capture is enabled, no passphrase, private key or ciphertext is logged.
        audit_trail.append('console','pqc-key-generation','evaluation',{'algorithm':algorithm,'publicKeySha256':result['publicKeySha256'],'moduleValidation':'not-established'},force_metadata=True)
        return result
    finally:
        config.pop('passphrase',None)
        phrase=None
        KEY_LOCK.release()
