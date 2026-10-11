"""Separate tamper-evident security-agent ledger; opt-in AES-256-GCM payload capture."""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import security_store as store

LOCK=threading.RLock()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
def directory():
    path=store.database_path().parent/'agent-audit';path.mkdir(exist_ok=True)
    return path
def signing_key():
    path=directory()/'integrity.key'
    with LOCK:
        if not path.exists():
            with path.open('xb') as f:f.write(secrets.token_bytes(32))
            os.chmod(path,0o600)
        key=path.read_bytes()
    if len(key)!=32:raise ValueError('Audit integrity key is invalid.')
    return key
def sign(value):return hmac.new(signing_key(),canonical(value),hashlib.sha256).hexdigest()
def settings():return store.get('settings','audit') or {'id':'audit','capture':False,'keyEnv':'RAYI_AUDIT_KEY'}
def capture_key(env):
    try:
        key=base64.b64decode(os.environ.get(env,''),validate=True)
        if len(key)!=32:raise ValueError()
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key)
    except Exception:raise ValueError('Full capture requires cryptography and a supplied base64-encoded 32-byte key in the named environment variable. Set it locally, then restart the app.') from None
def configure(config):
    env=config.get('keyEnv','RAYI_AUDIT_KEY')
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,79}',env):raise ValueError('Use an environment variable name, never paste a key here.')
    enabled=config.get('capture') is True
    if enabled:capture_key(env)
    append('console','audit-configuration','changed',{'capture':enabled,'keyEnv':env},force_metadata=True)
    return store.put('settings',{'id':'audit','capture':enabled,'keyEnv':env})
def connection():
    db=sqlite3.connect(directory()/'ledger.sqlite',timeout=10)
    db.execute('CREATE TABLE IF NOT EXISTS ledger(seq INTEGER PRIMARY KEY, body TEXT, digest TEXT)')
    return db
def append(agent,action,decision,payload=None,trace=None,force_metadata=False):
    raw=canonical(payload);trace=trace if isinstance(trace,str) and re.fullmatch(r'[A-Za-z0-9_-]{8,80}',trace) else secrets.token_hex(16)
    with LOCK:
        config=settings()
        db=connection()
        try:
            db.execute('BEGIN IMMEDIATE')
            prev=db.execute('SELECT seq,digest FROM ledger ORDER BY seq DESC LIMIT 1').fetchone()
            seq=prev[0]+1 if prev else 1
            if seq>100000:raise ValueError('Audit ledger limit reached. Archive the ledger and its trusted anchor before continuing.')
            record={'sequence':seq,'time':store.now(),'agent':str(agent)[:100],'action':str(action)[:100],
                    'decision':str(decision)[:30],'traceId':trace,'payloadHash':hashlib.sha256(raw).hexdigest(),'payloadBytes':len(raw),'previous':prev[1] if prev else 'GENESIS'}
            if config['capture'] and not force_metadata:
                cipher=capture_key(config['keyEnv']);nonce=secrets.token_bytes(12)
                record['encryptedPayload']={'algorithm':'AES-256-GCM','keyEnv':config['keyEnv'],'nonce':base64.b64encode(nonce).decode(),
                    'ciphertext':base64.b64encode(cipher.encrypt(nonce,raw,canonical(record))).decode()}
            digest=sign(record)
            db.execute('INSERT INTO ledger VALUES (?,?,?)',(seq,canonical(record).decode(),digest));db.commit()
            return {'sequence':seq,'digest':digest,'traceId':trace}
        finally:db.close()
def verify(config=None):
    config=config or {};previous='GENESIS';count=0;valid=True
    with LOCK:
        db=connection()
        try:
            for seq,body,digest in db.execute('SELECT seq,body,digest FROM ledger ORDER BY seq'):
                row=json.loads(body);count+=1
                if seq!=count or row['sequence']!=seq or row['previous']!=previous or not hmac.compare_digest(sign(row),digest):valid=False;break
                previous=digest
            anchor=config.get('anchor')
            if anchor:
                found=db.execute('SELECT digest FROM ledger WHERE seq=?',(int(anchor['sequence']),)).fetchone()
                valid=valid and bool(found) and hmac.compare_digest(found[0],anchor['digest'])
        finally:db.close()
    return {'valid':valid,'records':count,'anchor':{'sequence':count,'digest':previous},'anchored':bool(config.get('anchor')),
            'limit':'Export and retain anchors separately to detect tail truncation. A host administrator with the integrity key can rewrite this ledger.'}
def snapshot():
    with LOCK:
        db=connection()
        try:
            rows=[]
            for b,d in db.execute('SELECT body,digest FROM ledger ORDER BY seq DESC LIMIT 250'):
                row=json.loads(b);cipher=row.pop('encryptedPayload',None)
                if cipher:row['capture']={'encrypted':True,'algorithm':cipher['algorithm'],'keyEnv':cipher['keyEnv']}
                rows.append(dict(row,digest=d))
        finally:db.close()
    return {'settings':settings(),'verification':verify(),'records':rows,'retention':'Preview: latest 250 metadata records only. Use audit_export.py for the complete ciphertext ledger. Up to 100,000 append-only records; metadata and SHA-256 payload hashes by default. Export before the hard limit.'}
