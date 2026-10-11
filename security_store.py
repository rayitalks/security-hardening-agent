"""Local, bounded persistence for assets, policies and redacted runtime decisions."""
import contextlib
import datetime as dt
import json
import os
from pathlib import Path
import sqlite3
import uuid

ROOT = Path(__file__).resolve().parent

def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()

def database_path():
    base = Path(os.environ.get('SHA_DATA_DIR') or ('/data' if os.environ.get('SHA_CONTAINER') else ROOT / '.data'))
    base.mkdir(parents=True, exist_ok=True)
    return base / 'security.db'

@contextlib.contextmanager
def database():
    db = sqlite3.connect(database_path(), timeout=10)
    try:
        db.execute('PRAGMA busy_timeout=10000')
        db.execute('CREATE TABLE IF NOT EXISTS objects (kind TEXT, id TEXT, body TEXT, PRIMARY KEY(kind,id))')
        db.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, created TEXT, asset TEXT, point TEXT, decision TEXT, body TEXT)')
        yield db
        db.commit()
    finally:
        db.close()

def put(kind, item):
    item = dict(item)
    item.setdefault('id', uuid.uuid4().hex)
    item['updatedAt'] = now()
    body = json.dumps(item, ensure_ascii=True)
    if len(body) > 1_000_000:
        raise ValueError('Record exceeds 1 MB.')
    with database() as db:
        count = db.execute('SELECT COUNT(*) FROM objects WHERE kind=?', (kind,)).fetchone()[0]
        exists = db.execute('SELECT 1 FROM objects WHERE kind=? AND id=?', (kind,item['id'])).fetchone()
        if count >= 2000 and not exists:
            raise ValueError('The local registry limit of 2,000 records per kind has been reached.')
        db.execute('INSERT OR REPLACE INTO objects VALUES (?,?,?)', (kind,item['id'],body))
    return item

def get(kind, identity):
    with database() as db:
        row = db.execute('SELECT body FROM objects WHERE kind=? AND id=?', (kind,str(identity))).fetchone()
    return json.loads(row[0]) if row else None

def all_items(kind):
    with database() as db:
        return [json.loads(row[0]) for row in db.execute('SELECT body FROM objects WHERE kind=? ORDER BY id', (kind,))]

def event(asset, point, decision, rules, size=0):
    # Never persist request text, responses, tool arguments, bearer keys, or hashes of content.
    body = {'rules': sorted(set(str(r)[:100] for r in rules)), 'bytes': int(size)}
    with database() as db:
        db.execute('INSERT INTO events(created,asset,point,decision,body) VALUES (?,?,?,?,?)',
                   (now(),str(asset)[:100],str(point)[:60],str(decision)[:30],json.dumps(body)))
        db.execute('DELETE FROM events WHERE id <= (SELECT COALESCE(MAX(id),0)-10000 FROM events)')

def events(limit=200):
    with database() as db:
        rows = db.execute('SELECT id,created,asset,point,decision,body FROM events ORDER BY id DESC LIMIT ?', (max(1,min(int(limit),1000)),)).fetchall()
        counts = dict(db.execute('SELECT decision,COUNT(*) FROM events GROUP BY decision'))
    return {'events':[dict(id=r[0],createdAt=r[1],assetId=r[2],point=r[3],decision=r[4],**json.loads(r[5])) for r in rows],
            'counts':counts,'retention':'Most recent 10,000 decisions. Payloads and credentials are not stored.'}
