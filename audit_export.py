"""Export the complete ciphertext ledger and trusted anchor without copying keys."""
import argparse
import json
import os
from pathlib import Path
import audit_trail as audit

def export(path):
    path=Path(path)
    if path.exists():raise ValueError('Choose a new output file; existing evidence is never overwritten.')
    with audit.LOCK:
        verification=audit.verify()
        if not verification['valid']:raise ValueError('Audit integrity failed. Preserve the source ledger and investigate before exporting trusted evidence.')
        db=audit.connection()
        try:
            with path.open('x',encoding='utf-8') as f:
                f.write(json.dumps({'type':'anchor','verification':verification})+'\n')
                for body,digest in db.execute('SELECT body,digest FROM ledger ORDER BY seq'):
                    f.write(json.dumps({'type':'record','body':json.loads(body),'digest':digest})+'\n')
        finally:db.close()
    return verification['anchor']
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--data-dir',required=True);p.add_argument('--output',required=True);args=p.parse_args()
    os.environ['SHA_DATA_DIR']=str(Path(args.data_dir).resolve());print(json.dumps(export(args.output)))
