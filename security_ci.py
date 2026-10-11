"""Run approved synthetic regressions on a trusted runner. Exit nonzero on failures or gaps."""
import argparse
import json
import os
from pathlib import Path
import threading
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--config',required=True);parser.add_argument('--output',required=True);parser.add_argument('--data-dir',required=True)
    args=parser.parse_args();os.environ['SHA_DATA_DIR']=str(Path(args.data_dir).resolve())
    import team_suite
    config=json.loads(Path(args.config).read_text(encoding='utf-8'))
    if config.get('key'):raise ValueError('Use keyEnv rather than storing an API key in CI configuration.')
    report=team_suite.assess(config,lambda _:None,threading.Event());Path(args.output).write_text(json.dumps(report,indent=2),encoding='utf-8')
    return 0 if report['status']=='complete' and report['findings'] and all(r['status']=='pass' for r in report['findings']) else 1
if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception:print('CI gate failed: scope, credentials, inference or evidence unavailable.');raise SystemExit(2)
