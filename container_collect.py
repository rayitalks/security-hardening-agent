"""Collect sanitized read-only Docker evidence on the container host."""
import argparse
import json
from pathlib import Path
import containers

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--container',required=True)
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    data=containers.collect(args.container)
    Path(args.output).write_text(json.dumps(data,indent=2),encoding='utf-8')
    print('Saved container evidence without environment values, command arguments or health logs.')
