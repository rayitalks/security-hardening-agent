"""Verify or recover an encrypted Ray-i PQC evaluation key bundle, locally."""
import argparse
import getpass
import json
import os
from pathlib import Path
from pqc_tools import worker

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle',type=Path)
    parser.add_argument('--output',type=Path,help='Write an UNENCRYPTED PKCS#8 PEM to this new file. Omit to verify recovery without writing a private key.')
    args=parser.parse_args()
    if args.bundle.stat().st_size>100000:parser.error('Bundle exceeds 100 KB.')
    if args.output and args.output.exists():parser.error('Output already exists; refusing to overwrite it.')
    bundle=json.loads(args.bundle.read_text(encoding='utf-8'))
    phrase=getpass.getpass('Key protection passphrase (hidden): ')
    try:
        result=worker({'operation':'unwrap','bundle':bundle,'passphrase':phrase,'verifyOnly':not bool(args.output)})
        if args.output:
            fd=os.open(args.output,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            with os.fdopen(fd,'w',encoding='ascii') as f:f.write(result['privateKeyPem'])
            print('Recovered private key written. Restrict the destination directory ACL on Windows; this file is unencrypted.')
        else:print('Recovery and key-pair consistency verified. No private key written.')
    finally:phrase=None

if __name__=='__main__':main()
