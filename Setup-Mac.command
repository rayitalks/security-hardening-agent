#!/bin/sh
set -eu
cd "$(dirname "$0")"
for interpreter in python3.12 python3.13; do
    if command -v "$interpreter" >/dev/null 2>&1; then
        exec "$interpreter" setup_device.py --engines all --launch
    fi
done
printf '%s\n' 'Install Python 3.12 from https://www.python.org/downloads/ then run: sh Setup-Mac.command' >&2
printf '%s\n' 'See START-HERE.md for details.' >&2
exit 1
