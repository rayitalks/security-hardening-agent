"""Run the pinned NVIDIA scanner in a fresh process with restricted networking.

This is an egress guard for trusted Python dependencies, not a code sandbox.
Scanned code is never intentionally imported or executed.
"""
import ipaddress
import json
import os
import socket
import sys

def install_network_guard(endpoint=None):
    allowed = set()
    if endpoint:
        from urllib.parse import urlsplit
        p = urlsplit(endpoint)
        for addr in socket.getaddrinfo(p.hostname, p.port or 80, type=socket.SOCK_STREAM):
            allowed.add((addr[4][0], p.port or 80))
        allowed.add((p.hostname, p.port or 80))

    def guard(event, args):
        if event == 'socket.getaddrinfo':
            host, port = args[0], args[1]
            if (host, port) not in allowed:
                raise OSError('Network access disabled for this local SkillSpector scan.')
        if event in ('socket.connect', 'socket.sendto'):
            address = args[1] if event == 'socket.connect' else args[-1]
            if not isinstance(address, tuple) or (str(address[0]), address[1]) not in allowed:
                raise OSError('Network access disabled for this local SkillSpector scan.')
    sys.addaudithook(guard)

def main():
    from pathlib import Path
    config = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
    semantic = config.get('semantic', False)
    # Set before imports: prevent OSV requests, cloud tracing, and accidental cloud-provider use.
    os.environ.update(SKILLSPECTOR_OSV_TIMEOUT='0', SKILLSPECTOR_MAX_WORKFLOW_SECONDS='240',
                      LANGSMITH_TRACING='false', LANGCHAIN_TRACING_V2='false',
                      AWS_EC2_METADATA_DISABLED='true', DO_NOT_TRACK='1', TOKENIZERS_PARALLELISM='false')
    if semantic:
        os.environ.update(SKILLSPECTOR_PROVIDER='ollama', OLLAMA_BASE_URL=config['endpoint'], SKILLSPECTOR_MODEL=config['model'])
    else:
        os.environ['SKILLSPECTOR_PROVIDER'] = 'ollama'
    install_network_guard(config.get('endpoint') if semantic else None)
    from skillspector.cli import app
    argv = ['scan', config['target'], '--format', 'json', '--output', config['output']]
    if not semantic:
        argv.append('--no-llm')
    # No target-provided baselines, no transitive downloads, no CLI-agent provider.
    sys.argv = ['skillspector'] + argv
    app()

if __name__ == '__main__':
    main()
