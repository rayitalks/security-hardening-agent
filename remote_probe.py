"""Portable second-machine AI exposure probe. Python standard library only."""
import argparse
import datetime as dt
import ipaddress
import json
from pathlib import Path
import platform
import socket
import urllib.error
import urllib.request

SIGNATURES={'/api/version':'Ollama/version candidate','/v1/models':'OpenAI-compatible candidate','/config':'Gradio/config candidate','/system_stats':'ComfyUI candidate','/api/config':'Open WebUI/config candidate','/api':'Jupyter/API candidate','/collections':'Qdrant candidate'}

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None

def probe(target,ports,authorized=False,allow_private=False,tls_ports=()):
    if not authorized:raise ValueError('Explicit target authorization is required.')
    if not target or len(target)>253 or any(c in target for c in '/@?# \\'):raise ValueError('Choose one host/IP, without a URL, range, credentials or path.')
    addresses={r[4][0] for r in socket.getaddrinfo(target,None,type=socket.SOCK_STREAM)}
    if not allow_private and any(not ipaddress.ip_address(a).is_global for a in addresses):raise ValueError('Outside-in targets must resolve to public addresses. --allow-private is for a clearly labelled internal test.')
    if not ports or len(ports)>20 or any(not 1<=p<=65535 for p in ports):raise ValueError('Choose 1–20 explicit TCP ports.')
    results=[];findings=[]
    http=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    for port in ports:
        try:
            with socket.create_connection((target,port),timeout=2):pass
            opened=True
        except OSError:opened=False
        checks=[]
        if opened:
            for path,label in SIGNATURES.items():
                req=urllib.request.Request(('https' if port in tls_ports else 'http')+'://'+('['+target+']' if ':' in target else target)+':'+str(port)+path,headers={'User-Agent':'Ray-i-Outside-In/2.0','Accept':'application/json'})
                try:
                    with http.open(req,timeout=2) as response:
                        data=response.read(8192)
                        try:parsed=json.loads(data)
                        except (ValueError,UnicodeError):parsed=None
                        # Require service-shaped evidence to avoid calling an SPA fallback an AI service.
                        expected={'/api/version':('version',),'/v1/models':('data',),'/config':('components','version'),'/system_stats':('system','devices'),'/api/config':('features','status'),'/api':('version',),'/collections':('result',)}[path]
                        matched=isinstance(parsed,dict) and any(k in parsed for k in expected)
                        checks.append({'path':path,'status':response.status,'candidate':label if matched else None})
                except urllib.error.HTTPError as exc:
                    checks.append({'path':path,'status':exc.code,'candidate':None});exc.close()
                except OSError:checks.append({'path':path,'status':None,'candidate':None})
            hits=[c['candidate'] for c in checks if c['candidate']]
            findings.append({'name':'Reachable TCP port '+str(port),'status':'attention' if hits else 'review','evidence':('Unauthenticated service-shaped JSON: '+', '.join(hits)) if hits else 'TCP reachable; no supported AI fingerprint established.',
                             'recommendation':'Review internet exposure, authentication and firewall/proxy rules. Fingerprints are candidates, not verified product identities.','area':'Outside-in'})
        results.append({'port':port,'reachable':opened,'checks':checks})
    return {'schema':'sha-outside-in-v1','type':'Outside-in AI exposure','createdAt':dt.datetime.now(dt.timezone.utc).isoformat(),'target':target,
            'status':'complete','findings':findings,'probe':{'machine':platform.node(),'resolvedAddresses':sorted(addresses),'ports':results,'privateTargetsAllowed':allow_private},
            'limitations':['Point-in-time probe from the machine that ran this script; the importer cannot authenticate its vantage or evidence. Run on a second machine outside the VPS network to establish an outside-in observation.',
                           'At most 20 selected TCP ports and seven bounded GET paths per open port. No network ranges, POST operations, exploit templates or credential collection. Closed/failed ports can reflect filtering or service unavailability. TLS verification remains enabled; redirects are not followed.']}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target',required=True);parser.add_argument('--ports',required=True,help='Comma-separated authorized ports, up to 20')
    parser.add_argument('--tls-ports',default='');parser.add_argument('--authorized',action='store_true');parser.add_argument('--allow-private',action='store_true')
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    output=probe(args.target,[int(x) for x in args.ports.split(',')],args.authorized,args.allow_private,[int(x) for x in args.tls_ports.split(',') if x])
    Path(args.output).write_text(json.dumps(output,indent=2),encoding='utf-8')
    print('Saved scoped probe report to '+args.output)
