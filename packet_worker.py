"""Bounded local packet/connection analysis; payloads never leave this worker."""
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import time

PROVIDERS=('api.openai.com','api.anthropic.com','generativelanguage.googleapis.com','api.mistral.ai',
           'api.cohere.com','api.groq.com','api.deepseek.com','api.together.xyz','api.together.ai','api.fireworks.ai',
           'inference.huggingface.co','router.huggingface.co')
AI_PATH=re.compile(rb'^(?:POST|GET) (/(?:v1/(?:chat/completions|responses|completions|embeddings|models)|api/(?:chat|generate|embed|embeddings|tags)))(?:[? /\r\n])')
MODEL_NAMES={'ollama','ollama.exe','llama-server','llama-server.exe','vllm','lm studio','lm studio.exe','lmstudio','llamacpp'}

def provider(name):
    name=name.lower().rstrip('.')
    return next((x for x in PROVIDERS if name==x or name.endswith('.'+x)),None)

def tls_sni(data):
    """Read an unfragmented TLS ClientHello's SNI; no decryption or reassembly."""
    try:
        if len(data)<9 or data[0]!=22 or data[5]!=1:return None
        end=min(len(data),5+int.from_bytes(data[3:5],'big'))
        body=data[9:end];pos=34
        pos+=1+body[pos];n=int.from_bytes(body[pos:pos+2],'big');pos+=2+n
        pos+=1+body[pos];ext_end=pos+2+int.from_bytes(body[pos:pos+2],'big');pos+=2
        if ext_end>len(body):return None
        while pos+4<=ext_end:
            kind=int.from_bytes(body[pos:pos+2],'big');size=int.from_bytes(body[pos+2:pos+4],'big');pos+=4
            if pos+size>ext_end:return None
            if kind==0:
                chunk=body[pos:pos+size];offset=2
                while offset+3<=len(chunk):
                    typ=chunk[offset];ln=int.from_bytes(chunk[offset+1:offset+3],'big');offset+=3
                    if offset+ln>len(chunk):return None
                    if typ==0:return chunk[offset:offset+ln].decode('ascii',errors='ignore')
                    offset+=ln
            pos+=size
    except (ValueError,IndexError):pass
    return None

class Analyzer:
    def __init__(self,cidrs):
        self.networks=[ipaddress.ip_network(c,strict=False) for c in cidrs]
        self.flows={};self.packets=0;self.unsupported=0;self.droppedFlows=0;self.malformed=0
    def trusted(self,addr):
        value=ipaddress.ip_address(addr)
        return any(value in n for n in self.networks if n.version==value.version)
    def direction(self,src,dst):
        a,b=self.trusted(src),self.trusted(dst)
        return 'outbound' if a and not b else 'inbound' if b and not a else 'internal' if a and b else 'outside selected boundary'
    def packet(self,p):
        from scapy.layers.inet import IP,TCP,UDP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.dns import DNS
        self.packets+=1
        try:
            network=p.getlayer(IP) or p.getlayer(IPv6)
            if network is None:self.unsupported+=1;return
            src,dst=str(network.src),str(network.dst)
            transport=p.getlayer(TCP) or p.getlayer(UDP)
            protocol='TCP' if p.haslayer(TCP) else 'UDP' if p.haslayer(UDP) else 'Other IP'
            sport,dport=(int(transport.sport),int(transport.dport)) if transport else (0,0)
            key=(src,dst,sport,dport,protocol)
            if key not in self.flows:
                if len(self.flows)>=3000:self.droppedFlows+=1;return
                self.flows[key]={'source':src,'destination':dst,'sourcePort':sport,'destinationPort':dport,'transport':protocol,
                    'direction':self.direction(src,dst),'packets':0,'bytes':0,'hints':set(),'protocols':set(),'encrypted':False}
            flow=self.flows[key];flow['packets']+=1;flow['bytes']+=len(p)
            payload=bytes(transport.payload)[:8192] if transport else b''
            if p.haslayer(DNS):
                flow['protocols'].add('DNS')
                dns=p.getlayer(DNS)
                if dns.qd:
                    known=provider(bytes(dns.qd[0].qname).decode('ascii',errors='ignore'))
                    if known:flow['hints'].add('DNS query for known AI service: '+known)
            match=AI_PATH.match(payload)
            if match:
                flow['protocols'].add('HTTP');flow['hints'].add('AI API-shaped HTTP path: '+match[1].decode('ascii'))
            if payload.startswith((b'POST ',b'GET ',b'PUT ',b'HEAD ',b'HTTP/')):
                flow['protocols'].add('HTTP')
                header=payload.split(b'\r\n\r\n',1)[0]
                host=re.search(rb'(?im)^Host:\s*([^:\r\n ]+)',header)
                known=provider(host[1].decode('ascii',errors='ignore')) if host else None
                if known:flow['hints'].add('HTTP host is known AI service: '+known)
                if payload.startswith((b'POST ',b'PUT ')) and re.search(rb'(?i)filename=[^\r\n]{0,200}\.(?:gguf|safetensors|onnx|pt|pth|pkl)(?:["\s;]|$)',payload):
                    flow['hints'].add('Possible model-file upload filename; transfer contents unverified')
            if len(payload)>5 and payload[0] in (20,21,22,23) and payload[1]==3:
                flow['protocols'].add('TLS');flow['encrypted']=True
                known=provider(tls_sni(payload) or '')
                if known:flow['hints'].add('TLS SNI is known AI service: '+known)
            elif protocol=='TCP' and (sport==443 or dport==443):
                flow['protocols'].add('HTTPS-port candidate');flow['encrypted']=True
            if protocol=='UDP' and (sport==443 or dport==443):
                flow['protocols'].add('QUIC/HTTPS-port candidate');flow['encrypted']=True
            if protocol=='TCP' and (sport in (11434,1234,8000) or dport in (11434,1234,8000)):
                flow['hints'].add('Common inference port; AI use unconfirmed')
        except Exception:self.malformed+=1
    def result(self):
        flows=[]
        for f in self.flows.values():
            f=dict(f);f['hints']=sorted(f['hints']);f['protocols']=sorted(f['protocols']);flows.append(f)
        flows.sort(key=lambda x:(x['direction']!='outbound',not bool(x['hints']),-x['bytes']))
        return {'flows':flows,'packets':self.packets,'unsupportedPackets':self.unsupported,'malformedPackets':self.malformed,
                'droppedFlows':self.droppedFlows,'boundary':[str(n) for n in self.networks]}

def connections(config):
    import psutil
    analyzer=Analyzer(config['cidrs']);rows=[];denied=0
    selected=config.get('pid');raw=psutil.net_connections(kind='inet')
    omitted=0
    for connection in raw:
        if not connection.raddr:continue
        if selected and connection.pid!=selected:continue
        try:name=psutil.Process(connection.pid).name() if connection.pid else 'unattributed'
        except (psutil.Error,OSError):name='unavailable';denied+=1
        model=name.lower() in MODEL_NAMES
        src,dst=connection.laddr.ip,connection.raddr.ip
        if len(rows)>=3000:omitted+=1;continue
        rows.append({'source':src,'destination':dst,'sourcePort':connection.laddr.port,'destinationPort':connection.raddr.port,
                     'pid':connection.pid,'process':name[:100],'status':str(connection.status),
                     'direction':analyzer.direction(src,dst),'modelProcessCandidate':model})
    return {'connections':rows,'totalObserved':len(raw),'processNamesUnavailable':denied,'rowsOmitted':omitted,
            'boundary':config['cidrs'],'visibility':'process connection metadata only; no packet capture'}

def main():
    config=json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
    # No sockets are opened to an external service. Live capture is passive.
    mode=config['mode']
    if mode=='connections':result=connections(config)
    elif mode=='interfaces':
        from scapy.all import get_working_ifaces
        result={'interfaces':[{'id':i.network_name,'name':i.description or i.name} for i in get_working_ifaces()]}
    else:
        from scapy.all import PcapReader,sniff
        analyzer=Analyzer(config['cidrs']);limited=False
        if mode=='pcap':
            start=time.monotonic()
            with PcapReader(config['path']) as reader:
                for packet in reader:
                    if analyzer.packets>=25000 or time.monotonic()-start>60:limited=True;break
                    analyzer.packet(packet)
        elif mode=='capture':
            sniff(iface=config['interface'],prn=analyzer.packet,store=False,timeout=15,count=10000,promisc=False)
            limited=analyzer.packets>=10000
        else:raise ValueError('Unknown packet mode')
        result=analyzer.result();result.update(limited=limited,visibility='sampled packet metadata and selected protocol indicators; no payload retained')
    Path(config['output']).write_text(json.dumps(result),encoding='utf-8')

if __name__=='__main__':main()
