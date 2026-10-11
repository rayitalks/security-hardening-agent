"""AI egress indicators, captured packets and process connections."""
import ipaddress
import os
import threading

import containers
import engine
import model_tools

DEFAULT_CIDRS=['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.0/8','::1/128','fc00::/7','fe80::/10','169.254.0.0/16']

def networks(value):
    if not value:return DEFAULT_CIDRS
    if not isinstance(value,str) or len(value)>2000:raise ValueError('Enter trusted network ranges separated by commas.')
    values=[x.strip() for x in value.split(',') if x.strip()]
    if not values or len(values)>32:raise ValueError('Choose 1–32 trusted network ranges.')
    try:return [str(ipaddress.ip_network(x,strict=False)) for x in values]
    except ValueError:raise ValueError('A trusted network range is not valid CIDR notation.')

def interfaces():
    return model_tools.worker('packet_worker.py',{'mode':'interfaces'},threading.Event(),30)

def assess(config,progress,stop):
    mode=config.get('mode','connections')
    if mode not in ('connections','pcap','capture'):raise ValueError('Select a supported traffic analysis mode.')
    request={'mode':mode,'cidrs':networks(config.get('cidrs'))}
    target='This runtime: current network connections'
    if mode=='pcap':
        path=model_tools.target(config.get('path',''))
        if not path.is_file() or path.stat().st_size>256*1024*1024:raise ValueError('Choose a PCAP/PCAPNG file no larger than 256 MB.')
        request['path']=str(path);target=str(path)
    if mode=='connections' and config.get('pid'):
        try:request['pid']=int(config['pid'])
        except (ValueError,TypeError):raise ValueError('Process ID must be a positive whole number.')
        if request['pid']<1:raise ValueError('Process ID must be a positive whole number.')
    if mode=='capture':
        if config.get('authorized') is not True:raise ValueError('Confirm authorization to capture this interface.')
        chosen=config.get('interface')
        if chosen not in [x['id'] for x in interfaces()['interfaces']]:raise ValueError('Select a currently available capture interface.')
        request['interface']=chosen;target='15-second passive capture: '+chosen
    progress('Reading local connection metadata…' if mode=='connections' else 'Analyzing packets locally; payloads are not retained…')
    data=model_tools.worker('packet_worker.py',request,stop,90)
    findings=[]
    rows=data.get('connections',[]) if mode=='connections' else data.get('flows',[])
    candidates=0;outbound=0
    for row in rows:
        if row['direction']!='outbound':continue
        outbound+=1
        candidate=row.get('modelProcessCandidate') or bool(row.get('hints'))
        if candidate:candidates+=1
        if not candidate:continue
        reason=(', '.join(row.get('hints',[])) if mode!='connections' else 'Process name resembles a model server; attribution is not definitive.')
        findings.append(engine.finding('AI egress indicator across selected boundary','review',
            f"{row['source']} → {row['destination']}:{row['destinationPort']}. {reason}",
            'Confirm destination ownership and purpose, correlate process/proxy/firewall logs, and apply a specific outbound policy if needed. This observation alone is not proof of model or data exfiltration.',
            'AI traffic / egress'))
    if not candidates:
        findings.append(engine.finding('No AI egress indicators in this observation','unknown','No configured AI indicators matched outbound rows in this sample. Other protocols, encrypted connections and unseen interfaces remain unclassified.','Capture at the relevant interface or gateway and correlate the model process and firewall logs.','AI traffic / egress'))
    incomplete=bool(data.get('limited') or data.get('unsupportedPackets') or data.get('malformedPackets') or data.get('droppedFlows') or data.get('rowsOmitted'))
    if mode!='connections' and data.get('packets',0)==0:incomplete=True
    if incomplete:
        findings.append(engine.finding('Traffic sample coverage incomplete','unknown','The observation was empty or reached a packet, format, time or flow limit.','Use a smaller supported capture and inspect gaps before drawing a conclusion.','Packet coverage'))
    findings.append(engine.finding('Firewall crossing and encrypted contents are unverified','unknown',
        'Boundary classification uses the trusted ranges you supplied. It does not read firewall decisions, decrypt TLS/QUIC, or establish what an encrypted packet contains.',
        'Correlate an authorized gateway capture and firewall/proxy logs. Use application-side audit metadata for encrypted requests.','AI traffic / egress'))
    return {'schema':'sha-report-v1','type':'AI packet & protocol analysis','createdAt':containers.now(),'target':target,
        'status':'cancelled' if stop.is_set() else ('partial' if incomplete else 'complete'),'findings':findings,
        'coverage':{'mode':mode,'rows':len(rows),'outboundRows':outbound,'aiIndicatorRows':candidates,'packets':data.get('packets'),
                    'limited':incomplete,'firewallVerified':False,'encryptedContentVisible':False},
        'trafficAssessment':dict(data,mode=mode),
        'limitations':['No single capture can identify every AI packet or confirm model weights crossing a firewall. Encryption, tunnels, alternate endpoints, sampling, NAT and sensor position leave blind spots.',
            'Outbound means source inside your selected trusted CIDRs and destination outside. Defaults are private/link-local/loopback ranges; customize for your network. This is not the effective firewall policy.',
            'AI API-shaped HTTP paths, known-provider DNS/TLS SNI, common inference ports and process names are indicators, not proof of AI content or data loss.',
            'No prompts, authorization headers, packet payloads, DNS queries for other domains, file contents or TLS keys are retained. IP addresses and process names remain sensitive report metadata.',
            'No TCP stream reassembly, TLS decryption, QUIC decryption, protocol tunneling detection or exhaustive domain inventory. Fragmented/split headers may be missed.',
            'PCAP/PCAPNG: 256 MB input, 25,000 packets, 3,000 flows, 60 seconds. Passive capture: one interface, 15 seconds, 10,000 packets, no promiscuous mode.',
            'Live capture needs existing OS capture permissions/driver (Npcap on Windows). The app does not install drivers or elevate itself. Connection metadata may require additional permissions on some systems.',
            'Docker sees its own network namespace. Import captures from the model host/gateway for host-level visibility; no privileged container or Docker socket is added by default.']}
