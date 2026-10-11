"""Bounded MCP HTTP tool discovery and descriptor checks; never invokes tools during scanning."""
import hashlib
import json
import time
import urllib.error
import urllib.request
import engine
import guardrails
import security_store as store

VERSIONS={'2025-03-26','2025-06-18','2025-11-25'}

class Client:
    def __init__(self,url,key=''):
        self.url=engine.validate_target(url)
        if __import__('urllib.parse',fromlist=['urlsplit']).urlsplit(url).port==8766:
            raise ValueError('Choose the upstream MCP server, not the protection gateway.')
        self.key=key;self.session=None;self.version='2025-06-18';self.counter=0
        self.http=urllib.request.build_opener(urllib.request.ProxyHandler({}),engine.NoRedirect())
        if key and self.url.startswith('http://') and __import__('urllib.parse',fromlist=['urlsplit']).urlsplit(url).hostname not in ('127.0.0.1','localhost','::1'):
            raise ValueError('Remote MCP credentials require HTTPS.')

    def rpc(self,method,params=None,notification=False):
        self.counter+=1
        request={'jsonrpc':'2.0','method':method,'params':params or {}}
        if not notification:request['id']=self.counter
        headers={'Content-Type':'application/json','Accept':'application/json, text/event-stream','MCP-Protocol-Version':self.version}
        if self.session:headers['Mcp-Session-Id']=self.session
        if self.key:headers['Authorization']='Bearer '+self.key
        req=urllib.request.Request(self.url,data=json.dumps(request).encode(),headers=headers,method='POST')
        try:
            with self.http.open(req,timeout=15) as response:
                if response.headers.get('Mcp-Session-Id'):self.session=response.headers['Mcp-Session-Id']
                if notification and response.status in (200,202,204):return {}
                if 'text/event-stream' in response.headers.get('Content-Type',''):
                    size=0;parts=[];deadline=time.monotonic()+20
                    while time.monotonic()<deadline:
                        line=response.readline(65537);size+=len(line)
                        if size>2_000_000 or len(line)>65536:raise ValueError('MCP response exceeded the evidence limit.')
                        if not line:break
                        if line.startswith(b'data:'):parts.append(line[5:].strip())
                        elif line.strip()==b'' and parts:
                            item=json.loads(b'\n'.join(parts));parts=[]
                            if item.get('id')==request.get('id'):return self.result(item)
                    raise ValueError('MCP SSE response was incomplete or timed out.')
                raw=response.read(2_000_001)
                if len(raw)>2_000_000:raise ValueError('MCP response exceeds 2 MB.')
                item=json.loads(raw)
                if not isinstance(item,dict) or item.get('id')!=request.get('id'):raise ValueError('MCP response ID did not match.')
                return self.result(item)
        except (urllib.error.URLError,TimeoutError,OSError,json.JSONDecodeError) as exc:
            raise ValueError('MCP request failed, timed out, or returned unsupported data.') from exc

    @staticmethod
    def result(item):
        if 'error' in item:raise ValueError('The MCP server returned a protocol error.')
        if not isinstance(item.get('result'),dict):raise ValueError('MCP result is not an object.')
        return item['result']

    def initialize(self):
        result=self.rpc('initialize',{'protocolVersion':self.version,'capabilities':{},'clientInfo':{'name':'ray-i-security-agent','version':'2.0.0'}})
        if result.get('protocolVersion') not in VERSIONS:raise ValueError('Unsupported MCP protocol version negotiated.')
        self.version=result['protocolVersion']
        self.rpc('notifications/initialized',notification=True)
        return result

    def tools(self):
        result=[];cursor=None;seen=set()
        for _ in range(5):
            data=self.rpc('tools/list',{'cursor':cursor} if cursor else {})
            rows=data.get('tools')
            if not isinstance(rows,list) or any(not isinstance(x,dict) or not isinstance(x.get('name'),str) for x in rows):raise ValueError('Invalid MCP tool inventory.')
            result.extend(rows)
            if len(result)>500:raise ValueError('MCP inventory exceeds 500 tools; coverage incomplete.')
            cursor=data.get('nextCursor')
            if not cursor:
                if len({x['name'] for x in result})!=len(result):raise ValueError('Duplicate MCP tool names were rejected.')
                return result
            if not isinstance(cursor,str) or cursor in seen:raise ValueError('Invalid MCP pagination.')
            seen.add(cursor)
        raise ValueError('MCP inventory exceeds five pages; coverage incomplete.')

def digest(tool):
    # Descriptor change detection includes descriptions and annotations, not only argument shape.
    return hashlib.sha256(json.dumps(tool,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def scan(config,progress,stop):
    if config.get('authorized') is not True:raise ValueError('Confirm authorization to inspect this MCP endpoint.')
    progress('Initializing the selected MCP endpoint and listing tools; no tools are invoked…')
    client=Client(config.get('url',''),config.get('key',''));metadata=client.initialize()
    tools=client.tools();findings=[];pins={}
    for tool in tools:
        if stop.is_set():break
        name=tool['name'][:200];pins[name]=digest(tool)
        description=str(tool.get('description',''))
        verdict=guardrails.inspect(description,guardrails.DEFAULT)
        for rule in verdict['rules']:
            findings.append(engine.finding('MCP descriptor indicator: '+name,'review','Descriptor matched '+rule+'. Matched content omitted.','Review the tool description and implementation before allowing invocation.','MCP supply chain'))
        schema=tool.get('inputSchema')
        if not isinstance(schema,dict) or schema.get('type')!='object':
            findings.append(engine.finding('MCP argument schema: '+name,'unknown','Object input schema is missing or unsupported.','Require a bounded, reviewable argument schema.','MCP supply chain'))
        elif schema.get('additionalProperties') is not False:
            findings.append(engine.finding('Open MCP argument surface: '+name,'review','Additional arguments are not explicitly prohibited by this schema.','Review the argument schema and restrict unnecessary fields.','MCP supply chain'))
        annotations=tool.get('annotations',{})
        if annotations.get('destructiveHint',True) or not annotations.get('readOnlyHint',False):
            findings.append(engine.finding('MCP mutation capability: '+name,'review','Server annotations do not assert a read-only non-destructive tool; annotations are untrusted hints.','Allow only reviewed tools and require application approval for consequential actions.','MCP supply chain'))
    report={'schema':'sha-report-v1','type':'MCP tool assessment','target':client.url,'createdAt':store.now(),'status':'cancelled' if stop.is_set() else 'complete',
            'findings':findings,'mcpAssessment':{'protocolVersion':client.version,'tools':[{'name':t['name'][:200],'descriptorSha256':digest(t)} for t in tools]},
            'coverage':{'toolsInventoried':len(tools),'descriptorsChecked':len(pins),'toolsInvoked':0},
            'limitations':['HTTP tool metadata review only. No tool is invoked and implementation safety is not established. Stdio configurations are discovered without launching them. Descriptor hashes detect changes, not trustworthiness. At most five pages and 500 tools.']}
    asset=store.get('assets',config.get('assetId')) if config.get('assetId') else None
    if asset and asset['kind']=='mcp' and asset['target'].rstrip('/')==client.url.rstrip('/') and report['status']=='complete':
        asset['toolPins']=pins;asset['toolInventoryAt']=store.now();store.put('assets',asset)
    return report

def validate_arguments(value,schema,depth=0):
    """Conservative supported JSON Schema subset; unknown constraints fail closed."""
    if depth>15 or not isinstance(schema,dict):raise ValueError('Unsupported or deeply nested tool schema.')
    supported={'type','properties','required','additionalProperties','items','enum','const','minimum','maximum','minLength','maxLength','minItems','maxItems','description','title','default','$schema','examples'}
    if set(schema)-supported:raise ValueError('Tool schema contains unsupported constraints; invocation blocked.')
    kind=schema.get('type')
    types={'object':dict,'array':list,'string':str,'integer':int,'number':(int,float),'boolean':bool,'null':type(None)}
    if kind not in types or not isinstance(value,types[kind]) or kind in ('integer','number') and isinstance(value,bool):raise ValueError('Tool argument type does not match its schema.')
    if 'enum' in schema and value not in schema['enum']:raise ValueError('Tool argument is outside its enum.')
    if 'const' in schema and value!=schema['const']:raise ValueError('Tool argument does not match its constant.')
    if kind=='object':
        properties=schema.get('properties',{})
        if not isinstance(properties,dict) or any(k not in value for k in schema.get('required',[])):raise ValueError('Required tool argument missing.')
        for k,v in value.items():
            if k in properties:validate_arguments(v,properties[k],depth+1)
            elif schema.get('additionalProperties') is False:raise ValueError('Additional tool argument rejected.')
            elif isinstance(schema.get('additionalProperties'),dict):validate_arguments(v,schema['additionalProperties'],depth+1)
            else:raise ValueError('Unconstrained additional tool arguments are blocked by the gateway.')
    elif kind=='array':
        if not schema.get('minItems',0)<=len(value)<=schema.get('maxItems',1000):raise ValueError('Tool array length exceeded.')
        for v in value:validate_arguments(v,schema.get('items',{}),depth+1)
    elif kind=='string':
        if not schema.get('minLength',0)<=len(value)<=schema.get('maxLength',100000):raise ValueError('Tool string length exceeded.')
    elif kind in ('integer','number'):
        if not schema.get('minimum',-float('inf'))<=value<=schema.get('maximum',float('inf')):raise ValueError('Tool number is outside its bounds.')
