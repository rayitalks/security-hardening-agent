"""Opt-in local enforcement for routed model calls, MCP calls and agent preflight checks."""
from collections import defaultdict, deque
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
import re
import secrets
import threading
import time
from urllib.parse import urlsplit
import asset_registry
import engine
import guardrails
import mcp_security
import security_store as store
import audit_trail
import defense_ops
import inference_metrics

PORT=8766
_server=None
_lock=threading.RLock()
_rates=defaultdict(deque)
_counts=defaultdict(int)
_slots=threading.BoundedSemaphore(8)

def status():
    return {'running':_server is not None,'url':f'http://127.0.0.1:{PORT}',
            'enforcementPoints':['model input','model output','MCP arguments','MCP results','agent preflight'],
            'limitations':['Only traffic routed through this gateway is enforced. Direct access bypasses controls.',
                            'Text detectors are heuristic and can miss semantic or encoded harm. No TLS interception.',
                            'Model calls are buffered, non-streaming chat completions. MCP is a bounded HTTP tool proxy; no stdio launch, resources, prompts, sampling or resumable SSE.',
                            'Agent preflight returns a decision; an external agent must honor it. Tool calls through the MCP gateway are actively blocked before forwarding.',
                            'Budgets are shared per route and reset when the gateway is restarted.']}

def routes():
    return [{k:v for k,v in r.items() if k!='tokenHash'} for r in store.all_items('routes')]

def save_route(config):
    asset=store.get('assets',config.get('assetId'))
    if not asset:raise ValueError('Select a registered asset.')
    if asset['kind'] not in ('model','mcp','agent'):raise ValueError('Choose a model, MCP, or agent asset.')
    kind=asset['kind']
    upstream=config.get('upstream',asset['target'])
    provider=config.get('provider',asset.get('transport','ollama'))
    if kind!='agent':
        engine.validate_target(upstream)
        if urlsplit(upstream).port==PORT:raise ValueError('The upstream cannot be this gateway.')
        if kind=='model':engine.inference_providers.profile(provider)
        if kind=='model' and not asset.get('model'):raise ValueError('Register a specific model identity first.')
    keyenv=config.get('keyEnv','')
    if keyenv and (not isinstance(keyenv,str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,79}',keyenv)):raise ValueError('Use an environment variable name, not a credential value.')
    if keyenv and kind!='agent' and urlsplit(upstream).scheme!='https' and urlsplit(upstream).hostname not in ('127.0.0.1','localhost','::1'):
        raise ValueError('Credentials sent to remote upstreams require HTTPS.')
    if config.get('authorized') is not True:raise ValueError('Confirm authorization to route calls to this upstream.')
    identity=asset['id'];token=secrets.token_urlsafe(32)
    route={'id':identity,'assetId':asset['id'],'kind':kind,'upstream':upstream if kind!='agent' else '',
           'provider':provider if kind=='model' else '', 'keyEnv':keyenv,'enabled':True,
           'tokenHash':hashlib.sha256(token.encode()).hexdigest(),'tokenExpires':time.time()+3600}
    store.put('routes',route)
    return {'route':{k:v for k,v in route.items() if k!='tokenHash'},'token':token,
            'clientUrl':f'http://127.0.0.1:{PORT}/{kind}/{identity}'+('/v1' if kind=='model' else ''),
            'message':'Save this client token securely; only its hash is persisted. Recreating this route rotates the token.'}

def toggle_route(config):
    route=store.get('routes',config.get('routeId'))
    if not route or not isinstance(config.get('enabled'),bool):raise ValueError('Choose a route and enabled true/false.')
    route['enabled']=config['enabled'];store.put('routes',route)
    return {'ok':True}

def reserve(route,selected):
    with _lock:
        now=time.monotonic();rate=_rates[route['id']]
        while rate and rate[0]<now-60:rate.popleft()
        if len(rate)>=selected['requestsPerMinute']:return 'rate-limit'
        if _counts[route['id']]>=selected['maxSessionActions']:return 'gateway-session-budget'
        rate.append(now);_counts[route['id']]+=1
    return None

class GatewayServer(ThreadingHTTPServer):
    daemon_threads=True
    def process_request(self,request,address):
        if not _slots.acquire(blocking=False):
            request.close();return
        try:super().process_request(request,address)
        except BaseException:_slots.release();raise
    def process_request_thread(self,*args):
        try:super().process_request_thread(*args)
        finally:_slots.release()

class Handler(BaseHTTPRequestHandler):
    def setup(self):super().setup();self.connection.settimeout(20)
    def log_message(self,*args):pass
    def respond(self,code,data):
        raw=json.dumps(data,allow_nan=False).encode()
        if getattr(self,'auditAgent',None):
            try:audit_trail.append(self.auditAgent,'gateway-response',str(code),data,self.trace)
            except Exception:
                code=503;raw=json.dumps({'error':'Audit unavailable. Result withheld.'}).encode()
        self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff')
        if getattr(self,'trace',None):self.send_header('X-Trace-ID',self.trace)
        self.end_headers();self.wfile.write(raw)
    def identity(self):
        if self.headers.get('Host')!=f'127.0.0.1:{self.server.server_port}':raise PermissionError('Invalid gateway Host.')
        if self.headers.get('Origin') not in (None,f'http://127.0.0.1:{self.server.server_port}','http://127.0.0.1:8765'):raise PermissionError('Untrusted Origin.')
        bits=self.path.split('/')
        if len(bits)<3 or bits[1] not in ('model','mcp','agent') or not re.fullmatch(r'[a-f0-9]{24}',bits[2]):raise ValueError('Unknown gateway route.')
        route=store.get('routes',bits[2])
        if not route or not route.get('enabled') or route['kind']!=bits[1]:raise PermissionError('Gateway route is disabled or unknown.')
        token=self.headers.get('Authorization','').removeprefix('Bearer ')
        self.credential=defense_ops.authenticate(route,token)
        asset=store.get('assets',route['assetId'])
        return route,asset,guardrails.policy(asset.get('policyId','default'))
    def do_GET(self):
        try:
            if re.fullmatch(r'/canary/[a-f0-9]{32}',self.path):
                if self.headers.get('Host')!=f'127.0.0.1:{self.server.server_port}':raise PermissionError('Invalid gateway Host.')
                import integrity_monitor
                if integrity_monitor.canary_hit(self.path.rsplit('/',1)[1]):
                    self.send_response(204);self.send_header('Content-Length','0');self.send_header('Cache-Control','no-store');self.end_headers();return
                return self.respond(404,{'error':'Unknown canary.'})
            route,asset,selected=self.identity()
            if route['kind']=='model' and self.path.endswith('/v1/models'):
                return self.respond(200,{'object':'list','data':[{'id':asset['model'],'object':'model','owned_by':'configured-upstream'}]})
            self.respond(405,{'error':'Only JSON POST requests are supported here.'})
        except PermissionError as exc:self.respond(403,{'error':str(exc)})
        except ValueError as exc:self.respond(400,{'error':str(exc)})
    def check(self,route,selected,payload,point,tool=None):
        result=guardrails.inspect(payload,selected,point,tool)
        audit_trail.append(getattr(self,'auditAgent',route['id']),point,result['decision'],payload,getattr(self,'trace',None))
        store.event(route['assetId'],point,result['decision'],result['rules'],len(json.dumps(payload)))
        if result['decision']=='block':raise PermissionError('Blocked by '+', '.join(result['rules']))
        if tool and point.endswith('input'):defense_ops.authorize(route,self.credential,tool,payload,self.trace)
        defense_ops.observe(getattr(self,'auditAgent',route['id']),tool,payload)
        return result
    def do_POST(self):
        route=None
        self.auditAgent=None;self.trace=secrets.token_hex(16)
        incoming=self.headers.get('X-Trace-ID','')
        if re.fullmatch(r'[A-Za-z0-9_-]{8,80}',incoming):self.trace=incoming
        try:
            route,asset,selected=self.identity()
            self.auditAgent=self.credential['agentId']
            length=int(self.headers.get('Content-Length','0'))
            if length<2 or length>200000 or self.headers.get('Transfer-Encoding'):raise ValueError('Expected a JSON body of at most 200 KB.')
            data=json.loads(self.rfile.read(length),parse_constant=lambda _:(_ for _ in ()).throw(ValueError('Non-finite JSON numbers are unsupported.')))
            if not isinstance(data,dict):raise ValueError('Expected a JSON object.')
            audit_trail.append(self.auditAgent,'gateway-request','received',data,self.trace)
            defense_ops.authorize(route,self.credential,None,data,self.trace)
            if self.path==f"/{route['kind']}/{route['id']}/token/rotate":
                old=self.credential
                if not old.get('id'):raise PermissionError('Issue a scoped task token before using automatic rotation.')
                return self.respond(200,defense_ops.mint({'routeId':route['id'],'rotateId':old['id'],'agentId':old['agentId'],'taskId':old['taskId'],'role':old['role'],'sensitivity':old['sensitivity'],'tools':old['tools'],'ttlMinutes':min(60,max(1,int(data.get('ttlMinutes',60))))}))
            if route['kind']=='agent' and self.path==f"/agent/{route['id']}/memory/read":
                defense_ops.authorize(route,self.credential,'memory.read',{},self.trace)
                if 'memory.read' not in selected['allowedTools']:raise PermissionError('Memory access is outside route policy.')
                return self.respond(200,{'memory':defense_ops.memory_read(route['assetId'])})
            limit=reserve(route,selected)
            if limit:
                store.event(asset['id'],'budget','block',[limit]);return self.respond(429,{'error':limit})
            if route['kind']=='model':return self.model(route,asset,selected,data)
            if route['kind']=='mcp':return self.mcp(route,asset,selected,data)
            if self.path!=f"/agent/{route['id']}/check":raise ValueError('Use the agent /check endpoint.')
            tool=data.get('tool')
            if not isinstance(tool,str) or not tool:raise ValueError('Agent preflight requires a tool/action name.')
            result=guardrails.inspect(data.get('arguments',{}),selected,'agent-input',tool)
            if result['decision']!='block':defense_ops.authorize(route,self.credential,tool,data.get('arguments',{}),self.trace)
            defense_ops.observe(self.auditAgent,tool,data.get('arguments',{}))
            store.event(asset['id'],'agent-preflight',result['decision'],result['rules'],length)
            self.respond(200,dict(result,enforcement='Decision only: the caller must honor it. No action executed.'))
        except PermissionError as exc:self.respond(403,{'error':str(exc)})
        except (ValueError,TypeError,KeyError,OverflowError) as exc:
            if route:store.event(route['assetId'],'request','block',['invalid-or-unsupported-request'])
            self.respond(400,{'error':str(exc)[:300]})
        except Exception:
            if route:store.event(route['assetId'],'upstream','error',['upstream-or-enforcement-failure'])
            self.respond(502,{'error':'Upstream or enforcement failure. No uninspected result was forwarded.'})
    def upstream_key(self,route):
        key=os.environ.get(route['keyEnv'],'') if route['keyEnv'] else ''
        if route['keyEnv'] and not key:raise ValueError('Configured upstream credential environment variable is missing.')
        return key
    def model(self,route,asset,selected,data):
        if self.path!=f"/model/{route['id']}/v1/chat/completions":raise ValueError('Use /v1/chat/completions.')
        if data.get('stream') not in (None,False):raise ValueError('Use stream=false; outputs are inspected before release.')
        if data.get('model')!=asset['model']:raise ValueError('Model must match this route asset.')
        messages=data.get('messages')
        if not isinstance(messages,list) or not 1<=len(messages)<=100:raise ValueError('Provide 1–100 text messages.')
        if any(not isinstance(m,dict) or m.get('role') not in ('system','user','assistant','tool') or not isinstance(m.get('content'),str) for m in messages):raise ValueError('Only plain text messages are supported.')
        # Clients cannot supply extra transport parameters, tool schemas, URLs, or unreviewed tools.
        if set(data)-{'model','messages','stream','max_tokens','temperature'}:raise ValueError('Unsupported chat options or tool calling; use the MCP gateway for reviewed tools.')
        self.check(route,selected,messages,'model-input')
        defense_ops.authorize(route,self.credential,'model.infer',messages,self.trace)
        capped=data.get('max_tokens',selected['maxOutputTokens'])
        if isinstance(capped,bool) or not isinstance(capped,int) or capped<1:raise ValueError('max_tokens must be a positive integer.')
        capped=min(capped,selected['maxOutputTokens'])
        temperature=data.get('temperature',0)
        if isinstance(temperature,bool) or not isinstance(temperature,(float,int)) or not math.isfinite(temperature) or not 0<=temperature<=2:raise ValueError('temperature must be between 0 and 2.')
        upstream=engine.validate_target(route['upstream']);_,path=engine.api_paths(route['provider'],upstream)
        body={'model':asset['model'],'messages':[{'role':'system','content':selected['systemInstruction']}]+messages,'stream':False}
        if route['provider']=='ollama':body.update(think=False,options={'num_predict':capped,'temperature':temperature})
        else:body.update(max_tokens=capped,temperature=temperature)
        started=time.monotonic()
        code,result=engine.request(upstream,path,self.upstream_key(route),body,timeout=45)
        inference_metrics.record(asset['model'],route['provider'],route['id'],'success' if code==200 else 'error',time.monotonic()-started,result if isinstance(result,dict) else None)
        if isinstance(result,dict):
            usage=result.get('usage') or {};inp=result.get('prompt_eval_count') if route['provider']=='ollama' else usage.get('prompt_tokens');out=result.get('eval_count') if route['provider']=='ollama' else usage.get('completion_tokens')
            context=store.get('context-policy',route['id']) or {}
            known=all(isinstance(x,int) and not isinstance(x,bool) and x>=0 for x in (inp,out))
            cost=(inp*context.get('inputPrice',0)+out*context.get('outputPrice',0))/1e6 if known and context.get('inputPrice',0)+context.get('outputPrice',0)>0 else None
            defense_ops.observe(self.auditAgent,'model.infer',{}, {'tokens':inp+out if known else None,'cost':cost})
        if code!=200:raise RuntimeError('upstream request failed')
        if route['provider']=='ollama':message=result.get('message')
        else:
            choices=result.get('choices')
            if not isinstance(choices,list) or len(choices)!=1:raise ValueError('Upstream must return one chat completion.')
            message=choices[0].get('message')
        if not isinstance(message,dict) or not isinstance(message.get('content'),str) or message.get('tool_calls') or message.get('function_call'):raise ValueError('Upstream returned unsupported content or a tool call.')
        self.check(route,selected,message['content'],'model-output')
        # Reconstruct the response: never pass through hidden reasoning, raw errors or uninspected fields.
        self.respond(200,{'id':'sha-'+secrets.token_hex(8),'object':'chat.completion','created':int(time.time()),'model':asset['model'],
                          'choices':[{'index':0,'message':{'role':'assistant','content':message['content']},'finish_reason':'stop'}]})
    def mcp(self,route,asset,selected,data):
        if self.path!=f"/mcp/{route['id']}":raise ValueError('Use the configured MCP URL exactly.')
        if data.get('jsonrpc')!='2.0' or not isinstance(data.get('method'),str):raise ValueError('Expected a JSON-RPC request.')
        method=data['method'];identity=data.get('id');params=data.get('params',{})
        if method=='initialize':
            return self.respond(200,{'jsonrpc':'2.0','id':identity,'result':{'protocolVersion':'2025-06-18','capabilities':{'tools':{}},'serverInfo':{'name':'Ray-i protected tool gateway','version':'2.0.0'}}})
        if method=='notifications/initialized':
            self.send_response(202);self.send_header('Content-Length','0');self.end_headers();return
        if method=='ping':return self.respond(200,{'jsonrpc':'2.0','id':identity,'result':{}})
        if method not in ('tools/list','tools/call'):raise ValueError('Only reviewed MCP tool operations are supported.')
        client=mcp_security.Client(route['upstream'],self.upstream_key(route));client.initialize();tools=client.tools()
        pins=asset.get('toolPins',{})
        approved=[t for t in tools if t['name'] in selected['allowedTools'] and pins.get(t['name'])==mcp_security.digest(t)]
        if method=='tools/list':
            # Scan each returned descriptor, including its descriptions and schema defaults.
            for tool in approved:self.check(route,selected,tool,'mcp-output')
            return self.respond(200,{'jsonrpc':'2.0','id':identity,'result':{'tools':approved}})
        if not isinstance(params,dict):raise ValueError('Expected MCP params object.')
        name=params.get('name')
        chosen=next((t for t in approved if t['name']==name),None)
        if not chosen:
            store.event(asset['id'],'mcp-input','block',['tool-not-allowed-or-descriptor-changed'])
            raise PermissionError('Tool is not approved, unscanned, or its descriptor changed. Review and rescan before allowing it.')
        args=params.get('arguments',{})
        self.check(route,selected,args,'mcp-input',name)
        mcp_security.validate_arguments(args,chosen.get('inputSchema',{}))
        result=client.rpc('tools/call',{'name':name,'arguments':args})
        # Inspection after execution cannot undo an upstream tool's side effects.
        self.check(route,selected,result,'mcp-output')
        self.respond(200,{'jsonrpc':'2.0','id':identity,'result':result})

def start():
    global _server
    with _lock:
        if _server:return status()
        server=GatewayServer(('0.0.0.0' if os.environ.get('SHA_CONTAINER')=='1' else '127.0.0.1',PORT),Handler)
        _rates.clear();_counts.clear();_server=server
        threading.Thread(target=server.serve_forever,daemon=True).start()
    return status()

def stop():
    global _server
    with _lock:server=_server;_server=None
    if server:server.shutdown();server.server_close()
    return status()
