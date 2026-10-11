"""Small local gateway client with automatic scoped-token rotation. No token persistence."""
import json
import threading
import time
from urllib import request,error
from urllib.parse import urlsplit

class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None
class GatewayClient:
    def __init__(self,route_url,issued):
        parsed=urlsplit(route_url)
        if parsed.scheme!='http' or parsed.hostname!='127.0.0.1' or parsed.username or parsed.query or parsed.fragment:raise ValueError('Use the loopback gateway route URL.')
        self.url=route_url.rstrip('/');self.token=issued['token'];self.expires=issued['credential']['expires'];self.lock=threading.RLock()
    def _post(self,path,payload,trace_id=None):
        headers={'Content-Type':'application/json','Authorization':'Bearer '+self.token}
        if trace_id:headers['X-Trace-ID']=trace_id
        opener=request.build_opener(request.ProxyHandler({}),NoRedirect())
        try:
            with opener.open(request.Request(self.url+path,data=json.dumps(payload).encode(),headers=headers),timeout=60) as r:
                data=r.read(2_000_001)
                if len(data)>2_000_000:raise ValueError('Gateway response too large.')
                return json.loads(data)
        except error.HTTPError as exc:
            code=exc.code;exc.close();raise RuntimeError('Gateway denied or failed the request (HTTP '+str(code)+'). Review the console; no action is automatically retried.') from None
    def post(self,path,payload,trace_id=None):
        if not path.startswith('/') or '..' in path or '?' in path or '#' in path:raise ValueError('Use a route-relative operation path.')
        with self.lock:
            if time.time()>=self.expires:raise PermissionError('Task credential expired; obtain a new authorized credential.')
            if self.expires-time.time()<300:
                issued=self._post('/token/rotate',{'ttlMinutes':60},trace_id);self.token=issued['token'];self.expires=issued['credential']['expires']
            return self._post(path,payload,trace_id)
