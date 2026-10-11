"""In-memory usage telemetry for calls actually observed by the local gateway."""
from collections import deque
import math
import threading
import time

_lock=threading.Lock();_enabled=False;_rows=deque(maxlen=2000);_started=0

def enable(value):
    global _enabled,_started
    with _lock:
        _enabled=value
        if value:_rows.clear();_started=time.time()

def number(value):
    return value if isinstance(value,(int,float)) and not isinstance(value,bool) and math.isfinite(value) and value>=0 else None

def record(model,provider,route,status,seconds,result=None):
    if not _enabled:return
    result=result or {};usage=result.get('usage') or {}
    if provider=='ollama':
        prompt=number(result.get('prompt_eval_count'));output=number(result.get('eval_count'));duration=number(result.get('eval_duration'))
        speed=output/(duration/1e9) if output is not None and duration else None
    else:prompt=number(usage.get('prompt_tokens'));output=number(usage.get('completion_tokens'));speed=None
    row={'time':time.time(),'model':str(model)[:200],'provider':provider,'route':str(route)[:100],'status':status,
         'latencyMs':round(seconds*1000,1),'inputTokens':prompt,'outputTokens':output,'generationTokensPerSecond':speed}
    with _lock:_rows.append(row)

def snapshot():
    now=time.time()
    with _lock:rows=list(_rows);enabled=_enabled;started=_started
    recent=[r for r in rows if r['time']>=now-60];models=[]
    for identity in sorted({(r['route'],r['model'],r['provider']) for r in rows}):
        selected=[r for r in rows if (r['route'],r['model'],r['provider'])==identity];last=selected[-1]
        models.append({'route':identity[0],'model':identity[1],'provider':identity[2],'requests':len(selected),
                       'inputTokens':sum(r['inputTokens'] or 0 for r in selected),'outputTokens':sum(r['outputTokens'] or 0 for r in selected),
                       'usageKnownRequests':sum(r['outputTokens'] is not None for r in selected),
                       'lastLatencyMs':last['latencyMs'],'lastGenerationTokensPerSecond':last['generationTokensPerSecond']})
    latencies=sorted(r['latencyMs'] for r in recent)
    known=[r for r in recent if r['outputTokens'] is not None]
    return {'enabled':enabled,'source':'Observed local gateway calls only','retainedRequests':len(rows),'windowSeconds':min(60,max(0,now-started)) if started else 0,
            'requestsLastMinute':len(recent),'errorsLastMinute':sum(r['status']!='success' for r in recent),
            'outputTokensLastMinute':sum(r['outputTokens'] for r in known) if known else None,
            'meanLatencyMs':round(sum(latencies)/len(latencies),1) if latencies else None,
            'p95LatencyMs':latencies[max(0,math.ceil(len(latencies)*.95)-1)] if latencies else None,
            'models':models[:200],'limits':'Last 2,000 requests since monitor start. Missing usage remains unknown. No prompt, response, token estimate or inferred cost retained; TTFT unavailable for buffered calls.'}
