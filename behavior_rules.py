"""Explainable, bounded filesystem and authentication anomaly rules."""
from collections import Counter,deque,OrderedDict
import math
from pathlib import Path
import re
import time

def entropy(data):
    if not data:return 0.0
    size=len(data)
    return round(-sum((n/size)*math.log2(n/size) for n in Counter(data).values()),3)

class Detector:
    def __init__(self,threshold=40,window=20):
        self.threshold=threshold;self.window=window;self.activity=deque(maxlen=20000);self.failures=deque(maxlen=1000)
        self.baseline=deque(maxlen=90);self.cooldowns={};self.seen=OrderedDict()
    def alert(self,key,title,evidence,now,severity='review'):
        if now-self.cooldowns.get(key,-1e20)<60:return None
        self.cooldowns[key]=now
        return {'type':'alert','rule':key,'title':title,'severity':severity,'evidence':evidence,'observedAt':now,
                'meaning':'Behavioral indicator to investigate; it does not establish malware, actor identity or successful compromise.'}
    def ingest_file(self,event,now=None):
        now=time.time() if now is None else now;kind=event['action'];path=event['path'];key=(kind,path)
        if now-self.seen.get(key,-1e20)<.5:return []
        self.seen[key]=now;self.seen.move_to_end(key)
        while len(self.seen)>10000:self.seen.popitem(last=False)
        self.activity.append((now,event))
        while self.activity and self.activity[0][0]<now-self.window:self.activity.popleft()
        alerts=[]
        if Path(path).name.lower() in ('authorized_keys','sshd_config','sudoers') or re.search(r'(?i)(?:^|[/\\])sudoers\.d[/\\]',path):
            alerts.append(self.alert('privileged-config-change','SSH or administrative configuration changed',{'path':path,'action':kind},now))
        events=[e for _,e in self.activity];unique={e['path'] for e in events};renames={e['path'] for e in events if e['action']=='moved'}
        entropy_hits={e['path'] for e in events if (e.get('entropyIncrease') or 0)>=2 and (e.get('entropy') or 0)>=7.3}
        suspicious={e['path'] for e in events if e['path'].lower().endswith(('.locked','.encrypted','.crypt','.ryk','.lockbit'))}
        if len(unique)>=self.threshold:
            alerts.append(self.alert('rapid-file-churn','Rapid changes across many files',{'uniqueFiles':len(unique),'windowSeconds':self.window,'threshold':self.threshold},now))
            if len(entropy_hits)>=5 or len(suspicious)>=5:
                alerts.append(self.alert('encryption-like-burst','Possible mass encryption behavior',{'uniqueFiles':len(unique),'entropyIncreases':len(entropy_hits),'suspiciousExtensions':len(suspicious),'windowSeconds':self.window},now,'attention'))
        if len(renames)>=max(10,self.threshold//2):alerts.append(self.alert('bulk-rename','Bulk file renaming',{'uniqueRenames':len(renames),'windowSeconds':self.window},now))
        return [a for a in alerts if a]
    def interval(self,count,now=None):
        now=time.time() if now is None else now;alert=None
        if len(self.baseline)>=15:
            mean=sum(self.baseline)/len(self.baseline);variance=sum((n-mean)**2 for n in self.baseline)/len(self.baseline)
            limit=max(self.threshold,mean+4*math.sqrt(variance),mean*3)
            if count>limit:alert=self.alert('activity-baseline-deviation','Filesystem activity exceeded its learned baseline',{'currentEvents':count,'baselineMean':round(mean,1),'threshold':round(limit,1),'baselineSamples':len(self.baseline)},now)
        self.baseline.append(count)
        return alert
    def auth(self,event,now=None):
        now=time.time() if now is None else now;alerts=[];kind=event.get('kind')
        if kind in ('privileged-logon','admin-membership-change','explicit-credentials','sudo-request'):
            alerts.append(self.alert('auth-'+kind,'Administrative access activity',{'kind':kind,'source':event.get('source'),'account':event.get('account')},now))
        if kind=='authentication-failure':
            self.failures.append(now)
            while self.failures and self.failures[0]<now-60:self.failures.popleft()
            if len(self.failures)>=5:alerts.append(self.alert('authentication-failure-burst','Repeated authentication failures',{'failures':len(self.failures),'windowSeconds':60,'source':event.get('source')},now,'attention'))
        return [a for a in alerts if a]

def classify_auth(text):
    # Match message classes; callers omit raw messages, command lines and passwords.
    if re.search(r'(?i)failed password|authentication fail|invalid user|failed publickey',text):return 'authentication-failure'
    if re.search(r'(?i)\bsudo\b.*(?:COMMAND=|session opened|authentication)',text):return 'sudo-request'
    if re.search(r'(?i)accepted (?:password|publickey)|session opened for user',text):return 'ssh-or-session-success'
    if re.search(r'(?i)\bsshd\b.*(?:connection|disconnect|preauth)',text):return 'ssh-connection'
    return None
