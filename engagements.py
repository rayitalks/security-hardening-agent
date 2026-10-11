"""Locally signed, expiring, exact endpoint/model testing scopes."""
import hmac
import secrets
import time
import engine
import audit_trail as audit
import security_store as store

def create(config):
    if config.get('authorized') is not True:raise ValueError('Confirm authority for this exact endpoint and model.')
    url=engine.validate_target(config.get('url','')).rstrip('/');model=config.get('model','')
    if not isinstance(model,str) or not model.strip() or len(model)>200:raise ValueError('Select the exact model identity.')
    environment=config.get('environment','sandbox')
    if environment not in ('sandbox','production'):raise ValueError('Choose sandbox or production.')
    hours=int(config.get('hours',4))
    if not 1<=hours<=168:raise ValueError('Engagement expiry must be 1–168 hours.')
    value={'id':secrets.token_hex(12),'url':url,'model':model,'environment':environment,'expires':time.time()+hours*3600,
           'mode':'synthetic-intercepted-tools','approved':environment=='sandbox','version':1}
    value['signature']=audit.sign({'engagement':value});store.put('engagements',value)
    audit.append('console','engagement-created','pending' if environment=='production' else 'allowed',value)
    return value
def signed(value):return {k:v for k,v in value.items() if k not in ('signature','updatedAt')}
def approve(config):
    row=store.get('engagements',config.get('id'))
    if not row or config.get('confirmation')!='APPROVE SYNTHETIC PRODUCTION TEST':raise ValueError('Review the production target and type APPROVE SYNTHETIC PRODUCTION TEST.')
    if not hmac.compare_digest(row['signature'],audit.sign({'engagement':signed(row)})):raise ValueError('Invalid engagement signature.')
    row=signed(row);row['approved']=True;row['signature']=audit.sign({'engagement':row});store.put('engagements',row)
    audit.append('console','production-test-approval','approved',row)
    return row
def require(config):
    row=store.get('engagements',config.get('engagementId'))
    if not row or not hmac.compare_digest(row['signature'],audit.sign({'engagement':signed(row)})):raise ValueError('Select a valid signed engagement.')
    if row['expires']<=time.time() or not row['approved']:raise ValueError('Engagement expired or requires production sign-off.')
    if row['url']!=engine.validate_target(config.get('url','')).rstrip('/') or row['model']!=config.get('model'):raise ValueError('Endpoint/model is outside the signed engagement allowlist.')
    return row
