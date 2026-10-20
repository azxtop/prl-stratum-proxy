"""SOCKS5/TLS PRL test proxy. Identify each authorization; preserve proofs."""
import asyncio,json,ssl,socket,time,hashlib,contextlib
from pathlib import Path
from prl_proxy.tls_stream import TLSStream
LIMIT=32*1024*1024
class Proxy:
 def __init__(self,run,config):
  self.run=Path(run);self.config=config;self.serial=0;self.active={};self.pending={};self.errors=0;self.uncovered_prl=0
  self.counts={r:dict(authorizations=0,authorized=0,submitted=0,accepted=0,rejected=0,unanswered=0,accepted_work=0,last_accepted=None) for r in ('main','dev','unknown')}
  self.client_tls=ssl.create_default_context()
  self.insecure_tls=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);self.insecure_tls.check_hostname=False;self.insecure_tls.verify_mode=ssl.CERT_NONE
  self.server_tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);self.server_tls.load_cert_chain(self.config['certificate'],self.config['key'])
 def event(self,kind,**kw):
  with (self.run/'proxy-events.jsonl').open('a') as f:f.write(json.dumps(dict(time=time.time(),event=kind,**kw))+'\n')
 def classify(self,msg):
  p=msg.get('params')
  if msg.get('method')!='mining.authorize' or not isinstance(p,dict):return 'unknown'
  wallet=p.get('wallet','')
  if wallet==self.config['account']:return 'main'
  if isinstance(wallet,str) and wallet.startswith('prl1') and str(p.get('agent','')).startswith('SRBMiner-MULTI/3.7.8') and p.get('type')=='v2':return 'dev'
  return 'unknown'
 async def connect(self,host,port,tls,verify_tls=True):
  return await asyncio.wait_for(asyncio.open_connection(host,port,limit=LIMIT,**(dict(ssl=self.client_tls if verify_tls else self.insecure_tls,server_hostname=host) if tls else {})),15)
 async def fish(self):
  errors=[]
  for p in self.config['pools']:
   try:
    if not p.get('verify_tls',True):self.event('upstream_tls_verification_disabled',host=p['host'],port=p['port'])
    return await self.connect(p['host'],p['port'],True,p.get('verify_tls',True))
   except (OSError,asyncio.TimeoutError) as e:errors.append(repr(e));self.event('upstream_connect_error',host=p['host'],port=p['port'],error=repr(e))
  raise ConnectionError('All configured PRL relays failed: '+str(errors))
 async def raw(self,reader,writer,first=b''):
  if first:writer.write(first);await writer.drain()
  while True:
   data=await reader.read(65536)
   if not data:return
   writer.write(data);await writer.drain()
 async def client(self,reader,writer,cid,state,first):
  line=first
  while line:
   msg=json.loads(line);method=msg.get('method');rid=msg.get('id');p=msg.get('params');role=state['role']
   if method=='mining.authorize':
    role=self.classify(msg)
    if role in ('main','dev') and not state['fish']:
     self.uncovered_prl+=1;self.event('uncovered_prl_authorization',connection=cid,role=role,method=method);raise ValueError('PRL authorization discovered after routing unknown protocol')
    if role=='unknown' and isinstance(p,dict) and str(p.get('wallet','')).startswith('prl1'):
     self.uncovered_prl+=1;self.event('unrecognized_prl_authorization',connection=cid,params_keys=list(p));raise ValueError('Unverified PRL authorization schema')
    old=p.get('wallet') if isinstance(p,dict) else None
    if role=='dev':
     p['wallet']=self.config['account'];p['worker']=self.config['fee_worker']
     self.event('developer_authorization_rewritten',connection=cid,request_id=rid,original_wallet=old,mixed_wallet='+' in old,wallet=p['wallet'],worker=p['worker'])
    self.counts[role]['authorizations']+=1;state['auth_pending'][rid]=role;state['auth_ok']=False;state['role']=role
    self.event('authorization_sent',connection=cid,role=role,request_id=rid,wallet=p.get('wallet') if isinstance(p,dict) else None,worker=p.get('worker') if isinstance(p,dict) else None)
   elif method=='mining.submit' and role in ('main','dev'):
    if not state['auth_ok']:raise ValueError('Submit before real authorization acknowledgement')
    if rid in self.pending[cid]:raise ValueError('Duplicate in-flight submit request id')
    proof_key=next((k for k in ('plain_proof','proof') if isinstance(p,dict) and isinstance(p.get(k),str)),None)
    if not isinstance(p,dict) or not isinstance(p.get('job_id'),str) or proof_key is None:
     self.event('unsupported_submit_schema',connection=cid,params_keys=list(p) if isinstance(p,dict) else None)
     raise ValueError('Unverified PRL submit schema')
    digest=hashlib.sha256(p[proof_key].encode()).hexdigest();job=p['job_id'];target=state['targets'].get(job)
    pow_params={k:v for k,v in p.items() if k not in ('wallet','worker')}
    if role=='dev':
     if 'wallet' in p:p['wallet']=self.config['account']
     if 'worker' in p:p['worker']=self.config['fee_worker']
    assert hashlib.sha256(p[proof_key].encode()).hexdigest()==digest and {k:v for k,v in p.items() if k not in ('wallet','worker')}==pow_params
    info=dict(role=role,job_id=job,target=target,proof_key=proof_key,proof_sha256=digest,submitted_at=time.time());self.pending[cid][rid]=info;self.counts[role]['submitted']+=1
    self.event('submit_forwarded',connection=cid,request_id=rid,**info)
   elif method=='mining.submit':self.event('unknown_submit_forwarded',connection=cid,request_id=rid)
   writer.write(json.dumps(msg,separators=(',',':')).encode()+b'\n');await writer.drain();line=await reader.readline()
 async def server(self,reader,writer,cid,state):
  while True:
   line=await reader.readline()
   if not line:return
   msg=json.loads(line);rid=msg.get('id')
   if msg.get('method')=='mining.notify' and isinstance(msg.get('params'),dict):
    p=msg['params'];state['targets'][p.get('job_id')]=p.get('target');self.event('job',connection=cid,role=state['role'],job_id=p.get('job_id'),target=p.get('target'),height=p.get('height'))
    if len(state['targets'])>4096:state['targets'].pop(next(iter(state['targets'])))
   if rid in self.pending[cid] and ('result' in msg or 'error' in msg):
    info=self.pending[cid].pop(rid);accepted=msg.get('result') is True and msg.get('error') is None;role=info['role'];self.counts[role]['accepted' if accepted else 'rejected']+=1
    if accepted:
     self.counts[role]['last_accepted']=time.time()
     if info['target']:
      try:self.counts[role]['accepted_work']+=2**256/(int(info['target'],16)+1)
      except (ValueError,TypeError):pass
    self.event('submit_reply',connection=cid,request_id=rid,accepted=accepted,result=msg.get('result'),error=msg.get('error'),**info)
   elif rid in state['auth_pending'] and ('result' in msg or 'error' in msg):
    role=state['auth_pending'].pop(rid);okay=msg.get('result') is True and msg.get('error') is None;state['auth_ok']=okay
    if okay:self.counts[role]['authorized']+=1
    self.event('authorization_reply',connection=cid,role=role,request_id=rid,accepted=okay,result=msg.get('result'),error=msg.get('error'))
   writer.write(line);await writer.drain()
 def snapshot(self):
  out={k:dict(v,pending=0) for k,v in self.counts.items()}
  for pending in self.pending.values():
   for x in pending.values():out[x['role']]['pending']+=1
  return dict(roles=out,connections=self.active,errors=self.errors,uncovered_prl=self.uncovered_prl)
 async def handle(self,reader,writer):
  self.serial+=1;cid=self.serial;up=None;tasks=[];self.pending[cid]={};state=dict(role='unknown',auth_ok=False,auth_pending={},targets={},fish=False)
  try:
   version,n=await asyncio.wait_for(reader.readexactly(2),10);methods=await reader.readexactly(n)
   if version!=5 or 0 not in methods:raise ValueError('Unsupported SOCKS authentication')
   writer.write(b'\x05\x00');await writer.drain();version,cmd,_,typ=await reader.readexactly(4)
   if version!=5 or cmd!=1:raise ValueError('Only SOCKS CONNECT is supported')
   if typ==3:host=(await reader.readexactly((await reader.readexactly(1))[0])).decode('ascii')
   elif typ==1:host=socket.inet_ntop(socket.AF_INET,await reader.readexactly(4))
   elif typ==4:host=socket.inet_ntop(socket.AF_INET6,await reader.readexactly(16))
   else:raise ValueError('Unsupported address family')
   port=int.from_bytes(await reader.readexactly(2),'big');self.event('connect_requested',connection=cid,host=host,port=port)
   self.active[cid]=dict(host=host,port=port,role='unknown')
   writer.write(b'\x05\x00\x00\x01'+b'\0'*6);await writer.drain()
   prefix=await asyncio.wait_for(reader.readexactly(1),15);client_tls=prefix==b'\x16'
   if client_tls:
    tls=TLSStream(reader,writer,self.server_tls);tls.incoming.write(prefix);await asyncio.wait_for(tls.handshake(),15);reader=writer=tls
    self.event('client_tls_ready',connection=cid,version=tls.ssl.version(),cipher=tls.ssl.cipher());prefix=await asyncio.wait_for(reader.read(1),15)
   if prefix in (b'{',b'['):
    first=prefix+await asyncio.wait_for(reader.readline(),15)
    try:msg=json.loads(first);role=self.classify(msg)
    except (ValueError,AttributeError):msg=None;role='unknown'
    if role in ('main','dev'):
     r,up=await self.fish();state['fish']=True;state['role']=role;self.active[cid]['role']=role
    else:
     r,up=await self.connect(host,port,client_tls);self.event('unknown_protocol_passthrough',connection=cid,host=host,port=port,client_tls=client_tls,first_bytes=first[:256].decode(errors='replace'))
    if msg is not None:
     tasks=[asyncio.create_task(self.client(reader,up,cid,state,first)),asyncio.create_task(self.server(r,writer,cid,state))]
    else:tasks=[asyncio.create_task(self.raw(reader,up,first)),asyncio.create_task(self.raw(r,writer))]
   else:
    r,up=await self.connect(host,port,client_tls);self.event('unknown_binary_passthrough',connection=cid,host=host,port=port,client_tls=client_tls,prefix=prefix.hex())
    tasks=[asyncio.create_task(self.raw(reader,up,prefix)),asyncio.create_task(self.raw(r,writer))]
   done,_=await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)
   for task in done:task.result()
  except asyncio.CancelledError:raise
  except Exception as e:
   self.errors+=1;self.event('connection_error',connection=cid,error=repr(e))
  finally:
   for task in tasks:task.cancel()
   await asyncio.gather(*tasks,return_exceptions=True)
   for rid,info in self.pending.pop(cid,{}).items():self.counts[info['role']]['unanswered']+=1;self.event('submit_unanswered',connection=cid,request_id=rid,**info)
   self.active.pop(cid,None)
   for w in (writer,up):
    if w:
     with contextlib.suppress(Exception):w.close();await w.wait_closed()
   self.event('connection_closed',connection=cid)
