"""Scoped SOCKS5 routing; real PRL replies correlated by proxy-owned RPC IDs."""
import asyncio, hashlib, ipaddress, json, socket, ssl, time
from collections import OrderedDict

LIMIT=8*1024*1024

class Proxy:
    def __init__(self,c,emit):
        self.c=c;self.emit=emit;self.serial=0;self.tasks=set();self.writers=set();self.identity_errors=0
        self.counts={role:dict(connected=0,authorized=0,submitted=0,accepted=0,rejected=0,unanswered=0,errors=0,pending=0,unknown_target_accepts=0,accepted_work=0.,last_accepted=0.,last_job=0.) for role in ('main','redirect')}
        self.contexts={}
        self.targets=[];self.unknown=[]

    def event(self,kind,**kw):self.emit(kind,**kw)
    def snapshot(self):return {'roles':self.counts,'targets':self.targets,'unknown_connections':self.unknown,'identity_errors':self.identity_errors}
    async def open_pool(self,role,cid):
        last=None
        for pool in self.c['pools']:
            try:
                options={}
                if pool.get('tls',True):
                    key=(pool['host'],pool['port'],pool.get('verify_tls',True))
                    if key not in self.contexts:
                        ctx=ssl.create_default_context()
                        if not pool.get('verify_tls',True):
                            ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
                        self.contexts[key]=ctx
                    options.update(ssl=self.contexts[key],server_hostname=pool['host'])
                r,w=await asyncio.wait_for(asyncio.open_connection(pool['host'],pool['port'],limit=LIMIT,**options),15)
                self.event('pool_connected',role=role,connection=cid,host=pool['host'],port=pool['port'],peer=w.get_extra_info('peername'),local=w.get_extra_info('sockname'));return r,w
            except Exception as e:last=e;self.event('pool_connect_error',role=role,connection=cid,error=repr(e))
        raise ConnectionError('All configured user pool relays failed: '+repr(last))

    async def mining(self,reader,writer,role,ready=None):
        task=asyncio.current_task();self.tasks.add(task);self.writers.add(writer)
        self.serial+=1;cid=self.serial;count=self.counts[role];pending={};jobs=OrderedDict();up=None;pipes=[];sequence=0;authorized=False
        worker=self.c['worker']+ (self.c.get('fee_suffix','dev') if role=='redirect' else '')

        async def outgoing():
            nonlocal sequence
            while line:=await reader.readline():
                msg=json.loads(line);method=msg.get('method');params=msg.get('params');original_id=msg.get('id');info={'method':method,'original_id':original_id,'time':time.time()}
                if method in ('mining.authorize','mining.submit'):
                    if not isinstance(params,dict):self.identity_errors+=1;raise RuntimeError('Unverified PRL parameter schema')
                    if method=='mining.authorize':
                        wallet=params.get('wallet');original_worker=params.get('worker')
                        if not isinstance(wallet,str) or not wallet:self.identity_errors+=1;raise RuntimeError('Missing wallet identity')
                        if role=='redirect':
                            params=dict(params);params.update(wallet=self.c['account'],worker=worker);msg['params']=params
                            self.event('authorize_rewritten',role=role,connection=cid,original_wallet=wallet,original_worker=original_worker,wallet=self.c['account'],worker=worker,params_keys=sorted(params))
                        else:
                            if wallet!=self.c['account'] or original_worker!=worker:self.identity_errors+=1;raise RuntimeError('Unexpected primary mining identity')
                            self.event('authorize_observed',role=role,connection=cid,wallet=wallet,worker=original_worker,params_keys=sorted(params))
                    else:
                        if not authorized:raise RuntimeError('Submit before successful authorization reply')
                        job_id=params.get('job_id')
                        if not isinstance(job_id,str) or not job_id:self.identity_errors+=1;raise RuntimeError('Missing PRL job_id')
                        proof={k:v for k,v in params.items() if k not in ('wallet','worker')}
                        if len(proof)<2:self.identity_errors+=1;raise RuntimeError('No proof-bearing PRL parameter found')
                        digest=hashlib.sha256(json.dumps(proof,sort_keys=True,separators=(',',':')).encode()).hexdigest()
                        if role=='redirect':
                            params=dict(params)
                            if 'wallet' in params:params['wallet']=self.c['account']
                            if 'worker' in params:params['worker']=worker
                            msg['params']=params
                        assert {k:v for k,v in msg['params'].items() if k not in ('wallet','worker')}==proof
                        info.update(job_id=job_id,target=jobs.get(job_id),proof_sha256=digest)
                if original_id is not None:
                    if len(pending)>=4096:raise RuntimeError('Too many pending RPC requests')
                    sequence+=1;msg['id']=sequence;pending[sequence]=info
                if method=='mining.submit':
                    if original_id is None:raise RuntimeError('PRL submission has no request ID')
                    count['submitted']+=1;count['pending']+=1
                    self.event('submit_forwarded',role=role,connection=cid,client_id=original_id,upstream_id=sequence,job_id=info['job_id'],target=info['target'],proof_sha256=info['proof_sha256'],worker=worker,params_keys=sorted(params))
                up.write(json.dumps(msg,separators=(',',':')).encode()+b'\n');await up.drain()

        async def incoming(r):
            nonlocal authorized
            while line:=await r.readline():
                msg=json.loads(line);rid=msg.get('id');method=msg.get('method')
                if method=='mining.notify':
                    p=msg.get('params',{})
                    if isinstance(p,dict):
                        target=p.get('target');jid=p.get('job_id');count['last_job']=time.time()
                        if isinstance(target,str) and len(target)==64:
                            int(target,16);jobs[jid]=target
                            while len(jobs)>2048:jobs.popitem(last=False)
                        self.event('job',role=role,connection=cid,job_id=jid,target=target,height=p.get('height'))
                if rid in pending and ('result' in msg or 'error' in msg):
                    info=pending.pop(rid);ok=msg.get('result') is True and msg.get('error') is None
                    if info['method']=='mining.submit':
                        count['pending']-=1;count['accepted' if ok else 'rejected']+=1
                        if ok:
                            count['last_accepted']=time.time()
                            if info.get('target'):count['accepted_work']+=(1<<256)/(int(info['target'],16)+1)
                            else:count['unknown_target_accepts']+=1
                        self.event('submit_reply',role=role,connection=cid,client_id=info['original_id'],upstream_id=rid,accepted=ok,result=msg.get('result'),error=msg.get('error'),job_id=info['job_id'],target=info.get('target'),proof_sha256=info['proof_sha256'],worker=worker,latency=time.time()-info['time'])
                    elif info['method']=='mining.authorize':
                        authorized=ok
                        if ok:count['authorized']+=1
                        self.event('authorize_reply',role=role,connection=cid,accepted=ok,result=msg.get('result'),error=msg.get('error'),client_id=info['original_id'],upstream_id=rid)
                    msg['id']=info['original_id']
                writer.write(json.dumps(msg,separators=(',',':')).encode()+b'\n');await writer.drain()
        try:
            r,up=await self.open_pool(role,cid);self.writers.add(up);count['connected']+=1
            if ready:await ready()
            pipes=[asyncio.create_task(outgoing()),asyncio.create_task(incoming(r))]
            done,_=await asyncio.wait(pipes,return_when=asyncio.FIRST_COMPLETED)
            for p in done:p.result()
        except asyncio.CancelledError:raise
        except Exception as e:count['errors']+=1;self.event('proxy_error',role=role,connection=cid,error=repr(e))
        finally:
            for p in pipes:p.cancel()
            await asyncio.gather(*pipes,return_exceptions=True)
            lost=sum(info['method']=='mining.submit' for info in pending.values())
            count['unanswered']+=lost;count['pending']-=lost
            self.event('connection_closed',role=role,connection=cid,unanswered=lost)
            for w in (writer,up):
                if w:w.close();self.writers.discard(w)
            self.tasks.discard(task)

    async def direct_main(self,r,w):await self.mining(r,w,'main')

    async def socks(self,reader,writer):
        task=asyncio.current_task();self.tasks.add(task);self.writers.add(writer);up=None;pipes=[]
        try:
            version,n=await asyncio.wait_for(reader.readexactly(2),15);methods=await reader.readexactly(n)
            if version!=5 or 0 not in methods:writer.write(b'\x05\xff');await writer.drain();return
            writer.write(b'\x05\x00');await writer.drain()
            version,cmd,_,typ=await asyncio.wait_for(reader.readexactly(4),15)
            if version!=5 or cmd!=1:raise RuntimeError('Only SOCKS5 CONNECT is supported')
            if typ==1:host=socket.inet_ntop(socket.AF_INET,await reader.readexactly(4))
            elif typ==4:host=socket.inet_ntop(socket.AF_INET6,await reader.readexactly(16))
            elif typ==3:host=(await reader.readexactly((await reader.readexactly(1))[0])).decode('ascii')
            else:raise RuntimeError('Invalid SOCKS address type')
            port=int.from_bytes(await reader.readexactly(2),'big');norm=host.lower().rstrip('.')
            rules=self.c.get('redirect_rules',[{'domain_suffix':'lproute.com','port':3360}])
            matched=any(port==rule['port'] and (norm==rule['domain_suffix'] or norm.endswith('.'+rule['domain_suffix'])) for rule in rules)
            role='main' if norm in ('127.0.0.1','::1','localhost') and port==self.c['main_port'] else 'redirect' if matched else 'unknown'
            item={'time':time.time(),'host':host,'port':port,'role':role};self.targets.append(item);self.targets=self.targets[-256:];self.event('socks_target',**item)
            async def ready():writer.write(b'\x05\x00\x00\x01'+b'\0'*6);await writer.drain()
            if role!='unknown':await self.mining(reader,writer,role,ready);return
            if self.c.get('unknown_policy','passthrough')=='reject':
                self.unknown.append(item);self.unknown=self.unknown[-256:];self.event('unknown_rejected',host=host,port=port)
                writer.write(b'\x05\x02\x00\x01'+b'\0'*6);await writer.drain();return
            self.unknown.append(item);self.unknown=self.unknown[-256:];r,up=await asyncio.wait_for(asyncio.open_connection(host,port,limit=LIMIT),15);self.writers.add(up);await ready()
            async def pipe(src,dst,direction):
                first=True
                while chunk:=await src.read(65536):
                    if first:
                        hint='tls_record' if chunk[:1] in (b'\x16',b'\x17') else 'json_candidate' if chunk.lstrip()[:1] in (b'{',b'[') else 'opaque'
                        self.event('unknown_protocol',host=host,port=port,direction=direction,hint=hint,first_chunk_bytes=len(chunk));first=False
                    dst.write(chunk);await dst.drain()
            pipes=[asyncio.create_task(pipe(reader,up,'out')),asyncio.create_task(pipe(r,writer,'in'))]
            done,_=await asyncio.wait(pipes,return_when=asyncio.FIRST_COMPLETED)
            for p in done:p.result()
        except asyncio.CancelledError:raise
        except Exception as e:self.event('socks_error',error=repr(e))
        finally:
            for p in pipes:p.cancel()
            await asyncio.gather(*pipes,return_exceptions=True)
            for w in (writer,up):
                if w:w.close();self.writers.discard(w)
            self.tasks.discard(task)

    async def shutdown(self):
        for w in list(self.writers):w.close()
        for task in list(self.tasks):task.cancel()
        await asyncio.gather(*list(self.tasks),return_exceptions=True)
