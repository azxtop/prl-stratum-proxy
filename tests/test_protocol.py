import asyncio,json,unittest
from prl_proxy.proxy import Proxy,LIMIT

async def test(host='pearl-ru.lproute.com',port=3360,wallet='developer-wallet'):
    events=[];received=[];proofs=[{'job_id':'job','plain_proof':'aa'*32},{'job_id':'job','plain_proof':'bb'*32}]
    async def upstream(r,w):
        try:
            auth=json.loads(await r.readline());received.append(auth)
            assert auth['params']['wallet']=='sample_account' and auth['params']['worker']=='rig01dev'
            w.write(json.dumps({'id':auth['id'],'result':True,'error':None}).encode()+b'\n')
            w.write(json.dumps({'method':'mining.notify','params':{'job_id':'job','target':'0'*8+'f'*56}}).encode()+b'\n');await w.drain()
            a=json.loads(await r.readline());b=json.loads(await r.readline());received.extend([a,b])
            assert a['id']!=b['id'] and a['params']==proofs[0] and b['params']==proofs[1]
            for msg,ok in [(b,False),(a,True)]:
                w.write(json.dumps({'id':msg['id'],'result':ok,'error':None if ok else {'code':21,'msg':'stale-work'}}).encode()+b'\n')
            await w.drain();await r.read()
        finally:w.close()
    up=await asyncio.start_server(upstream,'127.0.0.1',0,limit=LIMIT)
    p=Proxy({'account':'sample_account','worker':'rig01','pools':[],'main_port':23784,'fee_suffix':'dev'},lambda kind,**kw:events.append({'event':kind,**kw}))
    async def connect(role,cid):return await asyncio.open_connection('127.0.0.1',up.sockets[0].getsockname()[1],limit=LIMIT)
    p.open_pool=connect
    srv=await asyncio.start_server(p.socks,'127.0.0.1',0,limit=LIMIT)
    r,w=await asyncio.open_connection('127.0.0.1',srv.sockets[0].getsockname()[1],limit=LIMIT)
    w.write(b'\x05\x01\x00');await w.drain();assert await r.readexactly(2)==b'\x05\x00'
    name=host.encode('ascii');w.write(b'\x05\x01\x00\x03'+bytes([len(name)])+name+port.to_bytes(2,'big'));await w.drain();assert (await r.readexactly(10))[:2]==b'\x05\x00'
    w.write(json.dumps({'id':1,'method':'mining.authorize','params':{'wallet':wallet,'worker':'developer-worker'}}).encode()+b'\n');await w.drain()
    assert json.loads(await r.readline())['id']==1;assert json.loads(await r.readline())['method']=='mining.notify'
    assert p.counts['redirect']['authorized']==1 and p.counts['redirect']['accepted']==0
    for proof in proofs:w.write(json.dumps({'id':1,'method':'mining.submit','params':proof}).encode()+b'\n')
    await w.drain()
    for ok in (False,True):
        reply=json.loads(await r.readline());assert reply['id']==1 and reply['result']==ok
    w.close();await w.wait_closed();await asyncio.sleep(.1)
    assert p.counts['redirect']['submitted']==2 and p.counts['redirect']['accepted']==1 and p.counts['redirect']['rejected']==1 and p.counts['redirect']['unanswered']==0
    replies=[x for x in events if x['event']=='submit_reply'];assert len(replies)==2 and replies[0]['proof_sha256']!=replies[1]['proof_sha256']
    route=next(x for x in events if x['event']=='connection_route')
    assert (route['source_host'],route['source_port'])==(host.lower().rstrip('.'),port)
    assert all(reply['connection']==route['connection'] and reply['role']==route['role'] for reply in replies)
    async def echo(reader,writer):
        try:
            while chunk:=await reader.read(65536):writer.write(chunk);await writer.drain()
        finally:writer.close()
    other=await asyncio.start_server(echo,'127.0.0.1',0)
    r,w=await asyncio.open_connection('127.0.0.1',srv.sockets[0].getsockname()[1],limit=LIMIT)
    w.write(b'\x05\x01\x00');await w.drain();assert await r.readexactly(2)==b'\x05\x00'
    w.write(b'\x05\x01\x00\x01\x7f\x00\x00\x01'+other.sockets[0].getsockname()[1].to_bytes(2,'big'));await w.drain();assert (await r.readexactly(10))[:2]==b'\x05\x00'
    opaque=b'\x16\x03\xffunchanged\0'*15000
    w.write(opaque);await w.drain();assert await r.readexactly(len(opaque))==opaque
    w.close();await w.wait_closed();await asyncio.sleep(.1)
    assert len(p.unknown)==1 and p.targets[-1]['role']=='unknown'
    await p.shutdown();srv.close();up.close();other.close();await srv.wait_closed();await up.wait_closed();await other.wait_closed()
    print('PASS: SOCKS domain route, authorization rewrite, proof preservation, colliding client IDs, out-of-order accepted/rejected replies, authorization excluded from share counts, unknown route byte-for-byte passthrough')

class ProtocolTest(unittest.TestCase):
    def test_protocol_roundtrip(self):
        asyncio.run(asyncio.wait_for(test(),15))

    def test_onezero_hk3361_roundtrip(self):
        asyncio.run(asyncio.wait_for(test('PEARL-HK.LPROUTE.COM.',3361,'prl1fixture'),15))

    def test_onezero_suprnova3373_roundtrip(self):
        asyncio.run(asyncio.wait_for(test('prl.suprnova.cc',3373,'prl1fixture'),15))

if __name__=='__main__':
    unittest.main()
