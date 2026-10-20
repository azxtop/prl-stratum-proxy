"""Standalone 3.7.8 regression fixtures; never download/run a miner or use GPUs."""
import asyncio
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest

from experimental.srb378.proxy import Proxy
from experimental.srb378.run import config, guard, identity, stop_owned, device_hashrates


@unittest.skipUnless(shutil.which('openssl'), 'OpenSSL command required for local TLS fixtures')
class Protocol378Tests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name)
        self.cert=self.root/'cert.pem'; self.key=self.root/'key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost',
            '-addext','subjectAltName=IP:127.0.0.1','-keyout',str(self.key),'-out',str(self.cert)],check=True,capture_output=True)

    async def asyncTearDown(self):
        self.tmp.cleanup()

    async def fixture(self,tls,role,accepted):
        proof='P'*300000; seen=[]; tasks=set()
        serverctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);serverctx.load_cert_chain(self.cert,self.key)
        async def backend(reader,writer):
            task=asyncio.current_task();tasks.add(task)
            try:
                auth=json.loads(await reader.readline());seen.append(auth)
                writer.write(json.dumps(dict(id=1,result=True,error=None)).encode()+b'\n');await writer.drain()
                request=json.loads(await reader.readline());seen.append(request)
                writer.write(json.dumps(dict(id=2,result=accepted,error=None if accepted else dict(code=21,msg='stale-work'))).encode()+b'\n');await writer.drain()
                await reader.read()
            finally:
                writer.close();await writer.wait_closed();tasks.discard(task)
        # PRL routing uses TLS even if its miner-side input was plaintext.
        upstream=await asyncio.start_server(backend,'127.0.0.1',0,ssl=serverctx if tls or role!='unknown' else None,limit=32*1024**2)
        port=upstream.sockets[0].getsockname()[1]
        proxy=Proxy(self.root,dict(account='sample_account',worker='rig01',fee_worker='rig01dev',pools=[dict(host='127.0.0.1',port=port)],certificate=str(self.cert),key=str(self.key)))
        proxy.client_tls.load_verify_locations(cafile=str(self.cert))
        listener=await asyncio.start_server(proxy.handle,'127.0.0.1',0,limit=32*1024**2)
        proxyport=listener.sockets[0].getsockname()[1]
        wallet='prl1synthetic' if role=='dev' else 'sample_account' if role=='main' else 'synthetic-other-protocol'
        original=dict(wallet=wallet,worker='rig01',job_id='job1',plain_proof=proof,hs=315000000000000)
        def client():
            with socket.create_connection(('127.0.0.1',proxyport),timeout=8) as sock:
                sock.sendall(b'\x05\x01\x00');self.assertEqual(sock.recv(2),b'\x05\x00')
                sock.sendall(b'\x05\x01\x00\x01'+socket.inet_aton('127.0.0.1')+port.to_bytes(2,'big'));self.assertEqual(len(sock.recv(10)),10)
                connection=sock
                if tls:
                    ctx=ssl.create_default_context(cafile=str(self.cert));connection=ctx.wrap_socket(sock,server_hostname='127.0.0.1')
                with connection.makefile('rwb',buffering=0) as stream:
                    auth=dict(id=1,method='mining.authorize',params=dict(wallet=wallet,worker='rig01',agent='SRBMiner-MULTI/3.7.8',type='v2'))
                    stream.write(json.dumps(auth).encode()+b'\n');self.assertTrue(json.loads(stream.readline())['result'])
                    stream.write(json.dumps(dict(id=2,method='mining.submit',params=original)).encode()+b'\n')
                    reply=json.loads(stream.readline());self.assertIs(reply['result'],accepted)
                    if not accepted:self.assertEqual(reply['error']['msg'],'stale-work')
                if tls:connection.close()
        try:
            await asyncio.to_thread(client)
            for _ in range(100):
                if not proxy.active:break
                await asyncio.sleep(.01)
            self.assertEqual(len(seen),2)
            expected=dict(original)
            if role=='dev':expected.update(wallet='sample_account',worker='rig01dev')
            self.assertEqual(seen[1]['params'],expected)
            self.assertEqual(seen[0]['params']['wallet'],expected['wallet'])
            self.assertEqual(seen[0]['params']['worker'],expected['worker'])
            snap=proxy.snapshot();self.assertEqual(snap['errors'],0)
            if role!='unknown':
                stats=snap['roles'][role]
                self.assertEqual((stats['submitted'],stats['accepted'],stats['rejected'],stats['pending'],stats['unanswered']),(1,int(accepted),int(not accepted),0,0))
                # Authorize result:true was not counted as a second accepted share.
                self.assertEqual(stats['authorized'],1)
            else:
                self.assertEqual(snap['roles']['dev']['submitted'],0)
                self.assertEqual(snap['roles']['main']['submitted'],0)
        finally:
            listener.close();upstream.close();await listener.wait_closed();await upstream.wait_closed()
            for task in list(tasks):task.cancel()
            await asyncio.gather(*list(tasks),return_exceptions=True)

    async def test_tls_developer_large_plain_proof(self):await self.fixture(True,'dev',True)
    async def test_plaintext_developer_to_tls_upstream(self):await self.fixture(False,'dev',True)
    async def test_real_reject_not_counted_as_accept(self):await self.fixture(True,'dev',False)
    async def test_main_identity_and_submit_visible(self):await self.fixture(True,'main',True)
    async def test_unknown_tls_preserved(self):await self.fixture(True,'unknown',True)
    async def test_unknown_plaintext_preserved(self):await self.fixture(False,'unknown',True)


class Config378Tests(unittest.TestCase):
    def test_native_aggregate_is_not_double_counted(self):
        response={'hashrate':{'gpu':{'gpu0':100.0,'gpu1':200.0,'total':300.0}}}
        self.assertEqual(sum(device_hashrates(response)),300.0)

    def test_worker_suffix_limit_and_relative_paths(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);p=root/'config.json'
            value=dict(account='sample_account',worker='rig01',pools=[dict(host='127.0.0.1',port=1234)],data_dir='data',certificate='cert.pem',key='key.pem')
            p.write_text(json.dumps(value));parsed=config(p)
            self.assertEqual(parsed['fee_worker'],'rig01dev');self.assertEqual(parsed['data_dir'],str(root/'data'))
            value['worker']='x'*13;p.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError,'1-15'):config(p)
            value['worker']='rig01';value['pools'][0]['verify_tls']='false';p.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError,'verify_tls'):config(p)


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux process identity checks')
class Guard378Tests(unittest.TestCase):
    def test_expired_lease_stops_only_recorded_child(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);code='import time;time.sleep(60)'
            child=subprocess.Popen([sys.executable,'-c',code],start_new_session=True)
            try:
                i=identity(child.pid,code)
                (root/'srb-process.json').write_text(json.dumps(i))
                (root/'run.json').write_text(json.dumps(dict(controller=identity(os.getpid(),'-m'),hard_deadline_monotonic=time.monotonic()-1)))
                (root/'lease.json').write_text('{}')
                guard(root);child.wait(timeout=3)
                self.assertIsNotNone(child.returncode);self.assertTrue((root/'guard-stopped.json').exists())
            finally:
                if child.poll() is None:child.kill();child.wait()

    def test_stale_pid_identity_is_not_signalled(self):
        code='import time;time.sleep(60)';child=subprocess.Popen([sys.executable,'-c',code],start_new_session=True)
        try:
            i=identity(child.pid,code);i['ticks']=str(int(i['ticks'])+1)
            stop_owned(i);self.assertIsNone(child.poll())
        finally:child.kill();child.wait()
