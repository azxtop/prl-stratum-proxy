"""Live loopback protocol fixtures; no miner binary or pool account required."""
import asyncio
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import unittest
from unittest import mock

from prl_proxy.config import load_config
from prl_proxy.launcher import forge_arguments, srb_arguments
from prl_proxy.proxy import LIMIT, Proxy


class ProfileTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.servers = []
        self.proxies = []
        self.events = []
        self.received = []
        self.writers = []
        self.temp = tempfile.TemporaryDirectory()
        self.config = dict(profile="forge", account="sample_account", worker="rig01", fee_suffix="dev",
                           main_port=23784, pools=[])

        async def pool(reader, writer):
            try:
                while line := await reader.readline():
                    msg = json.loads(line)
                    self.received.append(msg)
                    writer.write(json.dumps(dict(id=msg["id"], result=True, error=None)).encode() + b"\n")
                    if msg["method"] == "mining.authorize":
                        writer.write(json.dumps(dict(method="mining.notify", params=dict(job_id="job01", target="f" * 64))).encode() + b"\n")
                    await writer.drain()
            finally:
                writer.close()

        self.pool_port = await self.server(pool)

    async def asyncTearDown(self):
        for writer in self.writers:
            writer.close()
        for proxy in self.proxies:
            await proxy.shutdown()
        for server in self.servers:
            server.close()
            await server.wait_closed()
        await asyncio.sleep(.05)
        self.temp.cleanup()

    async def server(self, handler):
        server = await asyncio.start_server(handler, "127.0.0.1", 0, limit=LIMIT)
        self.servers.append(server)
        return server.sockets[0].getsockname()[1]

    def proxy(self):
        proxy = Proxy(self.config, lambda kind, **fields: self.events.append(dict(event=kind, **fields)))
        async def open_pool(role, cid):
            return await asyncio.open_connection("127.0.0.1", self.pool_port, limit=LIMIT)
        proxy.open_pool = open_pool
        self.proxies.append(proxy)
        return proxy

    async def connection(self, port):
        reader, writer = await asyncio.open_connection("127.0.0.1", port, limit=LIMIT)
        self.writers.append(writer)
        return reader, writer

    async def authorize_submit(self, reader, writer, params):
        writer.write(json.dumps(dict(id=41, method="mining.authorize", params=params)).encode() + b"\n")
        await writer.drain()
        self.assertEqual(json.loads(await reader.readline())["id"], 41)
        self.assertEqual(json.loads(await reader.readline())["method"], "mining.notify")
        proof = dict(job_id="job01", nonce="00a1", proof=[1, 2, 3])
        writer.write(json.dumps(dict(id=41, method="mining.submit", params=proof)).encode() + b"\n")
        await writer.drain()
        self.assertTrue(json.loads(await reader.readline())["result"])
        self.assertEqual(self.received[-1]["params"], proof)

    async def test_forge_main_and_developer_identity_proof(self):
        proxy = self.proxy()
        port = await self.server(proxy.direct_main)
        r, w = await self.connection(port)
        await self.authorize_submit(r, w, dict(wallet="sample_account.rig01"))
        self.assertEqual(self.received[0]["params"], dict(wallet="sample_account.rig01"))
        port = await self.server(proxy.direct_redirect)
        r, w = await self.connection(port)
        await self.authorize_submit(r, w, dict(wallet="prl1fixture", worker="dev", agent="ForgeMiner"))
        self.assertEqual(self.received[2]["params"]["wallet"], "sample_account")
        self.assertEqual(self.received[2]["params"]["worker"], "rig01dev")
        self.assertEqual(proxy.counts["main"]["accepted"], 1)
        self.assertEqual(proxy.counts["redirect"]["accepted"], 1)
        self.assertEqual(proxy.counts["redirect"]["authorized"], 1)

    async def test_forge_wrong_developer_schema_is_not_forwarded(self):
        proxy = self.proxy()
        port = await self.server(proxy.direct_redirect)
        r, w = await self.connection(port)
        w.write(b'{"id":1,"method":"mining.authorize","params":{"wallet":"unexpected"}}\n')
        await w.drain()
        self.assertEqual(await asyncio.wait_for(r.read(), 3), b"")
        self.assertEqual(self.received, [])
        self.assertEqual(proxy.identity_errors, 1)

    async def socks(self, port, host, target_port):
        r, w = await self.connection(port)
        w.write(b"\x05\x01\x00")
        await w.drain()
        self.assertEqual(await r.readexactly(2), b"\x05\x00")
        host = host.encode("ascii")
        w.write(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + target_port.to_bytes(2, "big"))
        await w.drain()
        self.assertEqual((await r.readexactly(10))[:2], b"\x05\x00")
        return r, w

    @unittest.skipUnless(shutil.which("openssl"), "openssl required for temporary TLS fixture")
    async def test_srb_tls_gate_rewrite_and_opaque_main(self):
        directory = Path(self.temp.name)
        key, cert = directory / "key.pem", directory / "cert.pem"
        subprocess.run([shutil.which("openssl"), "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=localhost", "-keyout", str(key), "-out", str(cert)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.config.update(profile="srb", client_cert=str(cert), client_key=str(key), unknown_policy="reject",
                           srb_main_targets=[dict(host="127.0.0.1", port=self.pool_port)])
        proxy = self.proxy()
        port = await self.server(proxy.socks)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        # TLS client fixture has the same trust behavior as the opt-in owned SRB process.
        r, w = await self.socks(port, "192.0.2.50", 3360)
        await w.start_tls(context, server_hostname="localhost")
        await self.authorize_submit(r, w, dict(wallet="prl1fixture", worker="dev", agent="SRBMiner-MULTI/3.7.6", type="v2"))
        self.assertEqual(self.received[0]["params"]["wallet"], "sample_account")
        self.assertEqual(self.received[0]["params"]["worker"], "rig01dev")
        self.assertEqual(proxy.counts["redirect"]["accepted"], 1)
        # A different protocol is rejected locally before opening an upstream mining connection.
        r, w = await self.socks(port, "192.0.2.51", 3361)
        await w.start_tls(context, server_hostname="localhost")
        w.write(b'{"id":1,"method":"mining.authorize","params":{"wallet":"prl1fixture","agent":"other","type":"v2"}}\n')
        await w.drain()
        self.assertEqual(await asyncio.wait_for(r.read(), 3), b"")
        self.assertEqual(len(self.received), 2)
        self.assertEqual(proxy.identity_errors, 0)
        self.assertTrue(any(e["event"] == "unknown_srb_protocol_rejected" for e in self.events))
        # Primary connection is preserved byte-for-byte, even with unknown_policy=reject.
        async def echo(reader, writer):
            try:
                while chunk := await reader.read(65536):
                    writer.write(chunk)
                    await writer.drain()
            finally:
                writer.close()
        target = await self.server(echo)
        proxy.c["srb_main_targets"] = [dict(host="127.0.0.1", port=target)]
        r, w = await self.socks(port, "127.0.0.1", target)
        payload = b"\x16\x03\x03opaque-main\x00" * 10000
        w.write(payload)
        await w.drain()
        self.assertEqual(await r.readexactly(len(payload)), payload)
        self.assertEqual(proxy.counts["main"]["submitted"], 0)


class ProfileConfigurationTests(unittest.TestCase):
    def test_defaults_and_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            value = dict(profile="forge", account="sample_account", worker="rig01", pools=[dict(host="127.0.0.1", port=30000)])
            path.write_text(json.dumps(value))
            c = load_config(path)
            self.assertEqual(c["redirect_rules"][0]["port"], 7048)
            self.assertEqual(c["fee_port"], 23785)
            self.assertIn("127.0.0.1:23900", forge_arguments("miner", c))
            value.update(profile="srb", client_cert="cert.pem", client_key="key.pem")
            path.write_text(json.dumps(value))
            c = load_config(path)
            self.assertEqual(Path(c["client_cert"]), Path(directory) / "cert.pem")
            self.assertEqual(c["srb_main_targets"], value["pools"])
            self.assertIn("--proxy", srb_arguments("miner", c))
            self.assertNotIn("--api-enable", srb_arguments("miner", c))
            for update in (dict(profile="unknown"), dict(miner_api_port=0), dict(miner_api_port=23783)):
                path.write_text(json.dumps({**value, **update}))
                with self.assertRaises(ValueError):
                    load_config(path)

    @unittest.skipUnless(os.name == "posix" and Path("/proc/self/maps").exists(), "Linux process launcher only")
    def test_srb_wrong_artifact_fails_before_child_start(self):
        from prl_proxy import srb_patch
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "miner"
            binary.write_bytes(b"unsupported artifact")
            with mock.patch.object(srb_patch.subprocess, "Popen") as popen:
                with self.assertRaisesRegex(ValueError, "hash"):
                    srb_patch.start([str(binary)], Path(directory) / "run")
                popen.assert_not_called()
