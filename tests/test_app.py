import asyncio
import json
import socket
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from prl_proxy.app import serve
from prl_proxy.proxy import Proxy


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ApplicationTest(unittest.IsolatedAsyncioTestCase):
    async def test_tls_verification_is_default_and_scoped(self):
        writer = MagicMock()
        writer.get_extra_info.return_value = ("127.0.0.1", 1)
        c = {"pools": [{"host": "localhost", "port": 1}]}
        proxy = Proxy(c, lambda *args, **kw: None)
        mocked = AsyncMock(return_value=(object(), writer))
        with patch("prl_proxy.proxy.asyncio.open_connection", mocked):
            await proxy.open_pool("main", 1)
            ctx = mocked.call_args.kwargs["ssl"]
            self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(ctx.check_hostname)
            c["pools"][0]["verify_tls"] = False
            await proxy.open_pool("main", 2)
            disabled = mocked.call_args.kwargs["ssl"]
            self.assertEqual(disabled.verify_mode, ssl.CERT_NONE)
            self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

    async def test_unknown_rejection_and_domain_boundary(self):
        events = []
        proxy = Proxy({"main_port": 23784, "unknown_policy": "reject"}, lambda kind, **kw: events.append((kind, kw)))
        server = await asyncio.start_server(proxy.socks, "127.0.0.1", 0)
        try:
            for host, port in ((b"evil-lproute.com", 3360), (b"pearl.lproute.com", 3361)):
                reader, writer = await asyncio.open_connection("127.0.0.1", server.sockets[0].getsockname()[1])
                writer.write(b"\x05\x01\x00")
                await writer.drain()
                self.assertEqual(await reader.readexactly(2), b"\x05\x00")
                writer.write(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + port.to_bytes(2, "big"))
                await writer.drain()
                self.assertEqual((await reader.readexactly(10))[:2], b"\x05\x02")
                writer.close()
                await writer.wait_closed()
            self.assertEqual(len(proxy.unknown), 2)
            self.assertEqual(sum(kind == "unknown_rejected" for kind, _ in events), 2)
        finally:
            server.close()
            await server.wait_closed()
            await proxy.shutdown()

    async def test_real_app_routes_main_and_redirect_and_preserves_proof(self):
        received = []
        async def upstream(reader, writer):
            try:
                auth = json.loads(await reader.readline())
                received.append(auth["params"])
                writer.write(json.dumps({"id": auth["id"], "result": True, "error": None}).encode() + b"\n")
                writer.write(json.dumps({"method": "mining.notify", "params": {"job_id": "job", "target": "0" * 8 + "f" * 56}}).encode() + b"\n")
                await writer.drain()
                submission = json.loads(await reader.readline())
                received.append(submission["params"])
                writer.write(json.dumps({"id": submission["id"], "result": True, "error": None}).encode() + b"\n")
                await writer.drain()
                await reader.read()
            finally:
                writer.close()
        pool = await asyncio.start_server(upstream, "127.0.0.1", 0)
        with tempfile.TemporaryDirectory() as temp:
            main_port = free_port()
            socks_port = free_port()
            while socks_port == main_port:
                socks_port = free_port()
            config = {"account": "sample_account", "worker": "rig01", "fee_suffix": "dev", "listen_host": "127.0.0.1",
                "main_port": main_port, "socks_port": socks_port, "data_dir": Path(temp),
                "pools": [{"host": "127.0.0.1", "port": pool.sockets[0].getsockname()[1], "tls": False}]}
            ready = asyncio.Event()
            stop = asyncio.Event()
            app = asyncio.create_task(serve(config, ready=ready, stop_event=stop))
            try:
                await asyncio.wait_for(ready.wait(), 3)
                for role in ("main", "redirect"):
                    reader, writer = await asyncio.open_connection("127.0.0.1", main_port if role == "main" else socks_port)
                    if role == "redirect":
                        writer.write(b"\x05\x01\x00")
                        await writer.drain()
                        await reader.readexactly(2)
                        host = b"pearl.lproute.com"
                        writer.write(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + (3360).to_bytes(2, "big"))
                        await writer.drain()
                        await reader.readexactly(10)
                    identity = {"wallet": "sample_account", "worker": "rig01"} if role == "main" else {"wallet": "developer-wallet", "worker": "x"}
                    writer.write(json.dumps({"id": 1, "method": "mining.authorize", "params": identity}).encode() + b"\n")
                    await writer.drain()
                    self.assertTrue(json.loads(await reader.readline())["result"])
                    await reader.readline()
                    proof = {"job_id": "job", "plain_proof": "ab" * 32}
                    writer.write(json.dumps({"id": 1, "method": "mining.submit", "params": proof}).encode() + b"\n")
                    await writer.drain()
                    self.assertTrue(json.loads(await reader.readline())["result"])
                    writer.close()
                    await writer.wait_closed()
                stop.set()
                await asyncio.wait_for(app, 5)
                state = json.loads((Path(temp) / "state.json").read_text(encoding="utf-8"))
                self.assertEqual(state["phase"], "stopped")
                for role in ("main", "redirect"):
                    self.assertEqual(state["stats"]["roles"][role]["accepted"], 1)
                self.assertEqual(received[0]["worker"], "rig01")
                self.assertEqual(received[2]["worker"], "rig01dev")
                self.assertEqual(received[3], proof)
                self.assertNotIn("ab" * 32, (Path(temp) / "events.jsonl").read_text(encoding="utf-8"))
            finally:
                stop.set()
                if not app.done():
                    await asyncio.wait_for(app, 5)
                pool.close()
                await pool.wait_closed()
