"""Known fallback routes, without real pool accounts or external connections."""
import asyncio
import json
import unittest

from prl_proxy.config import ADDED_ONEZERO_PRL_TARGETS
from prl_proxy.proxy import Proxy, classify_target


class OneZeroRouteTests(unittest.IsolatedAsyncioTestCase):
    def test_narrow_target_matching_and_main_precedence(self):
        config = {"main_port": 7001}
        for host, port in (("lproute.com", 3360), ("PEARL-RU.LPROUTE.COM.", 3360),
                           ("PEARL-HK.LPROUTE.COM.", 3361), ("prl.suprnova.cc", 3373)):
            self.assertEqual(classify_target(host, port, config), "redirect")
        for host, port in (("other.lproute.com", 3361), ("pearl-hk.lproute.com", 3373),
                           ("child.prl.suprnova.cc", 3373), ("prl.suprnova.cc", 3333),
                           ("evil-lproute.com", 3360), ("prl.suprnova.cc.evil.example", 3373),
                           ("other.example", 3373), ("192.0.2.50", 3361)):
            self.assertEqual(classify_target(host, port, config), "unknown")
        config["redirect_rules"] = [{"domain_suffix": "localhost", "port": 7001}]
        self.assertEqual(classify_target("LOCALHOST.", 7001, config), "main")
        self.assertEqual(classify_target("pearl-hk.lproute.com", 3361, config), "unknown")

    async def test_added_routes_refuse_non_prl_identity_before_forwarding(self):
        for host, port in sorted(ADDED_ONEZERO_PRL_TARGETS):
            with self.subTest(host=host):
                await asyncio.wait_for(self.refuse_identity(host, port), 5)

    async def refuse_identity(self, host, port):
        received = asyncio.get_running_loop().create_future()

        async def upstream(reader, writer):
            try:
                received.set_result(await reader.readline())
            finally:
                writer.close()

        pool = await asyncio.start_server(upstream, "127.0.0.1", 0)
        proxy = Proxy(dict(account="sample_account", worker="rig01", main_port=7001), lambda *a, **kw: None)

        async def open_pool(role, cid):
            return await asyncio.open_connection("127.0.0.1", pool.sockets[0].getsockname()[1])

        proxy.open_pool = open_pool
        server = await asyncio.start_server(proxy.socks, "127.0.0.1", 0)
        reader, writer = await asyncio.open_connection("127.0.0.1", server.sockets[0].getsockname()[1])
        try:
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            self.assertEqual(await reader.readexactly(2), b"\x05\x00")
            name = host.encode("ascii")
            writer.write(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + port.to_bytes(2, "big"))
            await writer.drain()
            self.assertEqual((await reader.readexactly(10))[:2], b"\x05\x00")
            writer.write(json.dumps(dict(id=1, method="mining.authorize", params=dict(wallet="other-coin-wallet"))).encode() + b"\n")
            await writer.drain()
            self.assertEqual(await reader.read(), b"")
            self.assertEqual(await received, b"")
            self.assertEqual(proxy.identity_errors, 1)
            self.assertEqual(proxy.counts["redirect"]["authorized"], 0)
            self.assertEqual(proxy.counts["redirect"]["submitted"], 0)
        finally:
            writer.close()
            await writer.wait_closed()
            await proxy.shutdown()
            server.close()
            pool.close()
            await server.wait_closed()
            await pool.wait_closed()
