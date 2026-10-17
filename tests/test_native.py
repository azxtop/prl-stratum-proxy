"""Compile our own socket client and verify the exact-executable native hook."""
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import tempfile
import threading
import unittest


@unittest.skipUnless(platform.system() == "Linux" and shutil.which("cc"), "Linux and C compiler required")
class NativeTests(unittest.TestCase):
    def test_scoped_routing_and_metadata_only(self):
        source = r'''
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv) {
    struct addrinfo h={0}, *a=NULL; h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
    if(argc!=2 || getaddrinfo("localhost",argv[1],&h,&a)) return 2;
    int fd=socket(a->ai_family,a->ai_socktype,a->ai_protocol);
    if(connect(fd,a->ai_addr,a->ai_addrlen)) return 3;
    const char *secret="fixture_payload_must_never_be_logged";
    if(send(fd,secret,strlen(secret),0)!=(ssize_t)strlen(secret)) return 4;
    char b[16]={0}; int n=recv(fd,b,15,0); if(n>0 && write(1,b,n)!=n) return 6;
    close(fd); freeaddrinfo(a); return n>0?0:5;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            src, binary, hook = base / "client.c", base / "client", base / "route.so"
            src.write_text(source)
            root = Path(__file__).resolve().parents[1]
            subprocess.run(["cc", "-O2", str(src), "-o", str(binary)], check=True)
            subprocess.run(["cc", "-O2", "-shared", "-fPIC", str(root / "native/netroute.c"), "-o", str(hook), "-ldl", "-pthread"], check=True)
            sockets = []
            threads = []
            def server(response):
                listener = socket.socket()
                listener.bind(("127.0.0.1", 0))
                listener.listen(5)
                listener.settimeout(5)
                sockets.append(listener)
                def accept():
                    try:
                        for _ in range(2):
                            conn, _ = listener.accept()
                            with conn:
                                conn.recv(4096)
                                conn.sendall(response)
                    except (OSError, TimeoutError):
                        pass
                thread = threading.Thread(target=accept, daemon=True)
                thread.start()
                threads.append(thread)
                return listener.getsockname()[1]
            original, redirected = server(b"original"), server(b"redirected")
            try:
                log, routes = base / "events.jsonl", base / "routes.txt"
                routes.write_text(f"localhost {original} {redirected}\n")
                env = {**os.environ, "LD_PRELOAD": str(hook), "PRL_OBSERVE_BINARY": str(binary),
                       "PRL_OBSERVE_LOG": str(log), "PRL_OBSERVE_ROUTES": str(routes)}
                def run(port):
                    return subprocess.run([str(binary), str(port)], env=env, capture_output=True, check=True, timeout=8).stdout
                self.assertEqual(run(original), b"redirected")
                self.assertEqual(run(redirected), b"redirected")  # unmatched port stays unchanged
                rows = [json.loads(line) for line in log.read_text().splitlines()]
                connects = [r for r in rows if r["event"] == "connect"]
                self.assertEqual([r["route_port"] for r in connects], [redirected, 0])
                self.assertTrue(any(r["event"] == "io_metadata" for r in rows))
                self.assertNotIn("fixture_payload", log.read_text())
                before = log.read_bytes()
                env["PRL_OBSERVE_BINARY"] = str(base / "different-executable")
                self.assertEqual(run(original), b"original")
                self.assertEqual(log.read_bytes(), before)
            finally:
                for listener in sockets:
                    listener.close()
                for thread in threads:
                    thread.join(timeout=6)
