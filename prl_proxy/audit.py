"""Optional Linux packet-header observation, with no payload retention."""
import ipaddress
import os
import select
import socket
import struct
import subprocess
import time


def monitor(evidence, stop):
    capture = None
    error = None
    try:
        if not hasattr(socket, "AF_PACKET"):
            raise OSError("Packet audit requires Linux AF_PACKET")
        capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        capture.setblocking(False)
    except OSError as exc:
        error = str(exc)
    try:
        addresses = set(subprocess.check_output(["hostname", "-I"], text=True, timeout=5).split())
    except (OSError, subprocess.SubprocessError):
        addresses = set()
    addresses.update(("127.0.0.1", "::1"))
    seen = {}
    packets = unsupported = 0
    next_status = next_sockets = 0
    evidence.event("audit_started", capture_started=capture is not None, error=error)
    try:
        while not stop.is_set():
            now = time.time()
            if now >= next_status:
                evidence.write("network-status.json", {"time": now, "pid": os.getpid(), "capture_started": capture is not None,
                    "error": error, "packets_observed": packets, "unsupported_headers": unsupported,
                    "payload_retained": False, "complete_process_attribution": False,
                    "complete_channel_coverage_proven": False})
                next_status = now + 5
            if now >= next_sockets:
                try:
                    result = subprocess.run(["ss", "-H", "-tunap"], capture_output=True, text=True, timeout=5)
                    evidence.append("socket-snapshots.jsonl", {"time": now, "output": result.stdout, "error": result.stderr})
                except (OSError, subprocess.SubprocessError) as exc:
                    evidence.event("audit_socket_error", error=str(exc))
                next_sockets = now + 60
            if capture is None:
                stop.wait(1)
                continue
            if not select.select([capture], [], [], 1)[0]:
                continue
            try:
                data, interface = capture.recvfrom(65535)
            except BlockingIOError:
                continue
            if len(data) < 34:
                continue
            packet = data[14:]
            if data[12:14] == b'\x08\x00':
                offset = (packet[0] & 15) * 4
                if offset < 20 or len(packet) < offset + 4:
                    unsupported += 1
                    continue
                source = socket.inet_ntop(socket.AF_INET, packet[12:16])
                destination = socket.inet_ntop(socket.AF_INET, packet[16:20])
                protocol = packet[9]
                if int.from_bytes(packet[6:8], "big") & 0x1fff:
                    unsupported += 1
                    continue
            elif data[12:14] == b'\x86\xdd' and len(data) >= 58:
                offset = 40
                protocol = packet[6]
                source = socket.inet_ntop(socket.AF_INET6, packet[8:24])
                destination = socket.inet_ntop(socket.AF_INET6, packet[24:40])
                if protocol not in (6, 17):
                    unsupported += 1
                    continue
            else:
                continue
            if source not in addresses or protocol not in (6, 17):
                continue
            source_port, destination_port = struct.unpack("!HH", packet[offset:offset + 4])
            key = (protocol, source, source_port, destination, destination_port)
            packets += 1
            if now - seen.get(key, 0) >= 300:
                category = "review_required"
                if ipaddress.ip_address(destination).is_loopback:
                    category = "loopback"
                elif source_port == 22:
                    category = "ssh_service_reply_candidate"
                elif protocol == 17 and destination_port == 53:
                    category = "dns_candidate"
                row = {"time": now, "protocol": "tcp" if protocol == 6 else "udp", "source_ip": source,
                    "source_port": source_port, "destination_ip": destination, "destination_port": destination_port,
                    "interface": interface[0], "classification": category, "attribution": "unassigned"}
                evidence.append("egress-flows.jsonl", row)
                if category == "review_required":
                    evidence.append("unknown-egress.jsonl", row)
                seen[key] = now
            if len(seen) > 20000:
                seen = {key: stamp for key, stamp in seen.items() if now - stamp < 300}
    except Exception as exc:
        evidence.event("audit_failed", error=str(exc))
        evidence.write("network-status.json", {"time": time.time(), "capture_started": False, "error": str(exc), "payload_retained": False})
    finally:
        if capture is not None:
            capture.close()
        evidence.event("audit_stopped")
