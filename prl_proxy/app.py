"""CLI for the standalone proxy; miner lifecycle is explicitly separate."""
import argparse
import asyncio
import contextlib
import json
import os
import signal
import threading
import time
from pathlib import Path

from .audit import monitor
from .config import load_config
from .evidence import Evidence
from .proxy import LIMIT, Proxy


async def serve(config, audit=False, ready=None, stop_event=None):
    evidence = Evidence(config["data_dir"])
    proxy = Proxy(config, evidence.event)
    stop = stop_event if stop_event is not None else asyncio.Event()
    thread_stop = threading.Event()
    thread = None
    servers = []
    loop = asyncio.get_running_loop()
    installed_signals = []
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
            installed_signals.append(sig)
        except (NotImplementedError, RuntimeError):
            pass
    evidence.event("session_started", pid=os.getpid(), complete_channel_coverage_proven=False)
    try:
        servers.append(await asyncio.start_server(proxy.socks, config["listen_host"], config["socks_port"], limit=LIMIT))
        servers.append(await asyncio.start_server(proxy.direct_main, config["listen_host"], config["main_port"], limit=LIMIT))
        if audit:
            thread = threading.Thread(target=monitor, args=(evidence, thread_stop), daemon=True)
            thread.start()
        for pool in config["pools"]:
            if pool.get("tls", True) and not pool.get("verify_tls", True):
                evidence.event("tls_validation_disabled", host=pool["host"], port=pool["port"])
        if ready is not None:
            ready.set()
        while not stop.is_set():
            snapshot = proxy.snapshot()
            evidence.write("state.json", {"time": time.time(), "phase": "running", "pid": os.getpid(),
                "account": config["account"], "worker": config["worker"], "fee_worker": config["worker"] + config["fee_suffix"],
                "stats": snapshot, "complete_channel_coverage_proven": False})
            if proxy.identity_errors:
                raise RuntimeError("PRL identity/schema verification failed; inspect local events")
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), 5)
    finally:
        for server in servers:
            server.close()
        for server in servers:
            await server.wait_closed()
        await proxy.shutdown()
        thread_stop.set()
        if thread is not None:
            await asyncio.to_thread(thread.join, 7)
        evidence.write("state.json", {"time": time.time(), "phase": "stopped", "stats": proxy.snapshot()})
        evidence.event("session_stopped")
        for sig in installed_signals:
            loop.remove_signal_handler(sig)


def main():
    parser = argparse.ArgumentParser(description="Local PRL Stratum proxy and submission evidence")
    parser.add_argument("command", choices=("run", "status", "logs", "netlogs", "check-config"))
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--audit", action="store_true", help="Optional Linux packet-header audit (requires existing raw-socket permission)")
    args = parser.parse_args()
    try:
        config = load_config(args.config)
        if args.command == "check-config":
            print("Configuration valid. No connection made.")
        elif args.command == "run":
            asyncio.run(serve(config, args.audit))
        elif args.command == "status":
            path = Path(config["data_dir"]) / "state.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["state_age_seconds"] = time.time() - value["time"]
            print(json.dumps(value, ensure_ascii=False, indent=2))
        else:
            directory = Path(config["data_dir"])
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            names = ("events.jsonl",) if args.command == "logs" else ("unknown-channels.jsonl", "unknown-egress.jsonl")
            for name in names:
                (directory / name).touch(exist_ok=True)
            os.execvp("tail", ["tail", "-n", "25", "-F", *[str(directory / name) for name in names]])
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError, RuntimeError) as exc:
        parser.exit(1, f"Error: {exc}\n")
