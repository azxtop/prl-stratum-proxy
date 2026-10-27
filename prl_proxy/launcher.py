"""Explicit child-only launchers for version-pinned miner profiles."""
import argparse
import hashlib
import json
import os
import platform
import signal
import subprocess
import time
from pathlib import Path

from .config import load_config
from .evidence import Evidence

FORGE_SHA256 = "248b7f879f872aed733237b16c9a286ad5bc06cb51884ec97bc0daa275acf2c4"
ONEZERO_SHA256 = {
    "d29ef582a7342b4914b990337693830ce75507accf4f86565d45911b6f743140": "1.8.2",
    "20cd045a78849bea80e4a8b35dc278076b1fedeaa6d40acf6788d51b77cfa2b6": "1.8.3",
    "7c2d68d61545cb121483fef76b6a1c2ab8fbeadab8e3ce737f76e19fd229b7ec": "1.8.4",
}


def onezero_arguments(binary, config):
    return [str(binary), "-a", "pearlhash", "-o", "stratum+tcp://127.0.0.1:" + str(config["main_port"]),
        "-w", config["account"], "--worker", config["worker"], "-p", "x",
        "--proxy", "127.0.0.1:" + str(config["socks_port"]), "--max-no-acc", "60"]


def start_onezero(binary, config):
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    if digest not in ONEZERO_SHA256:
        raise ValueError("OneZero binary is not a verified 1.8.2/1.8.3/1.8.4 artifact")
    return subprocess.Popen(onezero_arguments(binary, config), cwd=binary.parent, start_new_session=True)


def forge_arguments(binary, config):
    return [str(binary), "--algorithm", "pearlhash", "--pool", "stratum+tcp://127.0.0.1:" + str(config["main_port"]),
        "--tls", "false", "--wallet", config["account"], "--worker", config["worker"], "--password", "x",
        "--api-bind", "127.0.0.1:" + str(config.get("miner_api_port", 23900)), "--no-color", "--v1-tui"]


def srb_arguments(binary, config):
    pools = []
    for pool in config["pools"]:
        host = "[" + pool["host"] + "]" if ":" in pool["host"] else pool["host"]
        pools.append(("stratum+ssl://" if pool.get("tls", True) else "stratum+tcp://") + host + ":" + str(pool["port"]))
    return [str(binary), "--disable-cpu", "--disable-gpu-amd", "--disable-gpu-intel", "--disable-msr-tweaks",
        "--algorithm", "pearlhash", "--pool", ",".join(pools), "--wallet", config["account"], "--worker", config["worker"],
        "--password", "x", "--gpu-disable-oc", "--proxy", "127.0.0.1:" + str(config["socks_port"])]


def main():
    parser = argparse.ArgumentParser(description="Launch one owned OneZero/Forge/SRB process; never manages other miners")
    parser.add_argument("--config", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--hook", help="Forge: compiled native/netroute.c shared object")
    parser.add_argument("--enable-process-tls-patch", action="store_true", help="SRB: explicitly enable the version-pinned child memory change")
    args = parser.parse_args()
    child = None
    try:
        if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
            raise ValueError("These launchers support Linux x86_64 only")
        c = load_config(args.config)
        if c["listen_host"] != "127.0.0.1":
            raise ValueError("These miner launcher recipes require listen_host 127.0.0.1")
        binary = Path(args.binary).resolve(strict=True)
        state = json.loads((Path(c["data_dir"]) / "state.json").read_text(encoding="utf-8"))
        if state.get("phase") != "running" or time.time() - state.get("time", 0) > 15 or state.get("profile") != c["profile"]:
            raise ValueError("Start the matching proxy profile first; its status must be fresh")
        if state.get("account") != c["account"] or state.get("worker") != c["worker"]:
            raise ValueError("Proxy identity differs from launcher configuration")
        evidence = Evidence(c["data_dir"])
        if c["profile"] == "onezero":
            child = start_onezero(binary, c)
        elif c["profile"] == "forge":
            if hashlib.sha256(binary.read_bytes()).hexdigest() != FORGE_SHA256:
                raise ValueError("Forge binary is not the verified 1.8.8 artifact")
            if not args.hook:
                raise ValueError("Forge requires --hook pointing to a locally built shared object")
            hook = Path(args.hook).resolve(strict=True)
            rules = Path(c["data_dir"]) / "native-routes.txt"
            rules.write_text("".join(f"{rule['domain_suffix']} {rule['port']} {c['fee_port']}\n" for rule in c["redirect_rules"]), encoding="utf-8")
            env = {k: v for k, v in os.environ.items() if k not in ("LD_PRELOAD", "LD_AUDIT", "COLUMNS", "LINES") and not k.startswith(("FORGE_", "PRL_OBSERVE_"))}
            env.update(LD_PRELOAD=str(hook), PRL_OBSERVE_BINARY=str(binary), PRL_OBSERVE_LOG=str(Path(c["data_dir"]) / "native-events.jsonl"), PRL_OBSERVE_ROUTES=str(rules), NO_COLOR="1")
            child = subprocess.Popen(forge_arguments(binary, c), cwd=binary.parent, env=env, start_new_session=True)
        elif c["profile"] == "srb":
            if not args.enable_process_tls_patch:
                raise ValueError("SRB requires explicit --enable-process-tls-patch; read profiles/README.md first")
            from .srb_patch import start
            child = start(srb_arguments(binary, c), c["data_dir"])
        else:
            raise ValueError("Unsupported miner profile")
        evidence.event("owned_miner_started", profile=c["profile"], pid=child.pid, file_modified=False)
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *_: os.killpg(child.pid, signal.SIGTERM) if child.poll() is None else None)
        code = child.wait()
        evidence.event("owned_miner_exited", profile=c["profile"], pid=child.pid, returncode=code)
        if code:
            parser.exit(1, f"Miner exited with status {code}\n")
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        parser.exit(1, f"Error: {exc}\n")
    finally:
        if child is not None and child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)


if __name__ == "__main__":
    main()
