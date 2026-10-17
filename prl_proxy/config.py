"""Load public configuration without embedding deployment identities."""
import ipaddress
import json
import re
from pathlib import Path


def load_config(path):
    path = Path(path).resolve()
    with path.open(encoding="utf-8-sig") as source:
        value = json.load(source)
    if not isinstance(value, dict):
        raise ValueError("Configuration must be a JSON object")
    c = dict(value)
    c.setdefault("profile", "onezero")
    if c["profile"] not in ("onezero", "forge", "srb"):
        raise ValueError("profile must be onezero, forge or srb")
    for field in ("account", "worker"):
        if not isinstance(c.get(field), str) or not c[field].strip():
            raise ValueError(f"{field} is required")
    if c["account"] == "YOUR_POOL_ACCOUNT":
        raise ValueError("Replace YOUR_POOL_ACCOUNT with your own pool account")
    c.setdefault("fee_suffix", "dev")
    if not isinstance(c["fee_suffix"], str):
        raise ValueError("fee_suffix must be a string")
    c.setdefault("worker_max_length", 15)
    if not isinstance(c["worker_max_length"], int) or not 1 <= c["worker_max_length"] <= 128:
        raise ValueError("worker_max_length must be between 1 and 128")
    if not re.fullmatch("[a-z0-9]+", c["worker"]) or not re.fullmatch("[a-z0-9]*", c["fee_suffix"]):
        raise ValueError("worker and fee_suffix support lowercase letters and digits")
    if len(c["worker"] + c["fee_suffix"]) > c["worker_max_length"]:
        raise ValueError("Redirected worker exceeds worker_max_length")
    c.setdefault("listen_host", "127.0.0.1")
    if not ipaddress.ip_address(c["listen_host"]).is_loopback:
        raise ValueError("Only loopback listeners are supported; this is not a public proxy")
    for field, default in (("socks_port", 23783), ("main_port", 23784)):
        c.setdefault(field, default)
        if type(c[field]) is not int or not 1 <= c[field] <= 65535:
            raise ValueError(f"Invalid {field}")
    if c["socks_port"] == c["main_port"]:
        raise ValueError("Listener ports must be distinct")
    if c["profile"] == "forge":
        c.setdefault("fee_port", 23785)
        if type(c["fee_port"]) is not int or not 1 <= c["fee_port"] <= 65535 or c["fee_port"] in (c["socks_port"], c["main_port"]):
            raise ValueError("Forge fee_port must be a distinct valid local port")
    if "miner_api_port" in c:
        if type(c["miner_api_port"]) is not int or not 1 <= c["miner_api_port"] <= 65535:
            raise ValueError("Invalid miner_api_port")
        if c["miner_api_port"] in (c["socks_port"], c["main_port"], c.get("fee_port")):
            raise ValueError("miner_api_port must be distinct from proxy listeners")
    if not isinstance(c.get("pools"), list) or not c["pools"]:
        raise ValueError("At least one upstream pool is required")
    for pool in c["pools"]:
        if not isinstance(pool, dict) or not isinstance(pool.get("host"), str) or not pool["host"].strip():
            raise ValueError("Pool host is required")
        if pool["host"].endswith(".example.org") or pool["host"] == "example.org":
            raise ValueError("Replace the example pool host")
        if type(pool.get("port")) is not int or not 1 <= pool["port"] <= 65535:
            raise ValueError("Invalid upstream port")
        for flag in ("tls", "verify_tls"):
            if flag in pool and type(pool[flag]) is not bool:
                raise ValueError(f"{flag} must be a JSON boolean")
    default_rules = [{"domain_suffix": "prl.kryptex.network", "port": 7048}] if c["profile"] == "forge" else [{"domain_suffix": "lproute.com", "port": 3360}]
    c.setdefault("redirect_rules", default_rules)
    if not isinstance(c["redirect_rules"], list):
        raise ValueError("redirect_rules must be a list")
    for rule in c["redirect_rules"]:
        if not isinstance(rule, dict) or not isinstance(rule.get("domain_suffix"), str):
            raise ValueError("Redirect rule requires domain_suffix")
        domain = rule["domain_suffix"].lower().strip(".")
        if not domain or ":" in domain or "/" in domain or " " in domain:
            raise ValueError("Invalid domain suffix")
        rule["domain_suffix"] = domain
        if type(rule.get("port")) is not int or not 1 <= rule["port"] <= 65535:
            raise ValueError("Invalid redirect rule port")
    c.setdefault("unknown_policy", "passthrough")
    if c["unknown_policy"] not in ("passthrough", "reject"):
        raise ValueError("unknown_policy must be passthrough or reject")
    runtime = Path(c.get("data_dir", "runtime")).expanduser()
    c["data_dir"] = runtime if runtime.is_absolute() else path.parent / runtime
    if c["profile"] == "srb":
        for field in ("client_cert", "client_key"):
            if not isinstance(c.get(field), str) or not c[field]:
                raise ValueError(f"SRB profile requires a locally generated {field}")
            local = Path(c[field]).expanduser()
            c[field] = str(local if local.is_absolute() else path.parent / local)
        c.setdefault("srb_main_targets", [{"host": pool["host"], "port": pool["port"]} for pool in c["pools"]])
        if not isinstance(c["srb_main_targets"], list) or not c["srb_main_targets"]:
            raise ValueError("SRB profile requires srb_main_targets")
        for target in c["srb_main_targets"]:
            if not isinstance(target, dict) or not isinstance(target.get("host"), str) or not target["host"] or type(target.get("port")) is not int or not 1 <= target["port"] <= 65535:
                raise ValueError("Invalid srb_main_targets entry")
    return c
