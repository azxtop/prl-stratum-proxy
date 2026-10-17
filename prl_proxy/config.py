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
    c.setdefault("redirect_rules", [{"domain_suffix": "lproute.com", "port": 3360}])
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
    return c
