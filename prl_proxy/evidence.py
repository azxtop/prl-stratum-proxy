"""Bounded UTF-8 JSONL logs; runtime files are private deployment material."""
import json
import os
import threading
import time
from pathlib import Path


class Evidence:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = threading.RLock()

    def write(self, name, value):
        with self.lock:
            path = self.directory / name
            temporary = path.with_name(path.name + ".tmp")
            temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            if os.name == "posix":
                temporary.chmod(0o600)
            temporary.replace(path)

    def append(self, name, value, limit=16 * 1024 * 1024, backups=8):
        with self.lock:
            path = self.directory / name
            if path.exists() and path.stat().st_size >= limit:
                for index in range(backups, 0, -1):
                    source = path if index == 1 else Path(str(path) + "." + str(index - 1))
                    destination = Path(str(path) + "." + str(index))
                    if source.exists():
                        source.replace(destination)
            with path.open("a", encoding="utf-8") as output:
                output.write(json.dumps(value, ensure_ascii=False) + "\n")
            if os.name == "posix":
                path.chmod(0o600)

    def event(self, kind, **fields):
        row = {"time": time.time(), "event": kind, **fields}
        self.append("events.jsonl", row)
        if kind.startswith("unknown") or (kind == "socks_target" and fields.get("role") == "unknown"):
            self.append("unknown-channels.jsonl", row)
