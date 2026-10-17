import json
import tempfile
import unittest
from pathlib import Path

from prl_proxy.config import load_config
from prl_proxy.evidence import Evidence


class ConfigurationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "config.json"
        self.value = {"account": "sample_account", "worker": "rig01", "pools": [{"host": "127.0.0.1", "port": 12345}]}

    def load(self):
        self.path.write_text(json.dumps(self.value), encoding="utf-8")
        return load_config(self.path)

    def test_defaults_and_relative_runtime(self):
        c = self.load()
        self.assertEqual(c["fee_suffix"], "dev")
        self.assertEqual(c["data_dir"], self.path.parent / "runtime")
        self.assertEqual(c["unknown_policy"], "passthrough")

    def test_reject_open_proxy(self):
        self.value["listen_host"] = "0.0.0.0"
        with self.assertRaisesRegex(ValueError, "loopback"):
            self.load()

    def test_worker_suffix_length(self):
        self.value["worker"] = "a" * 13
        with self.assertRaisesRegex(ValueError, "length"):
            self.load()

    def test_placeholder_and_invalid_boolean(self):
        self.value["account"] = "YOUR_POOL_ACCOUNT"
        with self.assertRaises(ValueError):
            self.load()
        self.value["account"] = "sample_account"
        self.value["pools"][0]["verify_tls"] = "false"
        with self.assertRaisesRegex(ValueError, "boolean"):
            self.load()

    def test_invalid_rule_and_colliding_ports(self):
        self.value["redirect_rules"] = [{"domain_suffix": "", "port": 3360}]
        with self.assertRaises(ValueError):
            self.load()
        self.value.pop("redirect_rules")
        self.value.update(main_port=10000, socks_port=10000)
        with self.assertRaisesRegex(ValueError, "distinct"):
            self.load()

    def test_utf8_and_bounded_log_rotation(self):
        evidence = Evidence(Path(self.temp.name) / "runtime")
        for n in range(5):
            evidence.append("events.jsonl", {"n": n, "text": "日志"}, limit=1, backups=2)
        files = sorted(evidence.directory.glob("events.jsonl*"))
        self.assertEqual(len(files), 3)
        self.assertEqual(json.loads((evidence.directory / "events.jsonl").read_text(encoding="utf-8"))["n"], 4)
