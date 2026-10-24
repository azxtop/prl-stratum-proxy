"""No miner downloads or real pool connections; validate the launch boundary."""
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from prl_proxy import launcher


class OneZeroLauncherTests(unittest.TestCase):
    def setUp(self):
        self.config = dict(main_port=25101, socks_port=25102, account="sample_account", worker="rig07")

    def test_unknown_artifact_never_starts_a_process(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "miner"
            binary.write_bytes(b"wrong version")
            with mock.patch.object(launcher.subprocess, "Popen") as popen:
                with self.assertRaisesRegex(ValueError, "verified"):
                    launcher.start_onezero(binary, self.config)
                popen.assert_not_called()

    def test_verified_versions_route_both_connections_and_preserve_identity(self):
        for digest in launcher.ONEZERO_SHA256:
            with self.subTest(version=launcher.ONEZERO_SHA256[digest]):
                binary = mock.Mock()
                binary.__str__ = mock.Mock(return_value="/fixture/miner")
                with mock.patch.object(launcher.hashlib, "sha256") as sha, mock.patch.object(launcher.subprocess, "Popen") as popen:
                    sha.return_value.hexdigest.return_value = digest
                    self.assertIs(launcher.start_onezero(binary, self.config), popen.return_value)
                    args = popen.call_args.args[0]
                    for key, value in (("-o", "stratum+tcp://127.0.0.1:25101"),
                                       ("--proxy", "127.0.0.1:25102"), ("-w", "sample_account"),
                                       ("--worker", "rig07"), ("--max-no-acc", "60")):
                        self.assertEqual(args[args.index(key) + 1], value)
                    self.assertTrue(popen.call_args.kwargs["start_new_session"])
                    self.assertNotIn("--no-cert-validation", args)
                    self.assertNotIn("--kernel", args)


if __name__ == "__main__":
    unittest.main()
