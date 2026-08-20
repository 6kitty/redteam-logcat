"""Safe contract tests for the optional Linux mTLS transport assets."""
from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
INSTALLER = ROOT / "install.sh"
LINUX = ROOT / "platform" / "linux"
TRANSPORT = LINUX / "redteam-linux-transport.py"
SERVICE = LINUX / "redteam-logcat-transport.service"
TIMER = LINUX / "redteam-logcat-transport.timer"
SPEC = importlib.util.spec_from_file_location("linux_transport", TRANSPORT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LinuxTransportContractTests(unittest.TestCase):
    def test_assets_are_syntax_valid(self) -> None:
        compile(TRANSPORT.read_bytes(), str(TRANSPORT), "exec")

    @unittest.skipIf(os.name == "nt", "bash is unavailable on Windows runners")
    def test_installer_bash_syntax_is_valid(self) -> None:
        self.assertEqual(subprocess.run(["bash", "-n", str(INSTALLER)], capture_output=True, text=True).returncode, 0)

    def test_installer_keeps_transport_opt_in_and_reversible(self) -> None:
        text = INSTALLER.read_text(encoding="utf-8")
        for argument in ("--transport-endpoint", "--transport-endpoint-id", "--transport-ca-cert",
                         "--transport-client-cert", "--transport-client-key"):
            self.assertIn(argument, text)
        self.assertIn("all five --transport-* values are required together", text)
        self.assertIn("LINUX_TRANSPORT_ENABLED=0", text)
        self.assertIn("--dry-run", text)
        self.assertIn("--uninstall", text)
        self.assertIn("--disable-transport", text)
        self.assertIn("Idempotent base-installer re-runs", text)
        self.assertIn("endpoint-ID change", text)
        self.assertIn("preserved evidence", text)
        self.assertIn("central_collector.py", text)
        self.assertIn("redteam_evidence_protocol.py", text)
        self.assertIn("transport cutover", text)
        self.assertIn("commands-cursor.json", text)

    def test_exact_output_extraction_excludes_markers_and_timestamps(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output.log"
            output.write_bytes(b"prefix\x1b]777;redteam-logcat;start;session-1;2\x07proof\n"
                               b"\x1b]777;redteam-logcat;end;session-1;2;0\x07suffix")
            self.assertEqual(MODULE.completed_output("session-1", "2", output), b"proof\n")

    def test_forced_ssh_session_uses_its_root_owned_output_without_osc_markers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            session = Path(temporary) / "session-ssh"
            session.mkdir()
            output = session / "output.log"
            output.write_bytes(b"ssh stdout\nssh stderr\n")
            (session / "metadata").write_text("capture=ssh-command\n", encoding="utf-8")
            original = MODULE.private_regular
            try:
                MODULE.private_regular = lambda _path, **_kwargs: None
                self.assertEqual(MODULE.ssh_command_output(output), b"ssh stdout\nssh stderr\n")
            finally:
                MODULE.private_regular = original

    def test_transport_is_root_only_timer_driven_and_uses_shared_ack_spool(self) -> None:
        text = TRANSPORT.read_text(encoding="utf-8")
        self.assertIn("EvidenceSpool", text)
        self.assertIn("enqueue_stream", text)
        self.assertIn("for _ in range(32)", text)
        self.assertIn("acknowledged", text)
        self.assertIn("outstanding", text)
        self.assertIn("commands-cursor.json", text)
        self.assertIn("queue_completed_end_events", text)
        self.assertIn("ssh_command_output", text)
        self.assertIn("capture=ssh-command", text)
        self.assertNotIn("glob(\"*/output.log\")", text)
        self.assertIn('return 0\n\n\ndef check()', text)
        self.assertIn('"source_id": source_id()', text)
        self.assertIn('"endpoint_id": None', text)
        self.assertIn("different endpoint ID", text)
        self.assertIn("private_directory(ROOT)", text)
        self.assertNotIn("pty", text.lower())
        self.assertIn("User=root", SERVICE.read_text(encoding="utf-8"))
        self.assertIn("OnUnitInactiveSec=5s", TIMER.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
