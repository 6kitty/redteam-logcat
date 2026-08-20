from __future__ import annotations

import subprocess
import importlib.util
import json
import os
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
INSTALLER = ROOT / "platform/macos/install-macos.sh"
HARDWARE = ROOT / "platform/macos/validate-hardware.sh"
README = ROOT / "platform/macos/README.md"
RECORDER = ROOT / "platform/macos/redteam-macos-record-session"
HOOKS = ROOT / "platform/macos/shell-hooks.sh"
EVENT = ROOT / "platform/macos/redteam-macos-event"
TRANSPORT = ROOT / "platform/macos/redteam-macos-transport.py"
TRANSPORT_SPEC = importlib.util.spec_from_file_location("macos_transport", TRANSPORT)
assert TRANSPORT_SPEC is not None and TRANSPORT_SPEC.loader is not None
TRANSPORT_MODULE = importlib.util.module_from_spec(TRANSPORT_SPEC)
TRANSPORT_SPEC.loader.exec_module(TRANSPORT_MODULE)


class MacosCollectorStaticTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "bash is unavailable on Windows runners")
    def test_shell_sources_are_syntax_valid(self) -> None:
        for source in (INSTALLER, HARDWARE, RECORDER, EVENT):
            completed = subprocess.run(["bash", "-n", str(source)], check=False, capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_output_only_recording_and_viewer_contract_are_explicit(self) -> None:
        contents = (
            RECORDER.read_text(encoding="utf-8")
            + HOOKS.read_text(encoding="utf-8")
            + EVENT.read_text(encoding="utf-8")
        )
        self.assertIn('/usr/bin/script -q -e -F "$session/output.log"', contents)
        self.assertIn('BSD script -k, which records input', contents)
        self.assertIn('\\033]777;redteam-logcat;', contents)
        self.assertIn('[event=$event] [session=$session] [seq=$sequence]', contents)
        self.assertIn('/var/log/redteam/transport/capture-pending', contents)
        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertIn('refusing non-regular or symlink', installer)
        self.assertIn('.bash_profile', installer)
        self.assertIn('MACOS_TRANSPORT_ENABLED=0', installer)
        self.assertIn('org.redteam.logcat.transport', installer)
        self.assertIn('redteam_logcat.py', installer)
        self.assertIn('"$BIN_DIR/logcat"', installer)
        self.assertIn('--disable-transport', installer)
        self.assertIn('refusing endpoint-ID change while transport chain state exists', installer)
        self.assertIn('[[ ! -e $APP_DIR/transport.conf ]]', installer)
        self.assertIn('launchctl print system/org.redteam.logcat.transport', installer)
        self.assertIn('launchctl bootstrap system /Library/LaunchDaemons/org.redteam.logcat.transport.plist;', installer)
        transport = TRANSPORT.read_text(encoding="utf-8")
        self.assertIn('EvidenceSpool', transport)
        self.assertIn('enqueue_stream', transport)
        self.assertIn('for _ in range(32)', transport)
        self.assertIn('acknowledged', transport)
        self.assertIn('output_sha256', (ROOT / 'central_collector.py').read_text(encoding='utf-8'))

    def test_noninteractive_ssh_and_endpointsecurity_limits_are_documented(self) -> None:
        text = README.read_text(encoding="utf-8") + HARDWARE.read_text(encoding="utf-8")
        self.assertIn('noninteractive', text.lower())
        self.assertIn('unsupported', text.lower())
        self.assertIn('EndpointSecurity', text)
        self.assertIn('OpenBSM', text)

    @unittest.skipIf(os.name == "nt", "bash is unavailable on Windows runners")
    def test_hardware_report_is_safe_on_non_macos_hosts(self) -> None:
        completed = subprocess.run(["bash", str(HARDWARE), "--report"], check=False, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_transport_extracts_only_one_private_boundary_payload(self) -> None:
        with __import__("tempfile").TemporaryDirectory() as temporary:
            output = Path(temporary) / "output.log"
            output.write_bytes(
                b"prefix"
                b"\x1b]777;redteam-logcat;start;session-1;2\x07proof\n"
                b"\x1b]777;redteam-logcat;end;session-1;2;0\x07suffix"
            )
            self.assertEqual(TRANSPORT_MODULE.command_output("session-1", "2", output), b"proof\n")

    def test_transport_reconciles_an_acknowledged_final_event_after_crash(self) -> None:
        with __import__("tempfile").TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "acknowledged").mkdir()
            event = {"event_id": "event-1", "event_hash": "a" * 64}
            (root / "chain-state.json").write_text(json.dumps({"sequence": 1, "event_hash": "b" * 64, "outstanding": {"event_id": "event-1", "event_hash": "a" * 64, "sequence": 2}}), encoding="utf-8")
            (root / "acknowledged" / "event-1.json").write_text(json.dumps({"request": {"event": event}}), encoding="utf-8")
            self.assertTrue(TRANSPORT_MODULE.reconcile_acknowledged(root))
            state = json.loads((root / "chain-state.json").read_text(encoding="utf-8"))
            self.assertEqual(state, {"sequence": 2, "event_hash": "a" * 64, "outstanding": None})


if __name__ == "__main__":
    unittest.main()
