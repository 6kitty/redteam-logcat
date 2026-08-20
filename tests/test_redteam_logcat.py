from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).parents[1] / "redteam_logcat.py"
SPEC = importlib.util.spec_from_file_location("redteam_logcat", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
LOGCAT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = LOGCAT
SPEC.loader.exec_module(LOGCAT)


class RedteamLogcatTests(unittest.TestCase):
    def test_parses_structured_start_record(self) -> None:
        event = LOGCAT.parse_command_event(
            "2026-08-20T06:40:38+09:00 kali redteam-cmd[123]: "
            "[event=start] [session=session-7] [seq=2] [uid=1000] [user=kali] "
            "[tty=/dev/pts/3] [pwd=/home/kali/cjproj] [ssh=local] cmd=printf 'hello\\n'\n"
        )

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.session, "session-7")
        self.assertEqual(event.sequence, "2")
        self.assertEqual(event.command, "printf 'hello\\n'")

    def test_groups_only_text_between_private_boundary_markers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            output = directory / "output.log"
            timing = directory / "timing.log"
            start = b"\x1b]777;redteam-logcat;start;session-7;2\x07"
            visible = b"hello\r\n\x1b[31mred\x1b[0m\n"
            end = b"\x1b]777;redteam-logcat;end;session-7;2;0\x07"
            output.write_bytes(start + visible + end)
            timing.write_text(
                "H 0.000000 START_TIME 2026-08-20 00:00:00+00:00\n"
                f"O 0.000000 {len(start)}\n"
                f"O 0.000000 {len(visible)}\n"
                f"O 0.000000 {len(end)}\n",
                encoding="ascii",
            )
            session = LOGCAT.SessionView(
                session_id="session-7",
                output_path=output,
                timing_path=timing,
                metadata_path=directory / "metadata",
                start_at_end=False,
            )
            session.register_event(
                LOGCAT.CommandEvent(
                    timestamp="2026-08-20T06:40:38+09:00",
                    session="session-7",
                    sequence="2",
                    user="kali",
                    tty="/dev/pts/3",
                    working_directory="/home/kali/cjproj",
                    command="printf hello",
                )
            )

            rendered = io.StringIO()
            with contextlib.redirect_stdout(rendered):
                session.poll()  # establish file offsets
                session.poll()  # consume the complete fixture

        result = rendered.getvalue()
        self.assertIn("$ printf hello", result)
        self.assertIn("    hello", result)
        self.assertIn("    red", result)
        self.assertNotIn("\x1b", result)
        self.assertNotIn("redteam-logcat", result)

    def test_rejects_non_start_or_incomplete_records(self) -> None:
        self.assertIsNone(LOGCAT.parse_command_event("not a command\n"))
        self.assertIsNone(
            LOGCAT.parse_command_event(
                "2026-08-20T00:00:00Z kali redteam-cmd[1]: [event=end] [session=s] [seq=1]\n"
            )
        )

    def test_history_mode_renders_a_complete_structured_session(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            session_directory = root / "sessions" / "kali" / "session-7"
            session_directory.mkdir(parents=True)
            (session_directory / "metadata").write_text("session=session-7\n", encoding="utf-8")
            start = b"\x1b]777;redteam-logcat;start;session-7;1\x07"
            visible = b"proof\n"
            end = b"\x1b]777;redteam-logcat;end;session-7;1;0\x07"
            (session_directory / "output.log").write_bytes(start + visible + end)
            (session_directory / "timing.log").write_text(
                f"O 0.0 {len(start)}\nO 0.0 {len(visible)}\nO 0.0 {len(end)}\n",
                encoding="ascii",
            )
            command_log = root / "commands.log"
            command_log.write_text(
                "2026-08-20T06:40:38+09:00 kali redteam-cmd[1]: "
                "[event=start] [session=session-7] [seq=1] [uid=1000] [user=kali] "
                "[tty=/dev/pts/3] [pwd=/home/kali] [ssh=local] cmd=printf proof\n",
                encoding="utf-8",
            )

            rendered = io.StringIO()
            with contextlib.redirect_stdout(rendered):
                LOGCAT.Logcat(
                    command_log=command_log,
                    sessions_dir=root / "sessions",
                    history=1,
                    interval=0.01,
                    once=True,
                ).run()

        self.assertIn("$ printf proof", rendered.getvalue())
        self.assertIn("    proof", rendered.getvalue())

    def test_renders_fast_command_when_syslog_arrives_after_end_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            output = directory / "output.log"
            timing = directory / "timing.log"
            output.write_bytes(
                b"\x1b]777;redteam-logcat;start;session-7;3\x07"
                b"\x1b]777;redteam-logcat;end;session-7;3;1\x07"
            )
            timing.write_text("", encoding="ascii")
            session = LOGCAT.SessionView(
                session_id="session-7",
                output_path=output,
                timing_path=timing,
                metadata_path=directory / "metadata",
                start_at_end=False,
            )
            rendered = io.StringIO()
            with contextlib.redirect_stdout(rendered):
                session.poll()
                session.register_event(
                    LOGCAT.CommandEvent(
                        timestamp="2026-08-20T06:40:38+09:00",
                        session="session-7",
                        sequence="3",
                        user="kali",
                        tty="/dev/pts/3",
                        working_directory="/home/kali",
                        command="false",
                    )
                )

        self.assertIn("$ false", rendered.getvalue())
        self.assertIn("[exit 1]", rendered.getvalue())

    def test_groups_markerless_ssh_command_session(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            session_directory = root / "sessions" / "kali" / "ssh-7"
            session_directory.mkdir(parents=True)
            (session_directory / "metadata").write_text(
                "session=ssh-7\ncapture=ssh-command\nended_utc=2026-08-20T00:00:01Z\nexit_status=7\n",
                encoding="utf-8",
            )
            (session_directory / "output.log").write_bytes(b"remote stdout\nremote stderr\n")
            (session_directory / "timing.log").write_text("", encoding="ascii")
            command_log = root / "commands.log"
            command_log.write_text(
                "2026-08-20T06:40:38+09:00 kali redteam-cmd[1]: "
                "[event=start] [session=ssh-7] [seq=1] [uid=1000] [user=kali] "
                "[tty=ssh-command] [pwd=/home/kali] [ssh=local] cmd=printf remote\n",
                encoding="utf-8",
            )

            rendered = io.StringIO()
            with contextlib.redirect_stdout(rendered):
                LOGCAT.Logcat(
                    command_log=command_log,
                    sessions_dir=root / "sessions",
                    history=1,
                    interval=0.01,
                    once=True,
                ).run()

        result = rendered.getvalue()
        self.assertIn("$ printf remote", result)
        self.assertIn("    remote stdout", result)
        self.assertIn("    remote stderr", result)
        self.assertIn("    [exit 7]", result)

    def test_markerless_ssh_output_can_arrive_before_syslog(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            metadata = directory / "metadata"
            output = directory / "output.log"
            timing = directory / "timing.log"
            metadata.write_text(
                "session=ssh-race\ncapture=ssh-command\nended_utc=2026-08-20T00:00:01Z\nexit_status=0\n",
                encoding="utf-8",
            )
            output.write_bytes(b"arrived before syslog\n")
            timing.write_text("", encoding="ascii")
            session = LOGCAT.SessionView(
                session_id="ssh-race",
                output_path=output,
                timing_path=timing,
                metadata_path=metadata,
                start_at_end=False,
                capture_kind="ssh-command",
            )

            rendered = io.StringIO()
            with contextlib.redirect_stdout(rendered):
                session.poll()
                session.register_event(
                    LOGCAT.CommandEvent(
                        timestamp="2026-08-20T06:40:38+09:00",
                        session="ssh-race",
                        sequence="1",
                        user="kali",
                        tty="ssh-command",
                        working_directory="/home/kali",
                        command="printf race",
                    )
                )

        self.assertIn("    arrived before syslog", rendered.getvalue())

    def test_color_mode_preserves_only_safe_sgr_sequences(self) -> None:
        output: list[str] = []
        renderer = LOGCAT.PlainTextRenderer(output.append, preserve_sgr=True)

        renderer.feed(b"\x1b[38;5;45mcyan\x1b[0m\x1b]0;unsafe-title\x07")
        renderer.finish()

        self.assertEqual("".join(output), "\x1b[38;5;45mcyan\x1b[0m")

    def test_windows_administrator_check_uses_windows_api(self) -> None:
        with (
            mock.patch.object(LOGCAT.os, "name", "nt"),
            mock.patch.object(LOGCAT.ctypes, "windll", create=True) as windll,
        ):
            windll.shell32.IsUserAnAdmin.return_value = 1
            self.assertTrue(LOGCAT.has_elevated_privileges())


if __name__ == "__main__":
    unittest.main()
