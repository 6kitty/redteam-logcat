from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()
