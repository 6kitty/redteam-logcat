#!/usr/bin/env python3
"""Read-only live viewer for Redteam terminal evidence.

The viewer consumes only root-owned files produced by install-redteam-logging.sh.
It never enables terminal input recording and renders terminal output as safe plain
text rather than replaying control sequences on the operator's terminal.
"""

from __future__ import annotations

import argparse
import codecs
import ctypes
import os
import re
import stat
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable


VERSION = "0.1.3"
DEFAULT_COMMAND_LOG = Path("/var/log/redteam/commands.log")
DEFAULT_SESSIONS_DIR = Path("/var/log/redteam/sessions")
MARKER_PREFIX = b"\x1b]777;redteam-logcat;"
MAX_PENDING_OUTPUT = 1024 * 1024
FIELD_RE = re.compile(r"\[([a-z_]+)=([^\]]*)\]")
SGR_RE = re.compile(r"\x1b\[[0-9;:]*m")


class LogcatError(RuntimeError):
    """A recoverable configuration or evidence-file error."""


@dataclass(frozen=True)
class CommandEvent:
    timestamp: str
    session: str
    sequence: str
    user: str
    tty: str
    working_directory: str
    command: str


def parse_command_event(line: str) -> CommandEvent | None:
    """Parse only structured command-start records emitted by the installer."""
    if "redteam-cmd[" not in line or "[event=start]" not in line:
        return None

    timestamp, separator, remainder = line.partition(" ")
    if not separator:
        return None
    fields = dict(FIELD_RE.findall(remainder))
    command_marker = "cmd="
    command_position = remainder.find(command_marker)
    if command_position < 0:
        return None
    required = ("session", "seq", "user", "tty", "pwd")
    if any(not fields.get(name) for name in required):
        return None
    return CommandEvent(
        timestamp=timestamp,
        session=fields["session"],
        sequence=fields["seq"],
        user=fields["user"],
        tty=fields["tty"],
        working_directory=fields["pwd"],
        command=remainder[command_position + len(command_marker) :].rstrip("\n"),
    )


def has_elevated_privileges() -> bool:
    """Return whether this process can read root/administrator-only evidence files."""
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return os.geteuid() == 0


class SecureFollower:
    """Poll a regular file safely and recover from truncation or rotation."""

    def __init__(self, path: Path, *, start_at_end: bool) -> None:
        self.path = path
        self.start_at_end = start_at_end
        self.offset = 0
        self.identity: tuple[int, int] | None = None
        self.initialized = False

    def read_new(self) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags)
        except FileNotFoundError:
            return b""
        except OSError as error:
            raise LogcatError(f"cannot open {self.path}: {error.strerror}") from error

        try:
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode):
                raise LogcatError(f"refusing non-regular evidence file: {self.path}")
            identity = (details.st_dev, details.st_ino)
            if not self.initialized:
                self.identity = identity
                self.initialized = True
                if self.start_at_end:
                    self.offset = details.st_size
                    return b""
                self.offset = 0
            if self.identity != identity or details.st_size < self.offset:
                self.identity = identity
                self.offset = 0
            os.lseek(descriptor, self.offset, os.SEEK_SET)
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            data = b"".join(chunks)
            self.offset += len(data)
            return data
        finally:
            os.close(descriptor)


class MarkerSplitter:
    """Remove private OSC boundary markers while leaving normal bytes intact."""

    def __init__(self, on_text: Callable[[bytes], None], on_marker: Callable[[list[str]], None]) -> None:
        self._buffer = b""
        self._on_text = on_text
        self._on_marker = on_marker

    @staticmethod
    def _partial_prefix_length(data: bytes) -> int:
        maximum = min(len(data), len(MARKER_PREFIX) - 1)
        for size in range(maximum, 0, -1):
            if data.endswith(MARKER_PREFIX[:size]):
                return size
        return 0

    def feed(self, data: bytes) -> None:
        self._buffer += data
        while self._buffer:
            position = self._buffer.find(MARKER_PREFIX)
            if position < 0:
                keep = self._partial_prefix_length(self._buffer)
                if len(self._buffer) > keep:
                    self._on_text(self._buffer[:-keep] if keep else self._buffer)
                    self._buffer = self._buffer[-keep:] if keep else b""
                return
            if position:
                self._on_text(self._buffer[:position])
                self._buffer = self._buffer[position:]

            payload_start = len(MARKER_PREFIX)
            bell = self._buffer.find(b"\x07", payload_start)
            string_terminator = self._buffer.find(b"\x1b\\", payload_start)
            endings = [ending for ending in (bell, string_terminator) if ending >= 0]
            if not endings:
                return
            ending = min(endings)
            payload = self._buffer[payload_start:ending].decode("ascii", errors="replace")
            terminator_size = 1 if ending == bell else 2
            self._buffer = self._buffer[ending + terminator_size :]
            fields = payload.split(";")
            if len(fields) >= 3:
                self._on_marker(fields)


class PlainTextRenderer:
    """Drop terminal controls, optionally retaining safe Select Graphic Rendition colors."""

    NORMAL = 0
    ESCAPE = 1
    CSI = 2
    OSC = 3
    STRING = 4

    def __init__(self, emit: Callable[[str], None], *, preserve_sgr: bool) -> None:
        self._emit = emit
        self._preserve_sgr = preserve_sgr
        self._state = self.NORMAL
        self._text = bytearray()
        self._csi = bytearray()
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._last_was_cr = False

    def _flush_text(self) -> None:
        if self._text:
            self._emit(self._decoder.decode(bytes(self._text), final=False))
            self._text.clear()

    def _emit_newline(self) -> None:
        self._flush_text()
        self._emit("\n")

    def feed(self, data: bytes) -> None:
        for value in data:
            if self._state == self.NORMAL:
                if value == 0x1B:
                    self._flush_text()
                    self._state = self.ESCAPE
                    self._last_was_cr = False
                elif value == 0x0D:
                    self._emit_newline()
                    self._last_was_cr = True
                elif value == 0x0A:
                    if not self._last_was_cr:
                        self._emit_newline()
                    self._last_was_cr = False
                elif value == 0x09 or value >= 0x20:
                    self._text.append(value)
                    self._last_was_cr = False
                else:
                    self._flush_text()
                    self._emit(f"\\x{value:02x}")
                    self._last_was_cr = False
            elif self._state == self.ESCAPE:
                if value == ord("["):
                    self._csi = bytearray(b"\x1b[")
                    self._state = self.CSI
                elif value == ord("]"):
                    self._state = self.OSC
                elif value in (ord("P"), ord("^"), ord("_")):
                    self._state = self.STRING
                else:
                    self._state = self.NORMAL
            elif self._state == self.CSI:
                self._csi.append(value)
                if 0x40 <= value <= 0x7E:
                    if (
                        self._preserve_sgr
                        and value == ord("m")
                        and all(character in b"0123456789;:" for character in self._csi[2:-1])
                    ):
                        self._emit(self._csi.decode("ascii"))
                    self._csi.clear()
                    self._state = self.NORMAL
            elif self._state == self.OSC:
                if value == 0x07:
                    self._state = self.NORMAL
                elif value == 0x1B:
                    self._state = self.STRING
            elif self._state == self.STRING:
                if value == ord("\\"):
                    self._state = self.NORMAL
                elif self._state == self.OSC and value == 0x07:
                    self._state = self.NORMAL

    def finish(self) -> None:
        self._flush_text()


class IndentedOutput:
    """Print output with a stable indent beneath the command that produced it."""

    def __init__(self) -> None:
        self._line = ""

    @staticmethod
    def _is_script_footer(line: str) -> bool:
        return line.startswith("Script done on ") and "[COMMAND_EXIT_CODE=" in line

    @classmethod
    def _write_line(cls, line: str) -> None:
        visible_line = SGR_RE.sub("", line)
        if not visible_line.strip() or cls._is_script_footer(visible_line):
            return
        sys.stdout.write(f"    {line}\n")
        sys.stdout.flush()

    def write(self, text: str) -> None:
        self._line += text
        lines = self._line.split("\n")
        self._line = lines.pop()
        for line in lines:
            self._write_line(line)

    def close(self) -> None:
        if self._line:
            self._write_line(self._line)
            self._line = ""


@dataclass
class SessionView:
    session_id: str
    output_path: Path
    timing_path: Path
    start_at_end: bool
    color: bool = False
    waiting_events: dict[str, CommandEvent] = field(default_factory=dict)
    active_sequence: str | None = None
    active_event: CommandEvent | None = None
    active_return_code: str | None = None
    completed_return_codes: dict[str, str] = field(default_factory=dict)
    pending_output: list[str] = field(default_factory=list)
    displayed_output: IndentedOutput | None = None

    def __post_init__(self) -> None:
        self.output_follower = SecureFollower(self.output_path, start_at_end=self.start_at_end)
        self.renderer = PlainTextRenderer(self._on_text, preserve_sgr=self.color)
        self.splitter = MarkerSplitter(self.renderer.feed, self._on_marker)

    def register_event(self, event: CommandEvent) -> None:
        self.waiting_events[event.sequence] = event
        completed_return_code = self.completed_return_codes.pop(event.sequence, None)
        if completed_return_code is not None:
            self.active_sequence = event.sequence
            self._begin_event(event)
            self.active_return_code = completed_return_code
            self._finish_event()
            return
        if self.active_sequence == event.sequence and self.active_event is None:
            self._begin_event(event)

    def poll(self) -> None:
        # `script --log-out` records the raw terminal stream.  Its timing file
        # intentionally does not account for every line-discipline echo byte,
        # so using timing byte counts here can desynchronise a live display.
        # Our installer emits explicit, invisible, session-scoped boundaries in
        # that raw stream; consume that stream directly and retain timing only
        # for evidence replay with scriptreplay.
        data = self.output_follower.read_new()
        if data:
            self.splitter.feed(data)

    def _begin_event(self, event: CommandEvent) -> None:
        self.active_event = event
        self.displayed_output = IndentedOutput()
        print(f"\n[{event.timestamp}] {event.user} {event.tty} {event.working_directory}")
        print(f"$ {event.command}")
        for item in self.pending_output:
            self.displayed_output.write(item)
        self.pending_output.clear()

    def _on_marker(self, fields: list[str]) -> None:
        event_type, session_id, sequence = fields[:3]
        if session_id != self.session_id:
            return
        if event_type == "start":
            self.active_sequence = sequence
            event = self.waiting_events.get(sequence)
            if event is not None:
                self._begin_event(event)
        elif event_type == "end" and sequence == self.active_sequence:
            if len(fields) >= 4:
                self.active_return_code = fields[3]
            if self.active_event is None:
                self.completed_return_codes[sequence] = self.active_return_code or "?"
                self.active_sequence = None
            else:
                self._finish_event()

    def _on_text(self, text: str) -> None:
        if not text or self.active_sequence is None:
            return
        if self.active_event is None:
            total = sum(len(item) for item in self.pending_output) + len(text)
            if total <= MAX_PENDING_OUTPUT:
                self.pending_output.append(text)
            return
        assert self.displayed_output is not None
        self.displayed_output.write(text)

    def _finish_event(self) -> None:
        event_was_displayed = self.active_event is not None
        if self.displayed_output is not None:
            self.displayed_output.close()
        if event_was_displayed and self.active_return_code not in (None, "0"):
            print(f"    [exit {self.active_return_code}]")
        self.active_sequence = None
        self.active_event = None
        self.active_return_code = None
        self.pending_output.clear()
        self.displayed_output = None


class Logcat:
    def __init__(
        self,
        *,
        command_log: Path,
        sessions_dir: Path,
        history: int,
        interval: float,
        once: bool,
        color: bool = False,
    ) -> None:
        self.command_follower = SecureFollower(command_log, start_at_end=history == 0)
        self.command_pending = b""
        self.sessions_dir = sessions_dir
        self.start_at_end = history == 0
        self.history = history
        self.interval = interval
        self.once = once
        self.color = color
        self.sessions: dict[str, SessionView] = {}

    def discover_sessions(self) -> None:
        try:
            user_directories: Iterable[Path] = self.sessions_dir.iterdir()
        except FileNotFoundError:
            return
        for user_directory in user_directories:
            try:
                if not user_directory.is_dir() or user_directory.is_symlink():
                    continue
                session_directories = user_directory.iterdir()
            except OSError:
                continue
            for session_directory in session_directories:
                if not session_directory.is_dir() or session_directory.is_symlink():
                    continue
                metadata = session_directory / "metadata"
                output_path = session_directory / "output.log"
                timing_path = session_directory / "timing.log"
                if not metadata.is_file() or not output_path.exists() or not timing_path.exists():
                    continue
                session_id = self._session_id(metadata)
                if session_id and session_id not in self.sessions:
                    self.sessions[session_id] = SessionView(
                        session_id=session_id,
                        output_path=output_path,
                        timing_path=timing_path,
                        start_at_end=self.start_at_end,
                        color=self.color,
                    )

    @staticmethod
    def _session_id(metadata: Path) -> str | None:
        try:
            contents = metadata.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        for line in contents.splitlines():
            key, separator, value = line.partition("=")
            if key == "session" and separator and re.fullmatch(r"[A-Za-z0-9_.-]+", value):
                return value
        return None

    def _read_command_events(self) -> None:
        self.command_pending += self.command_follower.read_new()
        lines = self.command_pending.split(b"\n")
        self.command_pending = lines.pop()
        if self.history:
            lines = lines[-self.history :]
        for raw_line in lines:
            event = parse_command_event(raw_line.decode("utf-8", errors="replace") + "\n")
            if event is not None and event.session in self.sessions:
                self.sessions[event.session].register_event(event)

    def run(self) -> None:
        print("Redteam Logcat — root-only live evidence view (Ctrl-C to stop)")
        if self.start_at_end:
            print("Waiting for new structured sessions and commands…")
        while True:
            self.discover_sessions()
            self._read_command_events()
            for session in self.sessions.values():
                session.poll()
            if self.once:
                return
            time.sleep(self.interval)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Safely group structured Redteam shell commands with terminal output in real time."
    )
    parser.add_argument("--commands-log", type=Path, default=DEFAULT_COMMAND_LOG)
    parser.add_argument("--sessions-dir", type=Path, default=DEFAULT_SESSIONS_DIR)
    parser.add_argument(
        "--history",
        type=int,
        default=0,
        metavar="N",
        help="replay the last N structured command events (default: live events only)",
    )
    parser.add_argument("--interval", type=float, default=0.15, help="poll interval in seconds (default: 0.15)")
    parser.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="never" if os.environ.get("NO_COLOR") is not None else "auto",
        help="preserve safe ANSI colors from recorded output (default: auto)",
    )
    parser.add_argument("--no-color", action="store_const", const="never", dest="color", help=argparse.SUPPRESS)
    parser.add_argument("--once", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--version", action="version", version=f"redteam-logcat {VERSION}")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    if not has_elevated_privileges():
        privilege_command = "Run PowerShell as Administrator" if os.name == "nt" else "run with sudo"
        print(f"logcat: {privilege_command}; evidence files are administrator-only", file=sys.stderr)
        return 77
    if arguments.history < 0:
        print("logcat: --history must not be negative", file=sys.stderr)
        return 64
    if arguments.interval <= 0:
        print("logcat: --interval must be positive", file=sys.stderr)
        return 64
    color = arguments.color == "always" or (arguments.color == "auto" and sys.stdout.isatty())
    try:
        Logcat(
            command_log=arguments.commands_log,
            sessions_dir=arguments.sessions_dir,
            history=arguments.history,
            interval=arguments.interval,
            once=arguments.once,
            color=color,
        ).run()
    except KeyboardInterrupt:
        print("\nlogcat stopped")
    except LogcatError as error:
        print(f"logcat: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
