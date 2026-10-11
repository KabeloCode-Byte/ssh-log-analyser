"""Parse sshd authentication events out of Linux auth logs.

Two timestamp styles are supported:

* classic syslog:  ``Mar 14 10:02:11 web01 sshd[812]: Failed password for ...``
  (no year, so one is supplied by the caller)
* ISO 8601:        ``2025-03-14T10:02:11.123456+00:00 web01 sshd[812]: ...``

Timestamps are kept as the clock time written in the log. Time zone offsets are
dropped, which is fine for detection because all comparisons happen within one file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List, Optional, Tuple

SYSLOG_LINE = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<rest>.*)$")
ISO_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+(?P<rest>.*)$"
)
SSHD_LINE = re.compile(r"^(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<msg>.*)$")

FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+)(?: port (?P<port>\d+))?"
)
ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) "
    r"from (?P<ip>\S+)(?: port (?P<port>\d+))?"
)


@dataclass(frozen=True)
class AuthEvent:
    """One login attempt seen in the log."""

    timestamp: datetime
    host: str
    kind: str  # "failed" or "accepted"
    method: str  # password, publickey, keyboard-interactive/pam, ...
    user: str
    ip: str
    port: Optional[int]
    invalid_user: bool = False


@dataclass
class ParseStats:
    """Counts that help the reader judge how much of the log was understood."""

    lines_read: int = 0
    events: int = 0
    bad_timestamps: int = 0


def _parse_timestamp(line: str, year: int) -> Optional[Tuple[datetime, str]]:
    """Return (timestamp, remainder of line), or None if the line has no timestamp.

    Raises ValueError if a timestamp is present but not a real date (e.g. Feb 30).
    """
    match = ISO_LINE.match(line)
    if match:
        return datetime.strptime(match.group("ts"), "%Y-%m-%dT%H:%M:%S"), match.group("rest")

    match = SYSLOG_LINE.match(line)
    if match:
        text = " ".join(match.group("ts").split())  # collapse the padding in "Mar  4"
        return datetime.strptime(f"{year} {text}", "%Y %b %d %H:%M:%S"), match.group("rest")

    return None


def parse_lines(
    lines: Iterable[str], default_year: Optional[int] = None
) -> Tuple[List[AuthEvent], ParseStats]:
    """Parse log lines into events.

    ``default_year`` is only used for syslog-style timestamps. If the log crosses
    from December into January, the year is advanced automatically.
    """
    year = default_year if default_year is not None else datetime.now().year
    previous_month: Optional[int] = None
    events: List[AuthEvent] = []
    stats = ParseStats()

    for raw in lines:
        stats.lines_read += 1
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue

        try:
            parsed = _parse_timestamp(line, year)
        except ValueError:
            stats.bad_timestamps += 1
            continue
        if parsed is None:
            continue
        timestamp, rest = parsed

        # Syslog timestamps carry no year: roll it forward when December turns into January.
        if SYSLOG_LINE.match(line):
            if previous_month == 12 and timestamp.month == 1:
                year += 1
                timestamp = timestamp.replace(year=year)
            previous_month = timestamp.month

        sshd = SSHD_LINE.match(rest)
        if not sshd:
            continue
        message = sshd.group("msg")

        failed = FAILED.match(message)
        accepted = ACCEPTED.match(message)
        found = failed or accepted
        if not found:
            continue

        port = found.group("port")
        events.append(
            AuthEvent(
                timestamp=timestamp,
                host=sshd.group("host"),
                kind="failed" if failed else "accepted",
                method=found.group("method"),
                user=found.group("user"),
                ip=found.group("ip"),
                port=int(port) if port else None,
                invalid_user=bool(failed and failed.group("invalid")),
            )
        )
        stats.events += 1

    return events, stats
