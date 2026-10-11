"""Detection rules.

Each rule takes a list of AuthEvent objects and returns Findings. Rules use sliding
time windows per source IP address, so a slow, steady trickle of failures is not
flagged but a burst is.
"""

from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Sequence, Tuple

from .parser import AuthEvent

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2}


@dataclass(frozen=True)
class Thresholds:
    """Tunable limits. The defaults suit a small public-facing server."""

    brute_force_failures: int = 5
    brute_force_window_minutes: int = 10
    spray_distinct_users: int = 5
    spray_window_minutes: int = 30
    success_after_failures: int = 5
    success_window_minutes: int = 15


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    ip: str
    summary: str
    first_seen: datetime
    last_seen: datetime
    count: int
    users: Tuple[str, ...]
    mitre: str


def _failures_by_ip(events: Sequence[AuthEvent]) -> Dict[str, List[AuthEvent]]:
    by_ip: Dict[str, List[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.kind == "failed":
            by_ip[event.ip].append(event)
    for items in by_ip.values():
        items.sort(key=lambda e: e.timestamp)
    return by_ip


def detect_brute_force(events: Sequence[AuthEvent], limits: Thresholds) -> List[Finding]:
    """Many failed logins from one IP inside a short window (any usernames)."""
    window = timedelta(minutes=limits.brute_force_window_minutes)
    findings: List[Finding] = []

    for ip, failures in _failures_by_ip(events).items():
        best_count, best_lo, best_hi = 0, 0, 0
        lo = 0
        for hi, event in enumerate(failures):
            while event.timestamp - failures[lo].timestamp > window:
                lo += 1
            count = hi - lo + 1
            if count > best_count:
                best_count, best_lo, best_hi = count, lo, hi

        if best_count < limits.brute_force_failures:
            continue

        in_window = failures[best_lo : best_hi + 1]
        users = tuple(sorted({e.user for e in in_window}))
        severity = "high" if best_count >= 4 * limits.brute_force_failures else "medium"
        findings.append(
            Finding(
                rule="brute_force",
                severity=severity,
                ip=ip,
                summary=(
                    f"{best_count} failed logins within {limits.brute_force_window_minutes} min "
                    f"({len(failures)} failures in total)"
                ),
                first_seen=in_window[0].timestamp,
                last_seen=in_window[-1].timestamp,
                count=best_count,
                users=users,
                mitre="T1110.001 Brute Force: Password Guessing",
            )
        )
    return findings


def detect_password_spraying(events: Sequence[AuthEvent], limits: Thresholds) -> List[Finding]:
    """One IP trying many different usernames inside a window."""
    window = timedelta(minutes=limits.spray_window_minutes)
    findings: List[Finding] = []

    for ip, failures in _failures_by_ip(events).items():
        counts: Counter = Counter()
        best_distinct, best_lo, best_hi = 0, 0, 0
        best_users: List[str] = []
        lo = 0
        for hi, event in enumerate(failures):
            counts[event.user] += 1
            while event.timestamp - failures[lo].timestamp > window:
                gone = failures[lo].user
                counts[gone] -= 1
                if counts[gone] == 0:
                    del counts[gone]
                lo += 1
            if len(counts) > best_distinct:
                best_distinct, best_lo, best_hi = len(counts), lo, hi
                best_users = sorted(counts)

        if best_distinct < limits.spray_distinct_users:
            continue

        in_window = failures[best_lo : best_hi + 1]
        findings.append(
            Finding(
                rule="password_spraying",
                severity="high",
                ip=ip,
                summary=(
                    f"{best_distinct} different usernames tried within "
                    f"{limits.spray_window_minutes} min ({len(in_window)} attempts)"
                ),
                first_seen=in_window[0].timestamp,
                last_seen=in_window[-1].timestamp,
                count=len(in_window),
                users=tuple(best_users),
                mitre="T1110.003 Brute Force: Password Spraying",
            )
        )
    return findings


def detect_success_after_failures(events: Sequence[AuthEvent], limits: Thresholds) -> List[Finding]:
    """A successful login from an IP that was just failing repeatedly.

    This is the most important finding: the guessing may have worked.
    """
    window = timedelta(minutes=limits.success_window_minutes)
    failures = _failures_by_ip(events)
    failure_times = {ip: [e.timestamp for e in items] for ip, items in failures.items()}

    findings: List[Finding] = []
    seen = set()
    for event in events:
        if event.kind != "accepted" or event.ip not in failure_times:
            continue
        key = (event.ip, event.user)
        if key in seen:
            continue

        times = failure_times[event.ip]
        lo = bisect_left(times, event.timestamp - window)
        hi = bisect_right(times, event.timestamp)
        count = hi - lo
        if count < limits.success_after_failures:
            continue

        seen.add(key)
        recent = failures[event.ip][lo:hi]
        users = tuple(sorted({e.user for e in recent} | {event.user}))
        findings.append(
            Finding(
                rule="success_after_failures",
                severity="critical",
                ip=event.ip,
                summary=(
                    f"Login accepted for '{event.user}' after {count} failures "
                    f"in the previous {limits.success_window_minutes} min"
                ),
                first_seen=recent[0].timestamp,
                last_seen=event.timestamp,
                count=count,
                users=users,
                mitre="T1078 Valid Accounts",
            )
        )
    return findings


def detect_all(events: Sequence[AuthEvent], limits: Thresholds = Thresholds()) -> List[Finding]:
    """Run every rule. Results are ordered most severe first, then by time."""
    findings = (
        detect_brute_force(events, limits)
        + detect_password_spraying(events, limits)
        + detect_success_after_failures(events, limits)
    )
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.first_seen, f.ip, f.rule))
    return findings
