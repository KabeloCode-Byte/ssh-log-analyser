"""Turn events and findings into text, Markdown or JSON reports."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any, Dict, List, Sequence

from .detectors import Finding
from .parser import AuthEvent, ParseStats

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def summarise(events: Sequence[AuthEvent], stats: ParseStats) -> Dict[str, Any]:
    failed = [e for e in events if e.kind == "failed"]
    accepted = [e for e in events if e.kind == "accepted"]
    times = [e.timestamp for e in events]
    return {
        "lines_read": stats.lines_read,
        "events_parsed": stats.events,
        "lines_with_invalid_dates": stats.bad_timestamps,
        "failed_logins": len(failed),
        "accepted_logins": len(accepted),
        "unique_source_ips": len({e.ip for e in events}),
        "first_event": min(times).strftime(TIME_FORMAT) if times else None,
        "last_event": max(times).strftime(TIME_FORMAT) if times else None,
        "top_failing_ips": Counter(e.ip for e in failed).most_common(5),
        "top_targeted_usernames": Counter(e.user for e in failed).most_common(5),
    }


def _finding_dict(finding: Finding) -> Dict[str, Any]:
    return {
        "rule": finding.rule,
        "severity": finding.severity,
        "ip": finding.ip,
        "summary": finding.summary,
        "first_seen": finding.first_seen.strftime(TIME_FORMAT),
        "last_seen": finding.last_seen.strftime(TIME_FORMAT),
        "count": finding.count,
        "usernames": list(finding.users),
        "mitre_attack": finding.mitre,
    }


def render_json(summary: Dict[str, Any], findings: Sequence[Finding]) -> str:
    payload = {"summary": summary, "findings": [_finding_dict(f) for f in findings]}
    return json.dumps(payload, indent=2)


def _usernames(users: Sequence[str], limit: int = 8) -> str:
    shown = ", ".join(users[:limit])
    extra = len(users) - limit
    return f"{shown} (+{extra} more)" if extra > 0 else shown


def render_text(summary: Dict[str, Any], findings: Sequence[Finding]) -> str:
    lines: List[str] = []
    lines.append("SSH LOG ANALYSIS")
    lines.append("=" * 60)
    lines.append(f"Period:            {summary['first_event']}  to  {summary['last_event']}")
    lines.append(f"Lines read:        {summary['lines_read']}")
    lines.append(f"Login events:      {summary['events_parsed']}")
    lines.append(f"Failed logins:     {summary['failed_logins']}")
    lines.append(f"Accepted logins:   {summary['accepted_logins']}")
    lines.append(f"Source IPs:        {summary['unique_source_ips']}")
    if summary["lines_with_invalid_dates"]:
        lines.append(f"Skipped (bad date): {summary['lines_with_invalid_dates']}")
    lines.append("")

    if summary["top_failing_ips"]:
        lines.append("Top failing IPs")
        for ip, count in summary["top_failing_ips"]:
            lines.append(f"  {ip:<18}{count:>6}")
        lines.append("")
        lines.append("Most targeted usernames")
        for user, count in summary["top_targeted_usernames"]:
            lines.append(f"  {user:<18}{count:>6}")
        lines.append("")

    lines.append(f"FINDINGS ({len(findings)})")
    lines.append("=" * 60)
    if not findings:
        lines.append("No suspicious activity found with the current thresholds.")
    for number, finding in enumerate(findings, start=1):
        lines.append(f"{number}. [{finding.severity.upper()}] {finding.rule}  from {finding.ip}")
        lines.append(f"   {finding.summary}")
        lines.append(f"   Time:      {finding.first_seen.strftime(TIME_FORMAT)} to "
                     f"{finding.last_seen.strftime(TIME_FORMAT)}")
        lines.append(f"   Usernames: {_usernames(finding.users)}")
        lines.append(f"   MITRE:     {finding.mitre}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_markdown(summary: Dict[str, Any], findings: Sequence[Finding]) -> str:
    out: List[str] = []
    out.append("# SSH Log Analysis Report\n")
    out.append(f"**Period:** {summary['first_event']} to {summary['last_event']}\n")
    out.append("| Metric | Value |")
    out.append("|---|---|")
    out.append(f"| Lines read | {summary['lines_read']} |")
    out.append(f"| Login events | {summary['events_parsed']} |")
    out.append(f"| Failed logins | {summary['failed_logins']} |")
    out.append(f"| Accepted logins | {summary['accepted_logins']} |")
    out.append(f"| Source IPs | {summary['unique_source_ips']} |")
    out.append("")

    out.append(f"## Findings ({len(findings)})\n")
    if not findings:
        out.append("No suspicious activity found with the current thresholds.\n")
    else:
        out.append("| # | Severity | Rule | Source IP | Details | Usernames | MITRE ATT&CK |")
        out.append("|---|---|---|---|---|---|---|")
        for number, f in enumerate(findings, start=1):
            out.append(
                f"| {number} | {f.severity} | {f.rule} | `{f.ip}` | {f.summary}; "
                f"{f.first_seen.strftime(TIME_FORMAT)} to {f.last_seen.strftime(TIME_FORMAT)} | "
                f"{_usernames(f.users, 5)} | {f.mitre} |"
            )
        out.append("")

    if summary["top_failing_ips"]:
        out.append("## Top failing IPs\n")
        out.append("| IP | Failed logins |")
        out.append("|---|---|")
        for ip, count in summary["top_failing_ips"]:
            out.append(f"| `{ip}` | {count} |")
        out.append("")
    return "\n".join(out) + "\n"
