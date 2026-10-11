"""Command-line interface: python -m loganalyser <logfile> [options]."""

from __future__ import annotations

import argparse
import gzip
import sys
from datetime import datetime
from typing import Iterable, List, Optional

from . import __version__
from .detectors import Thresholds, detect_all
from .parser import parse_lines
from .report import render_json, render_markdown, render_text, summarise


def _positive(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be 1 or more")
    return number


def build_parser() -> argparse.ArgumentParser:
    defaults = Thresholds()
    parser = argparse.ArgumentParser(
        prog="loganalyser",
        description="Find brute-force and credential-guessing activity in SSH auth logs.",
    )
    parser.add_argument("logfile", help="path to an auth log (.log or .gz), or - for standard input")
    parser.add_argument("--year", type=int, default=datetime.now().year,
                        help="year for syslog-style timestamps that have none (default: current year)")
    parser.add_argument("--format", choices=["text", "json", "markdown"], default="text",
                        help="report format (default: text)")
    parser.add_argument("--output", "-o", help="write the report to this file instead of the screen")
    parser.add_argument("--fail-on-findings", action="store_true",
                        help="exit with code 2 if anything suspicious is found (useful in scripts)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    group = parser.add_argument_group("thresholds")
    group.add_argument("--bf-failures", type=_positive, default=defaults.brute_force_failures,
                       help="failed logins from one IP that count as brute force "
                            f"(default: {defaults.brute_force_failures})")
    group.add_argument("--bf-window", type=_positive, default=defaults.brute_force_window_minutes,
                       help="brute-force window in minutes "
                            f"(default: {defaults.brute_force_window_minutes})")
    group.add_argument("--spray-users", type=_positive, default=defaults.spray_distinct_users,
                       help="distinct usernames from one IP that count as spraying "
                            f"(default: {defaults.spray_distinct_users})")
    group.add_argument("--spray-window", type=_positive, default=defaults.spray_window_minutes,
                       help="spraying window in minutes "
                            f"(default: {defaults.spray_window_minutes})")
    group.add_argument("--success-failures", type=_positive, default=defaults.success_after_failures,
                       help="failures before a success that count as a possible compromise "
                            f"(default: {defaults.success_after_failures})")
    group.add_argument("--success-window", type=_positive, default=defaults.success_window_minutes,
                       help="look-back window in minutes for the rule above "
                            f"(default: {defaults.success_window_minutes})")
    return parser


def _read_lines(path: str) -> Iterable[str]:
    if path == "-":
        return sys.stdin.read().splitlines()
    if path.endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            return handle.read().splitlines()
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read().splitlines()


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        lines = _read_lines(args.logfile)
    except OSError as error:
        print(f"loganalyser: cannot read {args.logfile}: {error.strerror or error}", file=sys.stderr)
        return 1

    events, stats = parse_lines(lines, default_year=args.year)
    if stats.events == 0:
        print(
            "loganalyser: no SSH login events found. Check that this is an sshd auth log "
            "(for example /var/log/auth.log or /var/log/secure).",
            file=sys.stderr,
        )
        return 1

    limits = Thresholds(
        brute_force_failures=args.bf_failures,
        brute_force_window_minutes=args.bf_window,
        spray_distinct_users=args.spray_users,
        spray_window_minutes=args.spray_window,
        success_after_failures=args.success_failures,
        success_window_minutes=args.success_window,
    )
    findings = detect_all(events, limits)
    summary = summarise(events, stats)

    renderers = {"text": render_text, "json": render_json, "markdown": render_markdown}
    report = renderers[args.format](summary, findings)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(report)
        print(f"Report written to {args.output} ({len(findings)} findings)")
    else:
        sys.stdout.write(report)

    return 2 if (args.fail_on_findings and findings) else 0


if __name__ == "__main__":
    sys.exit(main())
