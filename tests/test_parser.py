import unittest
from datetime import datetime

from loganalyser.parser import parse_lines


class ParserTests(unittest.TestCase):
    def test_failed_password_syslog(self):
        line = "Mar 14 10:02:11 web01 sshd[812]: Failed password for root from 203.0.113.5 port 4242 ssh2"
        events, stats = parse_lines([line], default_year=2025)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.kind, "failed")
        self.assertEqual(event.user, "root")
        self.assertEqual(event.ip, "203.0.113.5")
        self.assertEqual(event.port, 4242)
        self.assertEqual(event.method, "password")
        self.assertFalse(event.invalid_user)
        self.assertEqual(event.timestamp, datetime(2025, 3, 14, 10, 2, 11))
        self.assertEqual(stats.events, 1)

    def test_invalid_user_is_flagged(self):
        line = "Mar 14 10:02:11 web01 sshd[812]: Failed password for invalid user admin from 203.0.113.5 port 4242 ssh2"
        events, _ = parse_lines([line], default_year=2025)
        self.assertEqual(events[0].user, "admin")
        self.assertTrue(events[0].invalid_user)

    def test_accepted_publickey(self):
        line = "Mar  4 08:00:00 web01 sshd[9]: Accepted publickey for alice from 192.0.2.10 port 5000 ssh2: RSA SHA256:x"
        events, _ = parse_lines([line], default_year=2025)
        self.assertEqual(events[0].kind, "accepted")
        self.assertEqual(events[0].method, "publickey")
        self.assertEqual(events[0].timestamp, datetime(2025, 3, 4, 8, 0, 0))  # padded day parsed

    def test_iso_timestamps(self):
        lines = [
            "2025-03-14T10:02:11.123456+00:00 web01 sshd[812]: Failed password for root from 203.0.113.5 port 1 ssh2",
            "2025-03-14T10:02:12Z web01 sshd[812]: Failed password for root from 203.0.113.5 port 2 ssh2",
        ]
        events, _ = parse_lines(lines)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].timestamp, datetime(2025, 3, 14, 10, 2, 11))

    def test_other_services_and_junk_are_ignored(self):
        lines = [
            "Mar 14 10:00:00 web01 CRON[1]: pam_unix(cron:session): session opened for user root",
            "Mar 14 10:00:01 web01 sshd[2]: Connection closed by 203.0.113.5 port 1 [preauth]",
            "",
            "this is not a log line at all",
        ]
        events, stats = parse_lines(lines, default_year=2025)
        self.assertEqual(events, [])
        self.assertEqual(stats.lines_read, 4)

    def test_impossible_date_is_counted_not_fatal(self):
        line = "Feb 30 10:00:00 web01 sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2"
        events, stats = parse_lines([line], default_year=2025)
        self.assertEqual(events, [])
        self.assertEqual(stats.bad_timestamps, 1)

    def test_year_rolls_over_from_december_to_january(self):
        lines = [
            "Dec 31 23:59:58 h sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2",
            "Jan  1 00:00:02 h sshd[1]: Failed password for root from 203.0.113.5 port 2 ssh2",
        ]
        events, _ = parse_lines(lines, default_year=2024)
        self.assertEqual(events[0].timestamp.year, 2024)
        self.assertEqual(events[1].timestamp.year, 2025)
        self.assertLess(events[0].timestamp, events[1].timestamp)


if __name__ == "__main__":
    unittest.main()
