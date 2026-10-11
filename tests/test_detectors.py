import unittest
from datetime import datetime, timedelta

from loganalyser.detectors import (
    Thresholds,
    detect_all,
    detect_brute_force,
    detect_password_spraying,
    detect_success_after_failures,
)
from loganalyser.parser import AuthEvent

BASE = datetime(2025, 3, 14, 12, 0, 0)


def failed(seconds, ip="203.0.113.5", user="root"):
    return AuthEvent(BASE + timedelta(seconds=seconds), "h", "failed", "password", user, ip, 22)


def accepted(seconds, ip="203.0.113.5", user="root"):
    return AuthEvent(BASE + timedelta(seconds=seconds), "h", "accepted", "password", user, ip, 22)


class BruteForceTests(unittest.TestCase):
    limits = Thresholds(brute_force_failures=5, brute_force_window_minutes=10)

    def test_flags_at_threshold(self):
        events = [failed(i * 10) for i in range(5)]
        findings = detect_brute_force(events, self.limits)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].ip, "203.0.113.5")
        self.assertEqual(findings[0].count, 5)

    def test_not_flagged_below_threshold(self):
        events = [failed(i * 10) for i in range(4)]
        self.assertEqual(detect_brute_force(events, self.limits), [])

    def test_failures_spread_beyond_window_are_not_flagged(self):
        # 5 failures, but 11 minutes apart each: never 5 inside any 10 minute window
        events = [failed(i * 11 * 60) for i in range(5)]
        self.assertEqual(detect_brute_force(events, self.limits), [])

    def test_ips_are_counted_separately(self):
        events = [failed(i, ip="203.0.113.1") for i in range(3)] + [failed(i, ip="203.0.113.2") for i in range(3)]
        self.assertEqual(detect_brute_force(events, self.limits), [])

    def test_severity_rises_with_volume(self):
        medium = detect_brute_force([failed(i) for i in range(5)], self.limits)[0]
        high = detect_brute_force([failed(i) for i in range(20)], self.limits)[0]
        self.assertEqual(medium.severity, "medium")
        self.assertEqual(high.severity, "high")

    def test_unsorted_input_still_works(self):
        events = [failed(i * 10) for i in range(5)][::-1]
        self.assertEqual(len(detect_brute_force(events, self.limits)), 1)


class SprayingTests(unittest.TestCase):
    limits = Thresholds(spray_distinct_users=5, spray_window_minutes=30)

    def test_many_usernames_flagged(self):
        users = ["a", "b", "c", "d", "e"]
        events = [failed(i * 60, user=u) for i, u in enumerate(users)]
        findings = detect_password_spraying(events, self.limits)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].users, ("a", "b", "c", "d", "e"))

    def test_one_username_many_times_is_not_spraying(self):
        events = [failed(i * 5, user="root") for i in range(30)]
        self.assertEqual(detect_password_spraying(events, self.limits), [])

    def test_usernames_outside_window_do_not_add_up(self):
        users = ["a", "b", "c", "d", "e"]
        events = [failed(i * 31 * 60, user=u) for i, u in enumerate(users)]
        self.assertEqual(detect_password_spraying(events, self.limits), [])


class SuccessAfterFailuresTests(unittest.TestCase):
    limits = Thresholds(success_after_failures=5, success_window_minutes=15)

    def test_success_after_burst_is_critical(self):
        events = [failed(i * 10) for i in range(6)] + [accepted(120, user="deploy")]
        findings = detect_success_after_failures(events, self.limits)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")
        self.assertIn("deploy", findings[0].users)

    def test_typo_then_success_is_not_flagged(self):
        events = [failed(0, user="alice"), failed(8, user="alice"), accepted(25, user="alice")]
        self.assertEqual(detect_success_after_failures(events, self.limits), [])

    def test_success_from_different_ip_is_not_flagged(self):
        events = [failed(i * 10) for i in range(8)] + [accepted(100, ip="192.0.2.99")]
        self.assertEqual(detect_success_after_failures(events, self.limits), [])

    def test_old_failures_outside_window_are_ignored(self):
        events = [failed(i) for i in range(8)] + [accepted(60 * 60)]
        self.assertEqual(detect_success_after_failures(events, self.limits), [])

    def test_failures_after_the_success_are_ignored(self):
        events = [accepted(0)] + [failed(10 + i) for i in range(8)]
        self.assertEqual(detect_success_after_failures(events, self.limits), [])

    def test_repeat_logins_give_one_finding(self):
        events = [failed(i) for i in range(6)] + [accepted(30), accepted(60)]
        self.assertEqual(len(detect_success_after_failures(events, self.limits)), 1)


class DetectAllTests(unittest.TestCase):
    def test_most_severe_first(self):
        events = [failed(i) for i in range(6)] + [accepted(30, user="root")]
        findings = detect_all(events)
        self.assertEqual(findings[0].rule, "success_after_failures")
        self.assertEqual(findings[1].rule, "brute_force")

    def test_quiet_log_has_no_findings(self):
        self.assertEqual(detect_all([accepted(0, user="alice", ip="192.0.2.10")]), [])


if __name__ == "__main__":
    unittest.main()
