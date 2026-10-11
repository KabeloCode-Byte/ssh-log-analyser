import contextlib
import io
import json
import os
import tempfile
import unittest

from loganalyser.cli import main

BURST = "".join(
    f"Mar 14 10:00:{i:02d} web01 sshd[1]: Failed password for root from 203.0.113.5 port {1000 + i} ssh2\n"
    for i in range(8)
)
QUIET = "Mar 14 10:00:00 web01 sshd[1]: Accepted publickey for alice from 192.0.2.10 port 1 ssh2\n"


def run(log_text, *extra):
    with tempfile.TemporaryDirectory() as folder:
        path = os.path.join(folder, "auth.log")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(log_text)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([path, "--year", "2025", *extra])
        return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_text_report_lists_the_finding(self):
        code, out, _ = run(BURST)
        self.assertEqual(code, 0)
        self.assertIn("brute_force", out)
        self.assertIn("203.0.113.5", out)

    def test_json_output_is_valid(self):
        code, out, _ = run(BURST, "--format", "json")
        data = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(data["summary"]["failed_logins"], 8)
        self.assertEqual(data["findings"][0]["rule"], "brute_force")

    def test_markdown_output(self):
        _, out, _ = run(BURST, "--format", "markdown")
        self.assertTrue(out.startswith("# SSH Log Analysis Report"))

    def test_fail_on_findings_exit_code(self):
        self.assertEqual(run(BURST, "--fail-on-findings")[0], 2)
        self.assertEqual(run(QUIET, "--fail-on-findings")[0], 0)

    def test_threshold_option_changes_result(self):
        _, out, _ = run(BURST, "--bf-failures", "20", "--format", "json")
        self.assertEqual(json.loads(out)["findings"], [])

    def test_non_ssh_log_gives_error(self):
        code, _, err = run("hello world\n")
        self.assertEqual(code, 1)
        self.assertIn("no SSH login events", err)

    def test_missing_file_gives_error(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = main(["/no/such/file.log"])
        self.assertEqual(code, 1)
        self.assertIn("cannot read", err.getvalue())


if __name__ == "__main__":
    unittest.main()
