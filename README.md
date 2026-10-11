# SSH Log Analyser

![tests](https://github.com/KabeloCode-Byte/ssh-log-analyser/actions/workflows/tests.yml/badge.svg)

A command-line tool that reads Linux SSH authentication logs and flags brute-force and credential-guessing activity. It uses only the Python standard library, so there is nothing to install.

It looks for three patterns, ordered by how serious they are, and maps each to the [MITRE ATT&CK](https://attack.mitre.org/) technique it represents.

## What it detects

| Rule | What it means | Default trigger | MITRE ATT&CK |
|---|---|---|---|
| `success_after_failures` (critical) | A login succeeded from an IP address that had just been failing repeatedly. The guessing may have worked. | 5 or more failures from the IP in the 15 minutes before a successful login | T1078 Valid Accounts |
| `password_spraying` (high) | One IP tried many different usernames. | 5 or more distinct usernames within 30 minutes | T1110.003 Password Spraying |
| `brute_force` (medium or high) | One IP produced a burst of failed logins. | 5 or more failures within 10 minutes | T1110.001 Password Guessing |

All thresholds can be changed from the command line. One IP can trigger several rules at once, because the same behaviour can fit more than one pattern.

Detection works on sliding time windows per source IP, so a burst is flagged but a slow trickle of ordinary typos is not.

## Quick start

Requires Python 3.9 or newer (developed and tested on Python 3.13).

```
git clone https://github.com/KabeloCode-Byte/ssh-log-analyser.git
cd ssh-log-analyser
python -m loganalyser sample_data/sample_auth.log --year 2025
```

On Windows, use `py -m loganalyser sample_data\sample_auth.log --year 2025` if `python` is not recognised.

The sample log is synthetic. It contains one brute-force attack, one password-spraying run, one possible compromise and one harmless typo, and the typo is correctly left alone.

### Example output

```
FINDINGS (5)
============================================================
1. [CRITICAL] success_after_failures  from 192.0.2.77
   Login accepted for 'deploy' after 8 failures in the previous 15 min
   Time:      2025-03-14 11:40:00 to 2025-03-14 11:43:05
   Usernames: deploy
   MITRE:     T1078 Valid Accounts

2. [HIGH] brute_force  from 203.0.113.45
   56 failed logins within 10 min (56 failures in total)
   Time:      2025-03-14 08:05:00 to 2025-03-14 08:09:35
   Usernames: admin, root, ubuntu
   MITRE:     T1110.001 Brute Force: Password Guessing

3. [HIGH] password_spraying  from 198.51.100.23
   12 different usernames tried within 30 min (12 attempts)
   ...
```

## Usage on a real server

```
python -m loganalyser /var/log/auth.log                     # Debian and Ubuntu
python -m loganalyser /var/log/secure                       # RHEL, CentOS, Fedora
python -m loganalyser /var/log/auth.log.2.gz                # rotated logs are read directly
python -m loganalyser /var/log/auth.log --format markdown -o report.md
python -m loganalyser /var/log/auth.log --format json -o report.json
journalctl -u ssh --no-pager | python -m loganalyser -      # read from standard input
```

Reading system logs usually needs `sudo`.

| Option | Purpose |
|---|---|
| `--year` | Year to use for syslog timestamps, which do not include one. Defaults to the current year. The year rolls forward automatically if the log crosses from December into January. |
| `--format` | `text` (default), `markdown` or `json`. |
| `--output`, `-o` | Write the report to a file. |
| `--fail-on-findings` | Exit with code 2 if anything is found, so the tool can be used in scripts or scheduled jobs. |
| `--bf-failures`, `--bf-window` | Brute-force count and window in minutes. |
| `--spray-users`, `--spray-window` | Spraying distinct-username count and window in minutes. |
| `--success-failures`, `--success-window` | Failures required before a success, and the look-back window in minutes. |

Run `python -m loganalyser --help` for the full list.

## How it works

```
loganalyser/
  parser.py      Reads syslog and ISO 8601 log lines into AuthEvent records
  detectors.py   The three detection rules, using per-IP sliding windows
  report.py      Text, Markdown and JSON output
  cli.py         Command-line interface
tests/           31 unit tests for the parser, the rules and the CLI
scripts/         Generator for the synthetic sample log
sample_data/     Synthetic log used in the examples above
```

The parser only reads `Failed ...` and `Accepted ...` lines from `sshd`. Lines from other services are ignored, and lines with impossible dates are counted and skipped rather than stopping the run.

## Running the tests

```
python -m unittest discover -s tests -t . -v
```

The tests cover the edges of each rule: exactly at and just below the threshold, failures spread beyond the window, different IPs not being added together, a user mistyping their password once or twice and then logging in correctly, and failures that happen after a successful login.

## Limitations

- **False positives are possible.** Many users behind one shared address (an office or university network using NAT) can look like one IP making many attempts. Tune the thresholds to your environment.
- **It only sees what is in the log.** Attackers who spread attempts over many IPs, or who go slowly, may stay under the thresholds.
- **A flagged login is a lead, not proof.** Check `success_after_failures` findings by looking at what that account did next.
- **Only OpenSSH password and key logins are parsed.** Other authentication logs are not covered.
- **Time zones are ignored.** Timestamps are compared as written, which is correct within a single log file.

## Responsible use

Only analyse logs from systems you own or are authorised to review. The sample data is entirely synthetic and uses IP addresses reserved for documentation (RFC 5737), so none of it relates to a real machine or person.

## Ideas for extension

- Look up flagged IPs against a threat-intelligence feed
- Add rules for logins at unusual hours or from new locations
- Print firewall-ready block lists for confirmed attackers
- Support other services such as web server login logs

## Author

Kabelo Mokgobu, [GitHub](https://github.com/KabeloCode-Byte)
