"""Generate a synthetic SSH auth log for trying out the analyser.

Everything here is made up. IP addresses come from the ranges reserved for
documentation (RFC 5737), so they never belong to a real machine or person.

Usage:  python scripts/generate_sample_log.py sample_data/sample_auth.log
"""

from __future__ import annotations

import random
import sys
from datetime import datetime, timedelta

random.seed(42)  # same output every run

HOST = "web01"
START = datetime(2025, 3, 14, 6, 0, 0)

lines = []  # (datetime, message)


def add(when: datetime, message: str) -> None:
    pid = random.randint(1000, 30000)
    port = random.randint(30000, 65000)
    lines.append((when, f"{HOST} sshd[{pid}]: {message.format(port=port)}"))


# 1. Normal day: staff log in with keys, occasionally from a couple of office addresses.
staff = [("alice", "192.0.2.10"), ("bob", "192.0.2.11"), ("deploy", "192.0.2.12")]
for hour in range(8):
    for user, ip in staff:
        if random.random() < 0.6:
            when = START + timedelta(hours=hour, minutes=random.randint(0, 59), seconds=random.randint(0, 59))
            add(when, f"Accepted publickey for {user} from {ip} port {{port}} ssh2: RSA SHA256:abc123")

# 2. A harmless typo: alice fails twice, then gets in. Must NOT be flagged.
t = START + timedelta(hours=3, minutes=12)
for step in range(2):
    add(t + timedelta(seconds=8 * step), "Failed password for alice from 192.0.2.10 port {port} ssh2")
add(t + timedelta(seconds=25), "Accepted password for alice from 192.0.2.10 port {port} ssh2")

# 3. Brute force: one IP hammers root, then a few common admin names.
t = START + timedelta(hours=2, minutes=5)
targets = ["root"] * 40 + ["admin"] * 10 + ["ubuntu"] * 6
for step, user in enumerate(targets):
    prefix = "invalid user " if user != "root" else ""
    add(t + timedelta(seconds=5 * step), f"Failed password for {prefix}{user} from 203.0.113.45 port {{port}} ssh2")

# 4. Password spraying: one IP, many usernames, slowly (about one try a minute).
t = START + timedelta(hours=4, minutes=30)
names = ["test", "oracle", "postgres", "git", "ftpuser", "guest", "support", "pi", "jenkins", "user", "mysql", "hadoop"]
for step, user in enumerate(names):
    add(t + timedelta(minutes=step, seconds=random.randint(0, 20)),
        f"Failed password for invalid user {user} from 198.51.100.23 port {{port}} ssh2")

# 5. Possible compromise: repeated failures against 'deploy', then a successful login.
t = START + timedelta(hours=5, minutes=40)
for step in range(8):
    add(t + timedelta(seconds=20 * step), "Failed password for deploy from 192.0.2.77 port {port} ssh2")
add(t + timedelta(seconds=185), "Accepted password for deploy from 192.0.2.77 port {port} ssh2")

# 6. Noise from other services, which the parser must ignore.
for hour in range(8):
    when = START + timedelta(hours=hour, minutes=1)
    lines.append((when, f"{HOST} CRON[{random.randint(1000, 9999)}]: pam_unix(cron:session): session opened for user root"))
    lines.append((when + timedelta(seconds=2), f"{HOST} systemd[1]: Started Session {hour} of user alice."))

lines.sort(key=lambda item: item[0])

path = sys.argv[1] if len(sys.argv) > 1 else "sample_auth.log"
with open(path, "w", encoding="utf-8") as handle:
    for when, text in lines:
        # classic syslog format: day is space-padded, no year
        stamp = when.strftime("%b ") + f"{when.day:>2}" + when.strftime(" %H:%M:%S")
        handle.write(f"{stamp} {text}\n")
print(f"Wrote {len(lines)} lines to {path}")
