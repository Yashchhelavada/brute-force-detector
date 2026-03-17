#!/usr/bin/env python3
"""
SSH Brute-Force Detector
Parses SSH auth logs, detects attack patterns, and generates threat reports.
Maps to MITRE ATT&CK: T1110 (Brute Force), T1078 (Valid Accounts)
"""

import re
import json
import argparse
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

# ─── Thresholds ────────────────────────────────────────────────────────────────
FAILED_THRESHOLD   = 5     # Attempts before flagging an IP
VELOCITY_THRESHOLD = 3.0   # Attempts per minute to flag as high-speed attack

# ─── Regex Patterns ────────────────────────────────────────────────────────────
PATTERNS = {
    "failed_password": re.compile(
        r"(\w{3}\s+\d+\s[\d:]+).*Failed password for (?:invalid user )?(\S+) from ([\d.]+)"
    ),
    "invalid_user": re.compile(
        r"(\w{3}\s+\d+\s[\d:]+).*Invalid user (\S+) from ([\d.]+)"
    ),
    "accepted_password": re.compile(
        r"(\w{3}\s+\d+\s[\d:]+).*Accepted password for (\S+) from ([\d.]+)"
    ),
    "accepted_publickey": re.compile(
        r"(\w{3}\s+\d+\s[\d:]+).*Accepted publickey for (\S+) from ([\d.]+)"
    ),
}


@dataclass
class AttackEvent:
    ip: str
    usernames_tried: set = field(default_factory=set)
    failed_attempts: int = 0
    invalid_user_attempts: int = 0
    timestamps: list = field(default_factory=list)
    succeeded: bool = False
    success_user: Optional[str] = None

    @property
    def total_attempts(self) -> int:
        return self.failed_attempts + self.invalid_user_attempts

    @property
    def velocity(self) -> float:
        """Attempts per minute."""
        if len(self.timestamps) < 2:
            return 0.0
        delta = (self.timestamps[-1] - self.timestamps[0]).total_seconds()
        return (len(self.timestamps) / delta * 60) if delta > 0 else float("inf")

    @property
    def threat_level(self) -> str:
        if self.succeeded and self.total_attempts >= FAILED_THRESHOLD:
            return "CRITICAL"  # Successful login after brute force
        if self.total_attempts >= FAILED_THRESHOLD * 3 or self.velocity >= VELOCITY_THRESHOLD * 2:
            return "HIGH"
        if self.total_attempts >= FAILED_THRESHOLD or self.velocity >= VELOCITY_THRESHOLD:
            return "MEDIUM"
        return "LOW"


def parse_timestamp(raw: str) -> datetime:
    """Parse syslog-style timestamp (no year — use current year)."""
    return datetime.strptime(f"{datetime.now().year} {raw.strip()}", "%Y %b %d %H:%M:%S")


def analyze_log(filepath: str) -> tuple[dict[str, AttackEvent], dict]:
    """Parse log file and return per-IP attack events + summary stats."""
    events: dict[str, AttackEvent] = defaultdict(lambda: AttackEvent(ip=""))
    stats = {
        "total_lines": 0,
        "failed_logins": 0,
        "invalid_users": 0,
        "successful_logins": 0,
        "unique_ips": set(),
    }

    with open(filepath, "r") as f:
        for line in f:
            stats["total_lines"] += 1

            # Failed password
            m = PATTERNS["failed_password"].search(line)
            if m:
                ts, user, ip = m.group(1), m.group(2), m.group(3)
                ev = events[ip]
                ev.ip = ip
                ev.failed_attempts += 1
                ev.usernames_tried.add(user)
                ev.timestamps.append(parse_timestamp(ts))
                stats["failed_logins"] += 1
                stats["unique_ips"].add(ip)
                continue

            # Invalid user
            m = PATTERNS["invalid_user"].search(line)
            if m:
                ts, user, ip = m.group(1), m.group(2), m.group(3)
                ev = events[ip]
                ev.ip = ip
                ev.invalid_user_attempts += 1
                ev.usernames_tried.add(user)
                ev.timestamps.append(parse_timestamp(ts))
                stats["invalid_users"] += 1
                stats["unique_ips"].add(ip)
                continue

            # Accepted password (possible post-brute-force success)
            m = PATTERNS["accepted_password"].search(line)
            if m:
                ts, user, ip = m.group(1), m.group(2), m.group(3)
                events[ip].succeeded = True
                events[ip].success_user = user
                events[ip].ip = ip
                stats["successful_logins"] += 1
                stats["unique_ips"].add(ip)
                continue

            # Accepted publickey (legitimate — still track)
            m = PATTERNS["accepted_publickey"].search(line)
            if m:
                _, _, ip = m.group(1), m.group(2), m.group(3)
                stats["successful_logins"] += 1
                stats["unique_ips"].add(ip)

    # Sort timestamps per IP
    for ev in events.values():
        ev.timestamps.sort()

    stats["unique_ips"] = len(stats["unique_ips"])
    return dict(events), stats


def filter_threats(events: dict[str, AttackEvent], min_attempts: int = 1) -> list[AttackEvent]:
    """Return events sorted by threat level and attempt count."""
    level_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    threats = [ev for ev in events.values() if ev.total_attempts >= min_attempts]
    return sorted(threats, key=lambda e: (level_order[e.threat_level], -e.total_attempts))


def export_json(events: dict[str, AttackEvent], stats: dict, output_path: str):
    """Export full results to JSON (useful for piping into SIEM/Elasticsearch)."""
    payload = {
        "scan_time": datetime.now().isoformat(),
        "summary": stats,
        "threats": [
            {
                "ip": ev.ip,
                "threat_level": ev.threat_level,
                "total_attempts": ev.total_attempts,
                "failed_passwords": ev.failed_attempts,
                "invalid_users": ev.invalid_user_attempts,
                "velocity_per_min": round(ev.velocity, 2),
                "usernames_tried": list(ev.usernames_tried),
                "succeeded": ev.succeeded,
                "success_user": ev.success_user,
                "first_seen": ev.timestamps[0].isoformat() if ev.timestamps else None,
                "last_seen": ev.timestamps[-1].isoformat() if ev.timestamps else None,
            }
            for ev in filter_threats(events)
        ],
    }
    with open(output_path, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"[+] JSON report saved → {output_path}")


def print_banner():
    print("""
╔══════════════════════════════════════════════════╗
║       SSH Brute-Force Detector v1.0              ║
║       MITRE ATT&CK: T1110, T1078                 ║
╚══════════════════════════════════════════════════╝
""")


def print_summary(stats: dict):
    print("── Log Summary ──────────────────────────────────")
    print(f"  Lines parsed       : {stats['total_lines']}")
    print(f"  Failed logins      : {stats['failed_logins']}")
    print(f"  Invalid user tries : {stats['invalid_users']}")
    print(f"  Successful logins  : {stats['successful_logins']}")
    print(f"  Unique IPs seen    : {stats['unique_ips']}")
    print()


COLORS = {
    "CRITICAL": "\033[91m",  # Red
    "HIGH":     "\033[33m",  # Yellow
    "MEDIUM":   "\033[36m",  # Cyan
    "LOW":      "\033[37m",  # White
    "RESET":    "\033[0m",
}


def print_threats(threats: list[AttackEvent]):
    if not threats:
        print("  ✅  No threats detected above threshold.")
        return

    print("── Detected Threats ─────────────────────────────")
    for ev in threats:
        color = COLORS.get(ev.threat_level, "")
        reset = COLORS["RESET"]
        tag = f"[{ev.threat_level}]"

        print(f"\n  {color}{tag}{reset}  {ev.ip}")
        print(f"    Attempts       : {ev.total_attempts} ({ev.failed_attempts} failed pwd, {ev.invalid_user_attempts} invalid user)")
        print(f"    Velocity       : {ev.velocity:.1f} attempts/min")
        print(f"    Usernames tried: {', '.join(sorted(ev.usernames_tried))}")
        if ev.timestamps:
            print(f"    First seen     : {ev.timestamps[0].strftime('%H:%M:%S')}")
            print(f"    Last seen      : {ev.timestamps[-1].strftime('%H:%M:%S')}")
        if ev.succeeded:
            print(f"    ⚠️  LOGIN SUCCESS as '{ev.success_user}' after brute force!")
    print()


def main():
    parser = argparse.ArgumentParser(description="SSH Brute-Force Log Analyzer")
    parser.add_argument("logfile", help="Path to auth.log file")
    parser.add_argument("--threshold", type=int, default=FAILED_THRESHOLD,
                        help=f"Min attempts to flag an IP (default: {FAILED_THRESHOLD})")
    parser.add_argument("--json", metavar="FILE", help="Also export results as JSON")
    args = parser.parse_args()

    print_banner()
    print(f"[*] Analyzing: {args.logfile}")
    print(f"[*] Flagging IPs with >= {args.threshold} failed attempts\n")

    events, stats = analyze_log(args.logfile)
    threats = filter_threats(events, min_attempts=args.threshold)

    print_summary(stats)
    print_threats(threats)

    if args.json:
        export_json(events, stats, args.json)


if __name__ == "__main__":
    main()
