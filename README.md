# SSH Brute-Force Detector

A Python tool that parses SSH authentication logs, identifies brute-force attacks, classifies threats by severity, and generates JSON reports.

**MITRE ATT&CK Coverage:**
- T1110 – Brute Force
- T1078 – Valid Accounts (post-compromise success detection)

---

## Features

- Parses standard Linux `auth.log` / `syslog` SSH entries
- Detects: failed passwords, invalid users, post-brute-force successes
- Calculates **attack velocity** (attempts/minute)
- Classifies threats: `CRITICAL / HIGH / MEDIUM / LOW`
- Exports structured **JSON reports** for SIEM ingestion (Elasticsearch, Splunk)
- Works on real logs or simulated Cowrie honeypot logs

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run against sample log
python detector.py sample_auth.log

# Custom threshold + JSON export
python detector.py sample_auth.log --threshold 3 --json report.json

# Run against real system log (Linux)
sudo python detector.py /var/log/auth.log --json report.json
```

---

## Threat Classification Logic

| Level    | Condition                                                  |
|----------|------------------------------------------------------------|
| CRITICAL | Brute force succeeded (login after ≥5 failed attempts)    |
| HIGH     | ≥15 attempts OR velocity ≥ 6 attempts/min                 |
| MEDIUM   | ≥5 attempts OR velocity ≥ 3 attempts/min                  |
| LOW      | Below thresholds but still recorded                       |

---

## JSON Output Schema

```json
{
  "scan_time": "2026-03-17T10:00:00",
  "summary": { "total_lines": 30, "failed_logins": 18, ... },
  "threats": [
    {
      "ip": "10.0.0.5",
      "threat_level": "HIGH",
      "total_attempts": 10,
      "velocity_per_min": 30.0,
      "usernames_tried": ["root"],
      "succeeded": false,
      "first_seen": "...",
      "last_seen": "..."
    }
  ]
}
```

---

## Integration with Honeypot Project

Cowrie logs are stored in JSON at `/home/cowrie/var/log/cowrie/cowrie.json`.
Convert them using:

```bash
# Extract failed logins from Cowrie JSON log
cat cowrie.json | python3 -c "
import sys, json
for line in sys.stdin:
    e = json.loads(line)
    if e.get('eventid') == 'cowrie.login.failed':
        print(f'... Failed password for {e[\"username\"]} from {e[\"src_ip\"]} ...')
" > converted_auth.log

python detector.py converted_auth.log --json cowrie_threats.json
```

---

## Resume Bullet Points

- Built a Python SSH log analyzer detecting brute-force attacks across 30+ log entries with MITRE ATT&CK T1110 mapping
- Implemented velocity-based threat scoring (attempts/min) with 4-tier severity classification (CRITICAL/HIGH/MEDIUM/LOW)
- Designed JSON export pipeline compatible with Elasticsearch ingestion for SIEM workflows
