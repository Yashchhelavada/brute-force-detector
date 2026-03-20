# SSH Brute-Force Detector

A Python tool that parses SSH authentication logs, identifies brute-force attacks, classifies threats by severity, generates JSON reports, and displays results in a live web dashboard.

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
- **Live web dashboard** — Flask-powered UI with auto-refresh every 30 seconds
- Works on real logs or simulated Cowrie honeypot logs

---

## Project Structure

```
brute-force-detector/
├── detector.py          # Core log parser and threat classifier
├── dashboard.py         # Flask web server
├── templates/
│   └── dashboard.html   # Web dashboard UI
├── sample_auth.log      # Sample log for testing
├── requirements.txt
└── README.md
```

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
cd YOUR_REPO_NAME

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### CLI Mode

```bash
# Run against sample log
python detector.py sample_auth.log

# Custom threshold + JSON export
python detector.py sample_auth.log --threshold 3 --json report.json

# Run against real system log (Linux)
sudo python detector.py /var/log/auth.log --json report.json
```

### Dashboard Mode

```bash
# Run web dashboard (opens at http://localhost:5000)
python dashboard.py

# Run against real system log
LOG_FILE=/var/log/auth.log python dashboard.py
```

Then open your browser at **http://localhost:5000**

---

## Dashboard

The web dashboard shows:

- **Stat cards** — failed logins, invalid users, successful logins, unique IPs, lines parsed
- **Threat table** — every flagged IP with severity badge, velocity bar, usernames tried, timestamps
- **Post-compromise alert** — flags IPs that brute-forced and successfully logged in
- **MITRE ATT&CK** coverage tags
- **Auto-refreshes** every 30 seconds against the live log

![Dashboard Preview](https://via.placeholder.com/800x400?text=Dashboard+Preview)

---

## Threat Classification Logic

| Level    | Condition                                              |
|----------|--------------------------------------------------------|
| CRITICAL | Brute force succeeded (login after ≥5 failed attempts) |
| HIGH     | ≥15 attempts OR velocity ≥ 6 attempts/min              |
| MEDIUM   | ≥5 attempts OR velocity ≥ 3 attempts/min               |
| LOW      | Below thresholds but still recorded                    |

---

## JSON Output Schema

```json
{
  "scan_time": "2026-03-17T10:00:00",
  "summary": { "total_lines": 30, "failed_logins": 18 },
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



python detector.py converted_auth.log --json cowrie_threats.json
```

---
