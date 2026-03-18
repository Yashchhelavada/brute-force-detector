#!/usr/bin/env python3
"""
Dashboard server for SSH Brute-Force Detector.
Reads report.json and serves a live web UI.
"""

import json
import subprocess
import os
from flask import Flask, render_template_string, jsonify

app = Flask(__name__)

LOG_FILE    = os.environ.get("LOG_FILE", "sample_auth.log")
REPORT_FILE = os.environ.get("REPORT_FILE", "report.json")


def get_report():
    """Load the latest report.json, or run detector to generate it."""
    if not os.path.exists(REPORT_FILE):
        subprocess.run(
            ["python", "detector.py", LOG_FILE, "--json", REPORT_FILE],
            capture_output=True
        )
    try:
        with open(REPORT_FILE) as f:
            return json.load(f)
    except Exception:
        return {"error": "Could not load report.json"}


@app.route("/")
def index():
    return render_template_string(open("templates/dashboard.html").read())


@app.route("/api/report")
def api_report():
    """Return latest report as JSON — can also be called by the frontend."""
    # Re-run detector to get fresh data every time the API is hit
    subprocess.run(
        ["python", "detector.py", LOG_FILE, "--json", REPORT_FILE],
        capture_output=True
    )
    return jsonify(get_report())


if __name__ == "__main__":
    os.makedirs("templates", exist_ok=True)
    print(f"\n[*] Dashboard running at http://localhost:5000")
    print(f"[*] Reading log : {LOG_FILE}")
    print(f"[*] Report file : {REPORT_FILE}\n")
    app.run(debug=False, port=5000)
