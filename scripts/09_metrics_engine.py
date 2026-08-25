#!/usr/bin/env python3
"""
Phase 9: Metrics & Analytics Engine
Author: Abett Reddy Cheruku | REQ54264 Interview Prep
"""

import os
import sqlite3
import json
import logging
from pathlib import Path

# --- CONFIGURATION ---
BASE_DIR = Path(os.path.expanduser("~/email-lab"))
DB_PATH = BASE_DIR / "db" / "email_hygiene.db"
LOG_PATH = BASE_DIR / "logs" / "phase9_metrics.log"
METRICS_DIR = BASE_DIR / "metrics"

METRICS_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(filename=LOG_PATH, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
logging.getLogger().addHandler(console_handler)

def generate_metrics(conn):
    cursor = conn.cursor()
    metrics = {}

    # 1. Overall Volume
    cursor.execute("SELECT COUNT(*) FROM emails")
    metrics["total_processed"] = cursor.fetchone()[0]

    # 2. Classification Breakdown
    cursor.execute("SELECT classification, COUNT(*) FROM emails GROUP BY classification")
    metrics["classifications"] = {row[0]: row[1] for row in cursor.fetchall() if row[0]}

    # 3. Authentication Failures
    cursor.execute("SELECT COUNT(*) FROM authentication_results WHERE dmarc_result = 'FAIL'")
    metrics["dmarc_failures"] = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM authentication_results WHERE spf_result IN ('FAIL', 'SOFTFAIL')")
    metrics["spf_failures"] = cursor.fetchone()[0]

    # 4. Top 5 Malicious Domains
    cursor.execute('''
        SELECT h.from_domain, COUNT(*) as count FROM email_headers h
        JOIN emails e ON h.email_id = e.email_id
        WHERE e.risk_score >= 60 AND h.from_domain != ''
        GROUP BY h.from_domain ORDER BY count DESC LIMIT 5
    ''')
    metrics["top_malicious_domains"] = [{"domain": row[0], "count": row[1]} for row in cursor.fetchall()]

    # 5. Save to JSON
    json_path = METRICS_DIR / "metrics_summary.json"
    with open(json_path, "w") as f:
        json.dump(metrics, f, indent=4)
        
    # 6. Save to Markdown
    md_path = METRICS_DIR / "metrics_summary.md"
    with open(md_path, "w") as f:
        f.write("# Email Hygiene Operations - Metrics Summary\n\n")
        f.write(f"**Total Processed:** {metrics['total_processed']}\n\n")
        f.write("### Classifications\n")
        for cls, count in metrics["classifications"].items():
            f.write(f"- **{cls}**: {count}\n")
        f.write(f"\n### Authentication Failures\n")
        f.write(f"- **DMARC Failures**: {metrics['dmarc_failures']}\n")
        f.write(f"- **SPF Failures/Softfails**: {metrics['spf_failures']}\n")

    logging.info(f"Metrics generated successfully at {json_path} and {md_path}")

if __name__ == "__main__":
    logging.info("Starting Phase 9: Metrics Engine...")
    db_conn = sqlite3.connect(DB_PATH)
    generate_metrics(db_conn)
    db_conn.close()
