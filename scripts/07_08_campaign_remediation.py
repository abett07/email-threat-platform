#!/usr/bin/env python3
"""
Phase 7 & 8: Campaign Correlation, IOC Extraction, and Remediation Simulation
Author: Abett Reddy Cheruku | REQ54264 Interview Prep
"""

import os
import sqlite3
import logging
import csv
from pathlib import Path

# --- CONFIGURATION ---
BASE_DIR = Path(os.path.expanduser("~/email-lab"))
DB_PATH = BASE_DIR / "db" / "email_hygiene.db"
LOG_PATH = BASE_DIR / "logs" / "phase7_8_remediation.log"
IOC_DIR = BASE_DIR / "iocs"
REPORTS_DIR = BASE_DIR / "reports"

# Ensure output directories exist
IOC_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# --- LOGGING SETUP ---
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
logging.getLogger().addHandler(console_handler)

def generate_iocs(conn):
    """Extract High-Confidence IOCs for blocking."""
    cursor = conn.cursor()
    logging.info("Extracting Malicious IOCs...")

    # 1. Malicious Senders
    cursor.execute('''
        SELECT DISTINCT h.from_address FROM email_headers h
        JOIN emails e ON h.email_id = e.email_id
        WHERE e.risk_score >= 80 AND h.from_address IS NOT NULL AND h.from_address != ''
    ''')
    with open(IOC_DIR / "malicious_senders.txt", "w") as f:
        for (sender,) in cursor.fetchall():
            f.write(f"{sender.replace('@', '[at]')}\n")

    # 2. Malicious Domains
    cursor.execute('''
        SELECT DISTINCT h.from_domain FROM email_headers h
        JOIN emails e ON h.email_id = e.email_id
        WHERE e.risk_score >= 80 AND h.from_domain IS NOT NULL AND h.from_domain != ''
    ''')
    with open(IOC_DIR / "malicious_domains.txt", "w") as f:
        for (domain,) in cursor.fetchall():
            f.write(f"{domain.replace('.', '[.]')}\n")

    # 3. Malicious URLs
    cursor.execute('''
        SELECT DISTINCT u.defanged_url FROM urls u
        JOIN emails e ON u.email_id = e.email_id
        WHERE e.risk_score >= 60 AND u.defanged_url IS NOT NULL
    ''')
    with open(IOC_DIR / "malicious_urls.txt", "w") as f:
        for (url,) in cursor.fetchall():
            f.write(f"{url}\n")

    # 4. Malicious Attachment Hashes
    cursor.execute('''
        SELECT DISTINCT a.sha256_hash FROM attachments a
        JOIN detections d ON a.attachment_id = d.attachment_id
        WHERE d.severity = 'HIGH'
    ''')
    with open(IOC_DIR / "malicious_hashes.txt", "w") as f:
        for (hash_val,) in cursor.fetchall():
            f.write(f"{hash_val}\n")
            
    logging.info("IOC extraction complete. Files saved to iocs/ directory.")

def simulate_remediation_and_campaigns(conn):
    """Generate Disposition Report and Detect Campaigns."""
    cursor = conn.cursor()
    logging.info("Generating Remediation Report and correlating campaigns...")

    # Fetch all scored emails
    cursor.execute('''
        SELECT e.email_id, e.filename, h.from_address, h.from_domain, h.subject, 
               e.classification, e.risk_score, e.risk_explanation
        FROM emails e
        LEFT JOIN email_headers h ON e.email_id = h.email_id
        WHERE e.scoring_status = 'COMPLETED'
        ORDER BY e.risk_score DESC
    ''')
    
    scored_emails = cursor.fetchall()
    
    # 1. Write Remediation CSV
    csv_path = REPORTS_DIR / "remediation_report.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Email ID", "Filename", "Sender", "Subject", "Classification", "Risk Score", "Disposition", "Reason"])
        
        for row in scored_emails:
            email_id, filename, sender, domain, subject, classification, score, explanation = row
            
            # Simulated Disposition Logic
            if score >= 80:
                disposition = "BLOCK / PURGE"
            elif score >= 60:
                disposition = "QUARANTINE"
            elif score >= 40:
                disposition = "MONITOR / ESCALATE"
            else:
                disposition = "RELEASE"
                
            writer.writerow([email_id, filename, sender, subject, classification, score, disposition, explanation.replace('\n', '; ') if explanation else ""])

    logging.info(f"Remediation report generated at {csv_path}")

    # 2. Campaign Correlation (Group by Domain for High Risk)
    cursor.execute('''
        SELECT h.from_domain, COUNT(e.email_id) as volume, AVG(e.risk_score) as avg_score, 
               GROUP_CONCAT(DISTINCT e.classification) as classifications
        FROM email_headers h
        JOIN emails e ON h.email_id = e.email_id
        WHERE e.risk_score >= 60 AND h.from_domain != ''
        GROUP BY h.from_domain
        HAVING volume >= 3
        ORDER BY volume DESC
        LIMIT 15
    ''')
    
    campaigns = cursor.fetchall()
    campaign_path = REPORTS_DIR / "campaign_summary.txt"
    
    with open(campaign_path, "w") as f:
        f.write("=== TOP THREAT CAMPAIGNS DETECTED ===\n")
        f.write("Criteria: 3+ malicious/phishing emails from the same domain.\n\n")
        
        for domain, volume, avg_score, classifications in campaigns:
            f.write(f"Campaign Domain : {domain.replace('.', '[.]')}\n")
            f.write(f"Message Volume  : {volume}\n")
            f.write(f"Average Risk    : {avg_score:.1f}\n")
            f.write(f"Classifications : {classifications}\n")
            f.write("-" * 40 + "\n")

    logging.info(f"Campaign correlation complete. Summary saved to {campaign_path}")

if __name__ == "__main__":
    logging.info("Starting Phase 7 & 8: Campaign & Remediation Engine...")
    db_conn = sqlite3.connect(DB_PATH)
    generate_iocs(db_conn)
    simulate_remediation_and_campaigns(db_conn)
    db_conn.close()
    logging.info("Phases 7 & 8 Completed Successfully.")
