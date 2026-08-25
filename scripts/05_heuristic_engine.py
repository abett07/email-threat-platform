#!/usr/bin/env python3
"""
Phase 5: Phishing, BEC, and Impersonation Detection Engine
Author: Abett Reddy Cheruku | REQ54264 Interview Prep
"""

import os
import sqlite3
import logging
import re
from pathlib import Path

# --- CONFIGURATION ---
BASE_DIR = Path(os.path.expanduser("~/email-lab"))
DB_PATH = BASE_DIR / "db" / "email_hygiene.db"
LOG_PATH = BASE_DIR / "logs" / "phase5_heuristics.log"

# --- LOGGING SETUP ---
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
logging.getLogger().addHandler(console_handler)

# --- THREAT INTEL DEFINITIONS ---
# Map high-value brands to their legitimate sending domains
LEGIT_BRANDS = {
    "microsoft": ["microsoft.com", "office.com", "windows.com", "sharepoint.com", "onedrive.com"],
    "google": ["google.com", "gmail.com", "youtube.com", "workspace.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "aws.amazon.com"],
    "paypal": ["paypal.com"],
    "coinbase": ["coinbase.com"],
    "docusign": ["docusign.net", "docusign.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "chase": ["chase.com"],
    "bank of america": ["bankofamerica.com"],
    "wells fargo": ["wellsfargo.com"],
    "adobe": ["adobe.com"],
    "linkedin": ["linkedin.com"]
}

BEC_KEYWORDS = re.compile(r"(wire transfer|urgent payment|invoice|bank account|gift card|routing number|payment instructions|overdue|remittance|w-2)", re.IGNORECASE)
PHISHING_KEYWORDS = re.compile(r"(password reset|verify your account|account suspended|login|validate|unauthorized access|action required|verify identity)", re.IGNORECASE)
URL_SHORTENERS = ["bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "adf.ly"]

def analyze_heuristics(conn):
    cursor = conn.cursor()
    
    # Add status column for this phase
    try:
        cursor.execute("ALTER TABLE emails ADD COLUMN heuristic_status TEXT DEFAULT 'PENDING'")
    except sqlite3.OperationalError:
        pass

    # Fetch emails needing analysis with their headers
    cursor.execute('''
        SELECT e.email_id, h.from_display, h.from_domain, h.subject, h.is_mismatch
        FROM emails e
        JOIN email_headers h ON e.email_id = h.email_id
        WHERE e.heuristic_status = 'PENDING' OR e.heuristic_status IS NULL
    ''')
    
    pending_emails = cursor.fetchall()
    total = len(pending_emails)
    
    if total == 0:
        logging.info("No emails pending heuristic analysis.")
        return

    logging.info(f"Found {total} emails for heuristic analysis.")
    count = 0
    detections_found = 0

    for email_id, from_display, from_domain, subject, is_mismatch in pending_emails:
        try:
            from_display_lower = str(from_display).lower()
            subject_lower = str(subject).lower()
            from_domain_lower = str(from_domain).lower()
            
            # 1. Brand Impersonation Check
            for brand, legit_domains in LEGIT_BRANDS.items():
                if brand in from_display_lower or brand in subject_lower:
                    # If the brand is mentioned but the sender domain is NOT in the legit list
                    if not any(from_domain_lower.endswith(ld) for ld in legit_domains):
                        cursor.execute('''
                            INSERT INTO detections (email_id, engine, detection_name, severity)
                            VALUES (?, ?, ?, ?)
                        ''', (email_id, 'Heuristics', f'Brand Impersonation: {brand.title()}', 'HIGH'))
                        detections_found += 1

            # 2. BEC & Phishing Keyword Checks (Subject Lines)
            if BEC_KEYWORDS.search(subject_lower):
                cursor.execute('''
                    INSERT INTO detections (email_id, engine, detection_name, severity)
                    VALUES (?, ?, ?, ?)
                ''', (email_id, 'Heuristics', 'Potential BEC / Financial Lure', 'MEDIUM'))
                detections_found += 1
                
            if PHISHING_KEYWORDS.search(subject_lower):
                cursor.execute('''
                    INSERT INTO detections (email_id, engine, detection_name, severity)
                    VALUES (?, ?, ?, ?)
                ''', (email_id, 'Heuristics', 'Credential Harvesting Lure', 'MEDIUM'))
                detections_found += 1

            # 3. Header Anomalies
            if is_mismatch:
                cursor.execute('''
                    INSERT INTO detections (email_id, engine, detection_name, severity)
                    VALUES (?, ?, ?, ?)
                ''', (email_id, 'Heuristics', 'Reply-To / Return-Path Mismatch', 'MEDIUM'))
                detections_found += 1

            # 4. URL Risk Check
            cursor.execute("SELECT domain, is_ip_based FROM urls WHERE email_id = ?", (email_id,))
            urls = cursor.fetchall()
            
            for url_domain, is_ip in urls:
                if is_ip:
                    cursor.execute('''
                        INSERT INTO detections (email_id, engine, detection_name, severity)
                        VALUES (?, ?, ?, ?)
                    ''', (email_id, 'Heuristics', 'IP-Based URL Destination', 'HIGH'))
                    detections_found += 1
                
                if url_domain and url_domain.lower() in URL_SHORTENERS:
                    cursor.execute('''
                        INSERT INTO detections (email_id, engine, detection_name, severity)
                        VALUES (?, ?, ?, ?)
                    ''', (email_id, 'Heuristics', 'Suspicious URL Shortener', 'MEDIUM'))
                    detections_found += 1

            # Mark as completed
            cursor.execute("UPDATE emails SET heuristic_status = 'COMPLETED' WHERE email_id = ?", (email_id,))
            count += 1

            if count % 1000 == 0:
                conn.commit()
                logging.info(f"Analyzed {count}/{total} emails. Detections so far: {detections_found}")

        except Exception as e:
            logging.error(f"Heuristics failed on email {email_id}: {e}")
            cursor.execute("UPDATE emails SET heuristic_status = 'FAILED' WHERE email_id = ?", (email_id,))

    conn.commit()
    logging.info(f"--- PHASE 5 COMPLETE: Analyzed {count} emails. Total Heuristic Detections: {detections_found} ---")

if __name__ == "__main__":
    logging.info("Starting Phase 5: Heuristic Engine...")
    conn = sqlite3.connect(DB_PATH)
    analyze_heuristics(conn)
    conn.close()
