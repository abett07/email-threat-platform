#!/usr/bin/env python3
"""
Phase 6: Explainable Risk Scoring & Classification Engine
Author: Abett Reddy Cheruku | REQ54264 Interview Prep
"""

import os
import sqlite3
import logging
from pathlib import Path

# --- CONFIGURATION ---
BASE_DIR = Path(os.path.expanduser("~/email-lab"))
DB_PATH = BASE_DIR / "db" / "email_hygiene.db"
LOG_PATH = BASE_DIR / "logs" / "phase6_scoring.log"

# --- LOGGING SETUP ---
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
logging.getLogger().addHandler(console_handler)

def init_phase6_schema(cursor):
    """Add scoring columns to the emails table."""
    try:
        cursor.execute("ALTER TABLE emails ADD COLUMN risk_score INTEGER DEFAULT 0")
        cursor.execute("ALTER TABLE emails ADD COLUMN classification TEXT DEFAULT 'UNKNOWN'")
        cursor.execute("ALTER TABLE emails ADD COLUMN risk_explanation TEXT")
        cursor.execute("ALTER TABLE emails ADD COLUMN tags TEXT")
        cursor.execute("ALTER TABLE emails ADD COLUMN scoring_status TEXT DEFAULT 'PENDING'")
    except sqlite3.OperationalError:
        pass  # Columns already exist

def score_and_classify(conn):
    cursor = conn.cursor()
    
    # Fetch all ingested emails that haven't been scored
    cursor.execute('''
        SELECT email_id FROM emails 
        WHERE status = 'INGESTED' AND (scoring_status = 'PENDING' OR scoring_status IS NULL)
    ''')
    
    pending_emails = cursor.fetchall()
    total = len(pending_emails)
    
    if total == 0:
        logging.info("No emails pending risk scoring.")
        return

    logging.info(f"Found {total} emails for risk scoring.")
    count = 0

    for (email_id,) in pending_emails:
        score = 0
        reasons = []
        tags = set()
        
        # --- 1. Evaluate Authentication ---
        cursor.execute('SELECT spf_result, dkim_result, dmarc_result FROM authentication_results WHERE email_id = ?', (email_id,))
        auth = cursor.fetchone()
        if auth:
            spf, dkim, dmarc = auth
            if dmarc == 'FAIL':
                score += 20
                reasons.append("+20 DMARC failure")
                tags.add("DMARC_FAIL")
            if spf in ['FAIL', 'SOFTFAIL']:
                score += 10
                reasons.append(f"+10 SPF {spf.lower()}")
                tags.add("SPF_FAIL")
            if dkim == 'FAIL':
                score += 10
                reasons.append("+10 DKIM failure")
                tags.add("DKIM_FAIL")

        # --- 2. Evaluate Header Mismatches ---
        cursor.execute('SELECT is_mismatch FROM email_headers WHERE email_id = ?', (email_id,))
        headers = cursor.fetchone()
        if headers and headers[0]:  # is_mismatch is True
            score += 15
            reasons.append("+15 Reply-To / Return-Path mismatch")
            tags.add("HEADER_ANOMALY")

        # --- 3. Evaluate Detections (ClamAV, YARA, OLEVBA, Heuristics) ---
        cursor.execute('SELECT engine, detection_name, severity FROM detections WHERE email_id = ?', (email_id,))
        detections = cursor.fetchall()
        
        has_malware = False
        has_bec = False
        has_phish = False
        
        for engine, name, severity in detections:
            if engine == 'ClamAV':
                score += 50
                reasons.append(f"+50 Known Malware Signature ({name})")
                tags.add("MALWARE")
                has_malware = True
            elif engine == 'YARA':
                score += 30
                reasons.append(f"+30 Suspicious File Pattern ({name})")
                tags.add("SUSPICIOUS_ATTACHMENT")
            elif engine == 'OLEVBA':
                score += 40
                reasons.append(f"+40 Malicious Macro ({name})")
                tags.add("MALWARE_MACRO")
                has_malware = True
            elif engine == 'Heuristics':
                if 'Brand Impersonation' in name:
                    score += 25
                    reasons.append(f"+25 {name}")
                    tags.add("BRAND_IMPERSONATION")
                elif 'Credential' in name:
                    score += 20
                    reasons.append(f"+20 {name}")
                    tags.add("CREDENTIAL_THEFT")
                    has_phish = True
                elif 'BEC' in name:
                    score += 20
                    reasons.append(f"+20 {name}")
                    tags.add("FINANCIAL_LURE")
                    has_bec = True
                elif 'IP-Based URL' in name:
                    score += 20
                    reasons.append("+20 IP-based URL detected")
                    tags.add("SUSPICIOUS_URL")
                elif 'URL Shortener' in name:
                    score += 10
                    reasons.append("+10 Suspicious URL shortener")
                    tags.add("OBFUSCATED_URL")

        # --- 4. Determine Primary Classification ---
        if has_malware or score >= 80:
            classification = "MALICIOUS"
        elif has_phish or (score >= 60 and score < 80):
            classification = "PHISHING"
        elif has_bec:
            classification = "POTENTIAL_BEC"
        elif score >= 40 and score < 60:
            classification = "SUSPICIOUS"
        elif score >= 20 and score < 40:
            classification = "LOW_RISK"
        else:
            classification = "BENIGN"

        # Overwrite with MALWARE if AV specifically triggered it
        if has_malware:
            classification = "MALWARE"

        explanation_str = "\n".join(reasons) if reasons else "No suspicious indicators found."
        tags_str = ",".join(list(tags))

        # --- 5. Update Database ---
        cursor.execute('''
            UPDATE emails 
            SET risk_score = ?, classification = ?, risk_explanation = ?, tags = ?, scoring_status = 'COMPLETED'
            WHERE email_id = ?
        ''', (score, classification, explanation_str, tags_str, email_id))

        count += 1
        if count % 1000 == 0:
            conn.commit()
            logging.info(f"Scored {count}/{total} emails...")

    conn.commit()
    logging.info(f"--- PHASE 6 COMPLETE: Scored and classified {count} emails. ---")

if __name__ == "__main__":
    logging.info("Starting Phase 6: Risk Scoring Engine...")
    conn = sqlite3.connect(DB_PATH)
    init_phase6_schema(conn.cursor())
    conn.commit()
    score_and_classify(conn)
    conn.close()
