#!/usr/bin/env python3
"""
Phase 2: Header, Authentication, and Received Hop Analyzer
Author: Abett Reddy Cheruku | REQ54264 Interview Prep
"""

import os
import sqlite3
import logging
import email
from email import policy
from email.utils import parseaddr
import re
from pathlib import Path

# --- CONFIGURATION ---
BASE_DIR = Path(os.path.expanduser("~/email-lab"))
DB_PATH = BASE_DIR / "db" / "email_hygiene.db"
LOG_PATH = BASE_DIR / "logs" / "phase2_headers.log"

# --- LOGGING SETUP ---
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
logging.getLogger().addHandler(console_handler)

def init_phase2_schema(cursor):
    """Extend database schema for Phase 2."""
    
    # Headers Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS email_headers (
            email_id INTEGER PRIMARY KEY,
            subject TEXT,
            date_sent TEXT,
            message_id TEXT,
            x_originating_ip TEXT,
            x_mailer TEXT,
            user_agent TEXT,
            content_type TEXT,
            from_display TEXT,
            from_address TEXT,
            from_domain TEXT,
            reply_to_address TEXT,
            return_path_address TEXT,
            is_mismatch BOOLEAN,
            FOREIGN KEY(email_id) REFERENCES emails(email_id)
        )
    ''')
    
    # Auth Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS authentication_results (
            email_id INTEGER PRIMARY KEY,
            spf_result TEXT,
            dkim_result TEXT,
            dmarc_result TEXT,
            raw_auth_header TEXT,
            FOREIGN KEY(email_id) REFERENCES emails(email_id)
        )
    ''')

    # Received Hops Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS received_hops (
            hop_id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_id INTEGER,
            hop_index INTEGER,
            hop_data TEXT,
            FOREIGN KEY(email_id) REFERENCES emails(email_id)
        )
    ''')

    # Indexes
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_from_domain ON email_headers(from_domain)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_is_mismatch ON email_headers(is_mismatch)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_dmarc_result ON authentication_results(dmarc_result)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_spf_result ON authentication_results(spf_result)')

def parse_auth(msg):
    """Normalize SPF, DKIM, and DMARC results."""
    auth_header = str(msg.get("Authentication-Results", "")).lower()
    spf_header = str(msg.get("Received-SPF", "")).lower()

    # Normalize SPF
    if "spf=pass" in auth_header or "pass" in spf_header: spf = "PASS"
    elif "spf=fail" in auth_header or "fail" in spf_header: spf = "FAIL"
    elif "spf=softfail" in auth_header or "softfail" in spf_header: spf = "SOFTFAIL"
    elif "spf=neutral" in auth_header or "neutral" in spf_header: spf = "NEUTRAL"
    else: spf = "NONE"

    # Normalize DKIM
    if "dkim=pass" in auth_header: dkim = "PASS"
    elif "dkim=fail" in auth_header: dkim = "FAIL"
    else: dkim = "NONE"

    # Normalize DMARC
    if "dmarc=pass" in auth_header: dmarc = "PASS"
    elif "dmarc=fail" in auth_header: dmarc = "FAIL"
    else: dmarc = "NONE"

    return spf, dkim, dmarc, auth_header[:500]

def analyze_headers(conn):
    cursor = conn.cursor()
    
    # Get all successfully ingested emails that haven't been parsed yet
    cursor.execute('''
        SELECT e.email_id, e.filepath 
        FROM emails e 
        LEFT JOIN email_headers eh ON e.email_id = eh.email_id 
        WHERE e.status = 'INGESTED' AND eh.email_id IS NULL
    ''')
    
    pending_emails = cursor.fetchall()
    total = len(pending_emails)
    logging.info(f"Found {total} emails to parse for headers and auth.")

    count = 0
    for email_id, filepath in pending_emails:
        try:
            with open(filepath, "rb") as f:
                msg = email.message_from_binary_file(f, policy=policy.default)
            
            # Extract Address Information
            from_display, from_address = parseaddr(msg.get("From", ""))
            from_domain = from_address.split('@')[-1].lower() if '@' in from_address else ""
            
            _, reply_to_address = parseaddr(msg.get("Reply-To", ""))
            _, return_path_address = parseaddr(msg.get("Return-Path", ""))
            
            reply_to_address = reply_to_address.lower()
            return_path_address = return_path_address.lower()
            from_address = from_address.lower()

            # Determine Mismatch
            is_mismatch = False
            if reply_to_address and reply_to_address != from_address:
                is_mismatch = True
            if return_path_address and return_path_address != from_address:
                is_mismatch = True

            # General Headers
            subject = str(msg.get("Subject", ""))
            date_sent = str(msg.get("Date", ""))
            message_id = str(msg.get("Message-ID", ""))
            x_orig_ip = str(msg.get("X-Originating-IP", ""))
            x_mailer = str(msg.get("X-Mailer", ""))
            user_agent = str(msg.get("User-Agent", ""))
            content_type = str(msg.get("Content-Type", ""))

            # Insert Header Data
            cursor.execute('''
                INSERT INTO email_headers (
                    email_id, subject, date_sent, message_id, x_originating_ip, 
                    x_mailer, user_agent, content_type, from_display, 
                    from_address, from_domain, reply_to_address, return_path_address, is_mismatch
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (email_id, subject, date_sent, message_id, x_orig_ip, x_mailer, 
                  user_agent, content_type, from_display, from_address, from_domain, 
                  reply_to_address, return_path_address, is_mismatch))

            # Auth Data
            spf, dkim, dmarc, raw_auth = parse_auth(msg)
            cursor.execute('''
                INSERT INTO authentication_results (email_id, spf_result, dkim_result, dmarc_result, raw_auth_header)
                VALUES (?, ?, ?, ?, ?)
            ''', (email_id, spf, dkim, dmarc, raw_auth))

            # Received Hops (Traced from bottom to top)
            received_headers = msg.get_all("Received") or []
            received_headers.reverse() # Oldest/Originating hop is now index 0
            
            for index, hop in enumerate(received_headers):
                cursor.execute('''
                    INSERT INTO received_hops (email_id, hop_index, hop_data)
                    VALUES (?, ?, ?)
                ''', (email_id, index, str(hop)))

            count += 1
            if count % 500 == 0:
                conn.commit()
                logging.info(f"Processed headers for {count}/{total} emails...")

        except Exception as e:
            logging.error(f"Failed to parse headers for Email ID {email_id}: {e}")

    conn.commit()
    logging.info(f"--- PHASE 2 COMPLETE: Processed {count} emails. ---")

if __name__ == "__main__":
    logging.info("Starting Phase 2: Header & Auth Analyzer...")
    conn = sqlite3.connect(DB_PATH)
    init_phase2_schema(conn.cursor())
    conn.commit()
    analyze_headers(conn)
    conn.close()
