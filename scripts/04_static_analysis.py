#!/usr/bin/env python3
"""
Phase 4: Static File Analysis Engine (ClamAV, YARA, OLEVBA)
Author: Abett Reddy Cheruku | REQ54264 Interview Prep
"""

import os
import sqlite3
import logging
import subprocess
import tempfile
import yara
from pathlib import Path
from oletools.olevba import VBA_Parser

# --- CONFIGURATION ---
BASE_DIR = Path(os.path.expanduser("~/email-lab"))
DB_PATH = BASE_DIR / "db" / "email_hygiene.db"
LOG_PATH = BASE_DIR / "logs" / "phase4_analysis.log"
YARA_RULES_PATH = BASE_DIR / "yara_rules" / "basic_rules.yar"

# --- LOGGING SETUP ---
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
logging.getLogger().addHandler(console_handler)

def init_phase4_schema(cursor):
    """Extend database schema for Phase 4."""
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS detections (
            detection_id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_id INTEGER,
            attachment_id INTEGER,
            engine TEXT,
            detection_name TEXT,
            severity TEXT,
            FOREIGN KEY(email_id) REFERENCES emails(email_id),
            FOREIGN KEY(attachment_id) REFERENCES attachments(attachment_id)
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_det_email_id ON detections(email_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_det_engine ON detections(engine)')

def run_clamav_bulk(file_paths):
    """Scan a list of files with ClamAV in a single execution."""
    results = {}
    if not file_paths:
        return results

    # Write paths to a temporary file for clamscan
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
        for path in file_paths:
            tmp.write(f"{path}\n")
        tmp_path = tmp.name

    try:
        logging.info(f"Running bulk ClamAV scan on {len(file_paths)} files. This will take a moment to load signatures...")
        # -i only outputs infected files, --no-summary skips the footer
        cmd = ['clamscan', '-i', '--no-summary', '-f', tmp_path]
        proc = subprocess.run(cmd, capture_output=True, text=True)

        # Parse the output (e.g., "/path/to/file: Win.Trojan.Gamarue FOUND")
        for line in proc.stdout.splitlines():
            if " FOUND" in line:
                parts = line.split(': ')
                if len(parts) >= 2:
                    filepath = parts[0]
                    detection = parts[1].replace(' FOUND', '').strip()
                    results[filepath] = detection
    except Exception as e:
        logging.error(f"Bulk ClamAV scan failed: {e}")
    finally:
        os.remove(tmp_path)

    return results

def analyze_attachments(conn):
    cursor = conn.cursor()

    try:
        cursor.execute("ALTER TABLE attachments ADD COLUMN analysis_status TEXT DEFAULT 'PENDING'")
    except sqlite3.OperationalError:
        pass

    # Compile YARA rules once into memory
    try:
        compiled_rules = yara.compile(filepath=str(YARA_RULES_PATH))
    except Exception as e:
        logging.error(f"Failed to compile YARA rules: {e}")
        return

    # Fetch attachments that need analysis
    cursor.execute('''
        SELECT attachment_id, email_id, extracted_path, file_extension
        FROM attachments
        WHERE analysis_status = 'PENDING' OR analysis_status IS NULL
    ''')

    pending_attachments = cursor.fetchall()
    total = len(pending_attachments)

    if total == 0:
        logging.info("No pending attachments found for analysis.")
        return

    logging.info(f"Found {total} attachments pending static analysis.")

    # Prepare batch for ClamAV
    valid_filepaths = [row[2] for row in pending_attachments if os.path.exists(row[2])]
    clamav_hits = run_clamav_bulk(valid_filepaths)

    count = 0
    detections_found = 0

    for att_id, email_id, filepath, ext in pending_attachments:
        if not os.path.exists(filepath):
            cursor.execute("UPDATE attachments SET analysis_status = 'MISSING' WHERE attachment_id = ?", (att_id,))
            continue

        try:
            # 1. ClamAV Results (O(1) Dictionary Lookup)
            if filepath in clamav_hits:
                cursor.execute('''
                    INSERT INTO detections (email_id, attachment_id, engine, detection_name, severity)
                    VALUES (?, ?, ?, ?, ?)
                ''', (email_id, att_id, 'ClamAV', clamav_hits[filepath], 'HIGH'))
                detections_found += 1

            # 2. YARA Scan (In-memory execution)
            yara_matches = compiled_rules.match(filepath)
            for match in yara_matches:
                severity = match.meta.get('severity', 'MEDIUM')
                cursor.execute('''
                    INSERT INTO detections (email_id, attachment_id, engine, detection_name, severity)
                    VALUES (?, ?, ?, ?, ?)
                ''', (email_id, att_id, 'YARA', match.rule, severity))
                detections_found += 1

            # 3. OLEVBA Scan (Targeted execution)
            office_exts = ['doc', 'xls', 'ppt', 'docm', 'xlsm', 'pptm', 'docx', 'xlsx', 'pptx', 'rtf']
            if ext.lower() in office_exts:
                vbaparser = VBA_Parser(filepath)
                if vbaparser.detect_vba_macros():
                    results = vbaparser.analyze_macros()
                    for kw_type, keyword, description in results:
                        if kw_type in ('Suspicious', 'AutoExec'):
                            cursor.execute('''
                                INSERT INTO detections (email_id, attachment_id, engine, detection_name, severity)
                                VALUES (?, ?, ?, ?, ?)
                            ''', (email_id, att_id, 'OLEVBA', f"{kw_type}: {keyword}", 'HIGH' if kw_type == 'AutoExec' else 'MEDIUM'))
                            detections_found += 1
                vbaparser.close()

            # Mark as completed
            cursor.execute("UPDATE attachments SET analysis_status = 'COMPLETED' WHERE attachment_id = ?", (att_id,))
            count += 1

            if count % 250 == 0:
                conn.commit()
                logging.info(f"Analyzed {count}/{total} attachments. Detections so far: {detections_found}")

        except Exception as e:
            logging.error(f"Analysis failed on attachment {att_id}: {e}")
            cursor.execute("UPDATE attachments SET analysis_status = 'FAILED' WHERE attachment_id = ?", (att_id,))

    conn.commit()
    logging.info(f"--- PHASE 4 COMPLETE: Analyzed {count} attachments. Total Detections: {detections_found} ---")

if __name__ == "__main__":
    logging.info("Starting Phase 4: Static File Analysis...")
    conn = sqlite3.connect(DB_PATH)
    init_phase4_schema(conn.cursor())
    conn.commit()
    analyze_attachments(conn)
    conn.close()
