#!/usr/bin/env python3
"""
Phase 1: Email Ingestion and Database Initialization Engine
Author: Abett Reddy Cheruku | REQ54264 Interview Prep
"""

import os
import hashlib
import sqlite3
import logging
from pathlib import Path
from datetime import datetime

# --- CONFIGURATION ---
BASE_DIR = Path(os.path.expanduser("~/email-lab"))
RAW_DIR = BASE_DIR / "raw"
DB_PATH = BASE_DIR / "db" / "email_hygiene.db"
LOG_PATH = BASE_DIR / "logs" / "ingestion.log"

# --- LOGGING SETUP ---
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
logging.getLogger().addHandler(console_handler)

def init_db():
    """Initialize the SQLite database and core schema."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create the primary emails table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS emails (
            email_id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT UNIQUE,
            filepath TEXT,
            file_size_bytes INTEGER,
            sha256_hash TEXT UNIQUE,
            processed_at TIMESTAMP,
            status TEXT,
            error_message TEXT
        )
    ''')
    
    # Create indexes for fast lookup
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_sha256 ON emails(sha256_hash)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_status ON emails(status)')
    
    conn.commit()
    return conn

def calculate_sha256(filepath):
    """Safely calculate the SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        logging.error(f"Failed to hash {filepath}: {e}")
        return None

def ingest_samples(conn):
    """Iterate through the raw directory and ingest .eml files."""
    cursor = conn.cursor()
    
    if not RAW_DIR.exists():
        logging.error(f"Raw directory not found: {RAW_DIR}")
        return

    eml_files = list(RAW_DIR.rglob("*.eml"))
    total_files = len(eml_files)
    logging.info(f"Found {total_files} .eml files for ingestion.")

    success_count = 0
    duplicate_count = 0
    error_count = 0

    for filepath in eml_files:
        filename = filepath.name
        
        # Check if already processed (Resume capability)
        cursor.execute("SELECT email_id FROM emails WHERE filename = ?", (filename,))
        if cursor.fetchone():
            duplicate_count += 1
            continue
            
        try:
            file_size = filepath.stat().st_size
            file_hash = calculate_sha256(filepath)
            
            if not file_hash:
                raise ValueError("Could not compute hash")

            cursor.execute('''
                INSERT INTO emails (filename, filepath, file_size_bytes, sha256_hash, processed_at, status, error_message)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (filename, str(filepath), file_size, file_hash, datetime.now(), "INGESTED", None))
            
            success_count += 1
            
            # Commit every 500 records to save memory/IO
            if success_count % 500 == 0:
                conn.commit()
                logging.info(f"Ingested {success_count}/{total_files} files...")

        except sqlite3.IntegrityError:
            # Hash already exists - duplicate file with different name
            logging.warning(f"Duplicate hash detected for {filename}. Skipping.")
            duplicate_count += 1
        except Exception as e:
            logging.error(f"Error processing {filename}: {str(e)}")
            cursor.execute('''
                INSERT INTO emails (filename, filepath, processed_at, status, error_message)
                VALUES (?, ?, ?, ?, ?)
            ''', (filename, str(filepath), datetime.now(), "FAILED", str(e)))
            error_count += 1

    conn.commit()
    logging.info("--- INGESTION COMPLETE ---")
    logging.info(f"Successfully Ingested: {success_count}")
    logging.info(f"Duplicates Skipped:  {duplicate_count}")
    logging.info(f"Failed:              {error_count}")

if __name__ == "__main__":
    logging.info("Starting Hygiene-Ops Ingestion Engine...")
    db_conn = init_db()
    ingest_samples(db_conn)
    db_conn.close()
