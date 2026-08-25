#!/usr/bin/env python3
"""
Phase 3: URL & Attachment Extraction Engine
Author: Abett Reddy Cheruku | REQ54264 Interview Prep
"""

import os
import sqlite3
import logging
import email
from email import policy
import re
import hashlib
from pathlib import Path
from bs4 import BeautifulSoup
import tldextract

# --- CONFIGURATION ---
BASE_DIR = Path(os.path.expanduser("~/email-lab"))
DB_PATH = BASE_DIR / "db" / "email_hygiene.db"
LOG_PATH = BASE_DIR / "logs" / "phase3_extractor.log"
ATTACHMENTS_DIR = BASE_DIR / "extracted" / "attachments"

# Ensure extraction directory exists
ATTACHMENTS_DIR.mkdir(parents=True, exist_ok=True)

# --- LOGGING SETUP ---
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
logging.getLogger().addHandler(console_handler)

URL_REGEX = re.compile(r'https?://[^\s<>"\']+|$')
IP_REGEX = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')

def init_phase3_schema(cursor):
    """Extend database schema for Phase 3."""
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS urls (
            url_id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_id INTEGER,
            original_url TEXT,
            defanged_url TEXT,
            domain TEXT,
            subdomain TEXT,
            is_ip_based BOOLEAN,
            FOREIGN KEY(email_id) REFERENCES emails(email_id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attachments (
            attachment_id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_id INTEGER,
            original_filename TEXT,
            sanitized_filename TEXT,
            file_extension TEXT,
            mime_type TEXT,
            file_size_bytes INTEGER,
            sha256_hash TEXT,
            md5_hash TEXT,
            extracted_path TEXT,
            FOREIGN KEY(email_id) REFERENCES emails(email_id)
        )
    ''')

    cursor.execute('CREATE INDEX IF NOT EXISTS idx_url_domain ON urls(domain)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_att_sha256 ON attachments(sha256_hash)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_url_email_id ON urls(email_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_att_email_id ON attachments(email_id)')

def sanitize_filename(filename):
    """Remove path traversal characters and weird symbols."""
    if not filename:
        return "unnamed_attachment.bin"
    # Keep only alphanumeric, dots, dashes, and underscores
    sanitized = re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)
    return sanitized

def defang_url(url):
    """Safely defang a URL."""
    return url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")

def process_email_body(msg, email_id, cursor):
    """Extract URLs from the email body."""
    urls_found = set() # Use a set to deduplicate URLs per email
    
    for part in msg.walk():
        content_type = part.get_content_type()
        
        # We only care about text/plain and text/html for URL extraction
        if content_type in ['text/plain', 'text/html'] and not part.is_multipart():
            try:
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                
                body_text = payload.decode(errors='ignore')
                
                # If HTML, use BeautifulSoup to find hrefs cleanly
                if content_type == 'text/html':
                    soup = BeautifulSoup(body_text, 'html.parser')
                    for a_tag in soup.find_all('a', href=True):
                        href = a_tag['href'].strip()
                        if href.startswith('http'):
                            urls_found.add(href)
                            
                # Regex fallback for plain text and missed HTML links
                found_links = re.findall(r'https?://[^\s<>"\']+', body_text)
                urls_found.update(found_links)
                
            except Exception as e:
                logging.debug(f"Error parsing body part for email {email_id}: {e}")

    # Process and insert unique URLs
    for url in urls_found:
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        subdomain = ext.subdomain
        is_ip = bool(IP_REGEX.match(domain))
        defanged = defang_url(url)
        
        cursor.execute('''
            INSERT INTO urls (email_id, original_url, defanged_url, domain, subdomain, is_ip_based)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (email_id, url, defanged, domain, subdomain, is_ip))

def process_attachments(msg, email_id, cursor):
    """Extract and hash attachments."""
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if part.get('Content-Disposition') is None and not part.get_filename():
            continue
            
        filename = part.get_filename()
        sanitized_name = sanitize_filename(filename)
        
        # Extract file extension
        _, ext = os.path.splitext(sanitized_name)
        file_extension = ext.lower().replace('.', '') if ext else 'unknown'
        mime_type = part.get_content_type()
        
        payload = part.get_payload(decode=True)
        if not payload:
            continue
            
        file_size = len(payload)
        sha256_hash = hashlib.sha256(payload).hexdigest()
        md5_hash = hashlib.md5(payload).hexdigest()
        
        # Save securely to disk prefixing with email_id to prevent overwrite
        safe_disk_name = f"{email_id}_{sanitized_name}"
        save_path = ATTACHMENTS_DIR / safe_disk_name
        
        try:
            with open(save_path, 'wb') as f:
                f.write(payload)
                
            cursor.execute('''
                INSERT INTO attachments (
                    email_id, original_filename, sanitized_filename, file_extension, 
                    mime_type, file_size_bytes, sha256_hash, md5_hash, extracted_path
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (email_id, filename, sanitized_name, file_extension, mime_type, 
                  file_size, sha256_hash, md5_hash, str(save_path)))
                  
        except Exception as e:
            logging.error(f"Failed to write attachment {sanitized_name} for email {email_id}: {e}")

def run_extraction(conn):
    cursor = conn.cursor()
    
    # Select emails that haven't had their URLs/Attachments extracted yet
    # We check if they exist in the DB but aren't in the urls or attachments tables yet.
    # To keep it simple and stateless, we track extraction status in the emails table
    
    try:
        cursor.execute("ALTER TABLE emails ADD COLUMN extraction_status TEXT DEFAULT 'PENDING'")
    except sqlite3.OperationalError:
        pass # Column already exists
        
    cursor.execute('''
        SELECT email_id, filepath 
        FROM emails 
        WHERE status = 'INGESTED' AND (extraction_status = 'PENDING' OR extraction_status IS NULL)
    ''')
    
    pending_emails = cursor.fetchall()
    total = len(pending_emails)
    logging.info(f"Found {total} emails pending URL and Attachment extraction.")

    count = 0
    for email_id, filepath in pending_emails:
        try:
            with open(filepath, "rb") as f:
                msg = email.message_from_binary_file(f, policy=policy.default)
                
            process_email_body(msg, email_id, cursor)
            process_attachments(msg, email_id, cursor)
            
            cursor.execute("UPDATE emails SET extraction_status = 'COMPLETED' WHERE email_id = ?", (email_id,))
            
            count += 1
            if count % 250 == 0:
                conn.commit()
                logging.info(f"Extracted URLs and Attachments for {count}/{total} emails...")

        except Exception as e:
            logging.error(f"Failed extraction on Email ID {email_id}: {e}")
            cursor.execute("UPDATE emails SET extraction_status = 'FAILED' WHERE email_id = ?", (email_id,))

    conn.commit()
    logging.info(f"--- PHASE 3 COMPLETE: Extracted payloads for {count} emails. ---")

if __name__ == "__main__":
    logging.info("Starting Phase 3: URL & Attachment Extractor...")
    conn = sqlite3.connect(DB_PATH)
    init_phase3_schema(conn.cursor())
    conn.commit()
    run_extraction(conn)
    conn.close()
