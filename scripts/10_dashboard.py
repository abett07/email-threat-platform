#!/usr/bin/env python3
"""
Phase 10: Email Security SOC Dashboard
Author: Abett Reddy Cheruku | REQ54264 Interview Prep
"""

import sqlite3
import pandas as pd
import streamlit as st
from pathlib import Path
import os

# --- CONFIGURATION ---
BASE_DIR = Path(os.path.expanduser("~/email-lab"))
DB_PATH = BASE_DIR / "db" / "email_hygiene.db"

st.set_page_config(page_title="Hygiene-Ops SOC Dashboard", layout="wide", initial_sidebar_state="expanded")

@st.cache_resource
def get_db_connection():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

conn = get_db_connection()

# --- SIDEBAR NAV ---
st.sidebar.title("Hygiene-Ops Platform")
st.sidebar.markdown("### SOC Analyst Interface")
page = st.sidebar.radio("Navigation", ["Executive Metrics", "Investigation Search", "Campaign Explorer"])

# --- PAGE: EXECUTIVE METRICS ---
if page == "Executive Metrics":
    st.title("🛡️ Email Threat Landscape Overview")
    
    # KPIs
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM emails")
    total_emails = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM emails WHERE classification IN ('PHISHING', 'MALICIOUS', 'MALWARE')")
    threats = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM urls WHERE is_ip_based = 1")
    ip_urls = cursor.fetchone()[0]
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Ingested", total_emails)
    col2.metric("High-Confidence Threats", threats)
    col3.metric("IP-Based URLs Detected", ip_urls)
    
    st.markdown("---")
    
    # Classification Bar Chart
    st.subheader("Message Classifications")
    df_class = pd.read_sql_query("SELECT classification, COUNT(*) as count FROM emails GROUP BY classification", conn)
    if not df_class.empty:
        st.bar_chart(df_class.set_index("classification"))

# --- PAGE: INVESTIGATION SEARCH ---
elif page == "Investigation Search":
    st.title("🔍 Threat Investigation")
    
    search_query = st.text_input("Search by Sender Domain, Subject, or Filename:")
    
    if search_query:
        query = f"%{search_query}%"
        df_search = pd.read_sql_query('''
            SELECT e.email_id, h.from_address, h.subject, e.classification, e.risk_score 
            FROM emails e
            LEFT JOIN email_headers h ON e.email_id = h.email_id
            WHERE h.from_domain LIKE ? OR h.subject LIKE ? OR e.filename LIKE ?
            ORDER BY e.risk_score DESC LIMIT 50
        ''', conn, params=(query, query, query))
        
        st.dataframe(df_search, use_container_width=True)
        
        if not df_search.empty:
            inspect_id = st.number_input("Enter Email ID to inspect:", min_value=0, step=1)
            if inspect_id > 0:
                st.markdown("### 📄 Investigation Details")
                
                # Fetch detailed report
                details = pd.read_sql_query('''
                    SELECT e.filename, e.risk_score, e.risk_explanation, e.tags, 
                           h.from_display, h.from_address, h.reply_to_address, a.spf_result, a.dmarc_result
                    FROM emails e
                    LEFT JOIN email_headers h ON e.email_id = h.email_id
                    LEFT JOIN authentication_results a ON e.email_id = a.email_id
                    WHERE e.email_id = ?
                ''', conn, params=(inspect_id,))
                
                if not details.empty:
                    st.json(details.iloc[0].to_dict())
                    
                    # Fetch Defanged URLs
                    urls = pd.read_sql_query("SELECT defanged_url FROM urls WHERE email_id = ?", conn, params=(inspect_id,))
                    if not urls.empty:
                        st.markdown("#### 🔗 Extracted URLs")
                        st.table(urls)

# --- PAGE: CAMPAIGN EXPLORER ---
elif page == "Campaign Explorer":
    st.title("🕸️ Threat Campaign Correlation")
    st.markdown("Clusters of 3+ malicious messages originating from the same infrastructure.")
    
    df_campaigns = pd.read_sql_query('''
        SELECT h.from_domain as "Attacker Infrastructure", COUNT(e.email_id) as "Volume", 
               ROUND(AVG(e.risk_score), 1) as "Avg Risk", GROUP_CONCAT(DISTINCT e.classification) as "Tags"
        FROM email_headers h
        JOIN emails e ON h.email_id = e.email_id
        WHERE e.risk_score >= 60 AND h.from_domain != ''
        GROUP BY h.from_domain
        HAVING Volume >= 3
        ORDER BY Volume DESC
    ''', conn)
    
    st.dataframe(df_campaigns, use_container_width=True)
