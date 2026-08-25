#  Automated Email Threat Analysis Platform

**Author:** Abett Reddy Cheruku  
**Role Target:** Email Hygiene Analyst / SOC Analyst (REQ54264)  
**Environment:** Kali Linux, Python 3, SQLite, Streamlit  

## 📌 Executive Summary
Hygiene-Ops is a custom-built, automated Email Security Operations Center (SOC) platform. Designed to process and triage bulk email datasets safely, this pipeline ingested **8,609 raw honeypot `.eml` samples**, extracting security-relevant artifacts without detonating payloads. 

The platform simulates an enterprise Email Security Gateway (like Proofpoint or Abnormal Security) by parsing headers, analyzing authentication protocols (SPF/DKIM/DMARC), defanging URLs, performing static analysis on attachments (ClamAV, YARA, OLEVBA), and utilizing a custom heuristic risk-scoring engine to cluster campaigns and generate actionable blocklists.

---

## 📸 Platform Dashboard
*(A custom Streamlit UI built to serve as the SOC Analyst investigation interface)*

### Executive Threat Landscape
![Executive Dashboard](/Screenshot_2026-08-24_05-18-28.png)

### Investigation Search & Heuristic Breakdown
![Investigation Search](/Screenshot_2026-08-24_05-18-00.png)

### Threat Campaign Correlation
![Campaign Explorer](/Screenshot_2026-08-24_05-16-36.png)

---

## ⚙️ Architecture & Pipeline Phases

The platform is modular, with data flowing through a structured 10-phase pipeline into a central SQLite database.

1. **Ingestion Engine:** Recursively scans directories for `.eml` files, calculates SHA-256 hashes, deduplicates, and logs them into SQLite, preventing memory exhaustion.
2. **Header & Authentication Analyzer:** Extracts routing data (bottom-up `Received` hops) and normalizes `Authentication-Results` (SPF, DKIM, DMARC). Detects `From` vs. `Return-Path` / `Reply-To` spoofing anomalies.
3. **Payload Extractor:** Safely dumps attachments to isolated disk directories (preventing path traversal). Extracts and defangs URLs (e.g., `hxxp://evil[.]com`) from HTML/Plain text bodies using BeautifulSoup.
4. **Static Analysis Engine:** 
    * **ClamAV:** Bulk-scans attachments via optimized `--file-list` execution.
    * **YARA:** In-memory execution of custom rules targeting hidden executables and malicious document structures.
    * **OLEVBA:** Native parsing of MS Office files to detect `AutoExec` triggers and weaponized macros.
5. **Heuristic Engine:** Detects Brand Impersonation (e.g., matching Display Name "Microsoft" against unauthorized sender domains), BEC financial lures, credential harvesting keywords, and IP-based URLs.
6. **Risk Scoring & Classification:** An explainable grading system. Assigns points (+20 DMARC fail, +25 Brand Impersonation, +50 Malware) to generate a final risk score (0-100+) and primary classification (`BENIGN`, `LOW_RISK`, `SUSPICIOUS`, `POTENTIAL_BEC`, `PHISHING`, `MALICIOUS`).
7. **Campaign Correlation:** Automatically clusters 3+ malicious messages originating from the same attacker infrastructure.
8. **Remediation Simulation:** Outputs enterprise-ready Defanged IOC blocklists (`malicious_domains.txt`, `malicious_hashes.txt`) and assigns disposition actions (`RELEASE`, `QUARANTINE`, `BLOCK/PURGE`).
9. **Metrics Engine:** Aggregates database statistics into JSON/Markdown reports.
10. **SOC Dashboard:** A Streamlit web application for real-time threat hunting and analyst review.

---

## 📊 Dataset Results

* **Total Samples Processed:** 8,609
* **High-Confidence Threats Blocked:** 298
* **IP-Based URLs Detected:** 833
* **Top Malicious Campaigns Detected:** 
  * `newsletter[.]otto[.]de` (Phishing/Malicious)
  * `stegen20[.]onmicrosoft[.]com` (BEC/Phishing)
  * `vargas[.]tchalala[.]shop` (Malicious)

---

## 🛠️ Technology Stack
* **Language:** Python 3
* **Database:** SQLite3
* **Static Analysis:** ClamAV, YARA (`yara-python`), `oletools` (OLEVBA/oleid), `pdfid`
* **Data Parsing:** `email`, `bs4` (BeautifulSoup), `tldextract`
* **Visualization:** Streamlit, Pandas

---

## 🚀 Installation & Usage

**1. Clone the repository:**
```bash
git clone (https://github.com/abett07/email-threat-platform.git)
cd email-security-analysis-lab

Set up the virtual environment & dependencies:

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Execute the pipeline scripts in order
./scripts/01_ingestion_engine.py
./scripts/02_header_auth_analyzer.py
./scripts/03_extractor_engine.py
./scripts/04_static_analysis.py
./scripts/05_heuristic_engine.py
./scripts/06_risk_scoring_engine.py
./scripts/07_08_campaign_remediation.py
./scripts/09_metrics_engine.py

# Launch the SOC Dashboard
streamlit run scripts/10_dashboard.py


Safety & Legal Disclaimer
Do not execute any files in the extracted/attachments directory. This project processes live, known-bad honeypot data containing active phishing links, weaponized documents, and malware. All analysis in this repository was performed using static, non-detonating techniques within an isolated Kali Linux environment. All output IOCs have been neutralized/defanged.
