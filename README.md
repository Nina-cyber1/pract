# Microsoft 365 Log Analysis Internship Project

**Author:** [Nina]  
**Internship Term:** Summer 2025   
**Organization:** [LMG]

---
# Microsoft 365 Audit Log Analysis Tool

This project analyzes Microsoft 365 audit log data to extract user login events, detect failed login attempts, and identify suspicious IP addresses based on excessive failures.

## 🔍 What It Does

- Parses a unified audit log CSV from Microsoft 365.
- Extracts key fields like user ID, timestamp, login result, IP address, and user agent.
- Separates successful and failed login attempts.
- Flags suspicious failed logins from IPs with more than 3 failures.
- Outputs:
  - `successful_logins.csv`
  - `failed_logins.csv`
  - `suspicious_failed_logins.csv`
  - A printed summary of suspicious user activity
---

##  Tools & Technologies

- **Python 3.x**
- `pandas` for data manipulation
- `datetime`, `re`, and other standard libraries
- Sample logs from Microsoft 365 (CSV format)
- Optional: `Jupyter Notebook` for interactive exploration

---
Place your Microsoft 365 audit log CSV file in the root of this project folder.
my file name is: 20200604_unified_auditlogs.csv

> ⚠️ Note: This CSV must be exported from the Microsoft Purview Audit portal and contain a column called `AuditData` with JSON strings.

---



### 1. Install Python 

Make sure Python and `pip` are installed.

### 2. Install required libraries


```bash
pip install -r requirements.txt

