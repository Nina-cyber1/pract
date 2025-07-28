# Microsoft 365 Log Analysis Internship Project

**Author**: Nina Liu  
**Internship Term**: Summer 2025  
**Organization**: LMG  

---

## Project Overview

This project analyzes Microsoft 365 Unified Audit Log data to:
- Extract login events
- Detect failed login attempts
- Identify suspicious IP addresses with more than 3 failures
- Generate readable reports for investigation

---

##  Tools & Technologies

- Python 3.x
- pandas
- datetime, re, and other standard libraries
- LaTeX (for PDF report)
- Sample CSV logs from Microsoft 365

---

## Input File

Place your Microsoft 365 audit log CSV file in the root of the project.  
**Example file**: `20200604_unified_auditlogs.csv`

> **Note**: This CSV must be exported from Microsoft Purview and contain a column called `AuditData` with JSON-formatted strings.

---

##  Installation

Make sure you have Python 3 and pip installed. Then run:

```bash
pip install -r requirements.txt

## Run the Script

```bash
python3 m365_parser.py 20200604_unified_auditlogs.csv

3. Output Files Generated
successful_logins.csv

failed_logins.csv

suspicious_failed_logins.csv

summary.txt

These files will be saved in the current working directory.
