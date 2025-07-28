# Microsoft 365 Log Analysis Internship Project

**Author:** Nina Liu  
**Internship Term:** Summer 2025  
**Organization:** LMG  

---

## Project Overview

This project analyzes Microsoft 365 Unified Audit Log data to:

- Extract login events  
- Detect failed login attempts  
- Identify suspicious IP addresses with more than 3 failures  
- Generate readable reports for investigation  

---

## Tools & Technologies

- Python 3.x  
- pandas  
- Standard libraries: datetime, re, json, etc.  
- (Optional) LaTeX for report generation  
- Sample Microsoft 365 Unified Audit Log (CSV format)  

---

## Input File

Place your Microsoft 365 audit log CSV file in the root of the project.  

**Example filename:** `20200604_unified_auditlogs.csv`

>  Note: The CSV must be exported from Microsoft Purview and contain a column called `AuditData` with JSON-formatted strings.

---

## Installation

Make sure Python 3 and pip are installed. Then run:

```bash
pip install -r requirements.txt

---

## Run the Script

Run the analysis with this command:

```bash
python3 m365_parser.py 20200604_unified_auditlogs.csv

