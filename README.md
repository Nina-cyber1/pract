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

> Note: The CSV must be exported from Microsoft Purview and contain a column called `AuditData` with JSON-formatted strings.

---

## Prerequisites

You need **Python 3** installed.

You also need to install required Python libraries. On most systems, you can run:

```bash
pip install -r requirements.txt
pip install matplotlib


## How to run the analysis

1. Clone the repository and enter the folder:

git clone https://github.com/Nina-cyber1/pract.git
cd pract

Place your Microsoft 365 audit log CSV file in this folder.

The file should be exported from Microsoft Purview and contain a column named `AuditData` with JSON-formatted strings.

Example filename:20200604_unified_auditlogs.csv


Run the main analysis script:python3 m365_parser.py
