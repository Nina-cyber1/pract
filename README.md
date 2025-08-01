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
- matplotlib (for plotting)
- `tabulate` (for clean table output)
- (Optional) LaTeX for report generation  
- Sample Microsoft 365 Unified Audit Log (CSV format)  

---

## Input File

Place your Microsoft 365 audit log CSV file in the root of the project.

**Example filename:** `20200604_unified_auditlogs.csv`

> Note: The CSV must be exported from Microsoft Purview and contain a column called `AuditData` with JSON-formatted strings.

---
## Running it

Clone the repository and enter the project folder:

```bash
git clone https://github.com/Nina-cyber1/pract.git
cd pract
```
Copy your Microsoft 365 audit log CSV file into the pract folder.

The file must contain a column named AuditData with JSON strings.

Example file: 20200604_unified_auditlogs.csv

(Optional but recommended) Create and activate a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
```

Install required Python packages:
```bash
pip install pandas matplotlib tabulate
```

If your repo includes a requirements.txt, run:
```bash
pip install -r requirements.txt
```

Run the analysis script:
```bash
python3 m365_parser.py
```

## Prerequisites

Make sure you have **Python 3** installed.

Install required Python libraries by running:

```bash
pip install -r requirements.txt
```

## Output
This code generates suspicious users, successful and failed logins, and a bar graph

Additional notes:

If you want to build the LaTeX report, you can run:
```bash

pdflatex report.tex
```
# Microsoft 365 Audit Log Parser (cont) and Table

This Python script parses Microsoft 365 Unified Audit Log CSV exports and outputs human-readable CSVs to investigate:
Follow the same steps and you may run the script with the CSV file as so: 
```bash
python3 m365_parser_table.py 20200604_unified_auditlogs.csv
python3 m365_parser_cont.py 20200604_unified_auditlogs.csv
```
- User logins (success/failure)
- Suspicious IPs
- Mail forwarding rules
- File access and downloads
- MFA-related changes
- A human-readable table showing the results
