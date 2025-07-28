
Microsoft 365 Log Analysis Internship Project
Author: Nina Liu
Internship Term: Summer 2025
Organization: LMG

 Project Overview
This project analyzes Microsoft 365 Unified Audit Log data to:

Extract login events

Detect failed login attempts

Identify suspicious IP addresses with more than 3 failures

Generate readable reports for investigation

 Tools & Technologies
Python 3.x

pandas

Standard libraries: datetime, re, json, etc.

(Optional) LaTeX for report generation

Sample Microsoft 365 Unified Audit Log (CSV format)

 Input File
Place your Microsoft 365 audit log CSV file in the root of the project.

Example filename:

Copy
Edit
20200604_unified_auditlogs.csv
 Note: The CSV must be exported from Microsoft Purview and contain a column called AuditData with JSON-formatted strings.

 Installation
Make sure Python 3 and pip are installed. Then run:

bash
Copy
Edit
pip install -r requirements.txt
Run the Script
To execute the analysis script:

bash
Copy
Edit
python3 m365_parser.py 20200604_unified_auditlogs.csv
 Output Files Generated
These files will be saved in the current working directory:

successful_logins.csv – All successful login attempts

failed_logins.csv – All failed login attempts

suspicious_failed_logins.csv – Failed logins with >3 attempts from same IP

summary.txt – Summary of findings printed by the script
