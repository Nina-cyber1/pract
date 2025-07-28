# Microsoft 365 Log Analysis Internship Project

**Author:** [Nina]  
**Internship Term:** Summer 2025   
**Organization:** [LMG]

---

##  Project Overview

This project focuses on analyzing Microsoft 365 audit log data to identify and summarize key user and system activities. The goal is to provide clear, human-readable reports that can support security investigations and compliance monitoring. 

Key areas of focus include:

- User authentication events (successful and failed logins)
- MFA registration and setting changes
- Mail forwarding rules (auto-forwarding and potential exfiltration)
- Mailbox and file access logs
- File downloads and sharing events
- Administrative actions

---

##  Tools & Technologies

- **Python 3.x**
- `pandas` for data manipulation
- `datetime`, `re`, and other standard libraries
- Sample logs from Microsoft 365 (CSV format)
- Optional: `Jupyter Notebook` for interactive exploration

---

## 📁Project Structure
m365-log-analysis/
├── data/ # Sample or anonymized log files
├── scripts/ # Python scripts for parsing and analysis
│ └── log_parser.py # Main script to parse and summarize logs
├── outputs/ # Output reports (e.g., CSVs or JSON)
├── README.md # Project documentation
├── requirements.txt # Python dependencies
└── .gitignore # Ignored files/folders
