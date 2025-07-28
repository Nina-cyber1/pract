import pandas as pd
import json
import sys
import matplotlib.pyplot as plt
def parse_audit_json(row):
    try:
        data = json.loads(row)
        return {
            'CreationTime': data.get('CreationTime'),
            'UserId': data.get('UserId'),
            'Operation': data.get('Operation'),
            'ResultStatus': data.get('ResultStatus'),
            'ClientIP': data.get('ClientIP'),
            'UserAgent': next(
                (item['Value'] for item in data.get('ExtendedProperties', []) if item['Name'] == 'UserAgent'), 
                None
            )
        }
    except Exception:
        return None

def main():
    filename = "20200604_unified_auditlogs.csv"

    # Try loading CSV file
    try:
        df = pd.read_csv(filename, skiprows=1)
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found. Please put it in the script folder.")
        sys.exit(1)

    # Remove rows where AuditData is missing
    df = df[df['AuditData'].notna()]

    # Parse AuditData JSON
    parsed_rows = df['AuditData'].apply(parse_audit_json)
    parsed_df = pd.DataFrame(parsed_rows.tolist())

    # Drop rows that failed to parse
    parsed_df = parsed_df.dropna(subset=['Operation'])

    # Filter login events
    successful_logins = parsed_df[parsed_df['Operation'] == 'UserLoggedIn']
    failed_logins = parsed_df[parsed_df['Operation'] == 'UserLoginFailed']

    # Identify suspicious failed logins (same IP > 3 failures)
    suspicious_ips = failed_logins['ClientIP'].value_counts()
    suspicious_ips = suspicious_ips[suspicious_ips > 3].index.tolist()
    suspicious_failed_logins = failed_logins[failed_logins['ClientIP'].isin(suspicious_ips)]

    # Save results
    successful_logins.to_csv("successful_logins.csv", index=False)
    failed_logins.to_csv("failed_logins.csv", index=False)
    suspicious_failed_logins.to_csv("suspicious_failed_logins.csv", index=False)

    # Print suspicious emails with failure counts
    print("\nSuspicious email addresses and number of failed login attempts:")
    suspicious_counts = suspicious_failed_logins['UserId'].value_counts()
    for email, count in suspicious_counts.items():
        print(f"- {email}: {count} failed attempts")

    print("\nAnalysis complete!")
    print(f"✔️ Parsed {len(parsed_df)} records.")
    print(f"✔️ Saved {len(successful_logins)} successful logins.")
    print(f"✔️ Saved {len(failed_logins)} failed logins.")
    print(f"✔️ Saved {len(suspicious_failed_logins)} suspicious failed logins.")

if __name__ == "__main__":
    main()
