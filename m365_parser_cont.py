import pandas as pd
import json
import sys
import matplotlib.pyplot as plt
from collections import defaultdict

# Helper function to parse JSON from AuditData
def parse_audit_json(row):
    try:
        data = json.loads(row)
        base = {
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
        # Optional GeoIP stub placeholder
        base['GeoLocation'] = f"Geo({base['ClientIP']})" if base['ClientIP'] else None
        return {**base, 'RawData': data}
    except Exception as e:
        return None

# Filter helpers
def extract_events(df, keyword):
    return df[df['Operation'].str.contains(keyword, case=False, na=False)]

def main():
    filename = "20200604_unified_auditlogs.csv"

    try:
        df = pd.read_csv(filename, skiprows=1)
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        sys.exit(1)

    df = df[df['AuditData'].notna()]
    parsed_rows = df['AuditData'].apply(parse_audit_json)
    parsed_df = pd.DataFrame(parsed_rows.tolist())
    parsed_df = parsed_df.dropna(subset=['Operation'])

    # ---------------------- AUTH EVENTS ----------------------
    auth_success = parsed_df[parsed_df['Operation'] == 'UserLoggedIn']
    auth_failed = parsed_df[parsed_df['Operation'] == 'UserLoginFailed']
    suspicious_ips = auth_failed['ClientIP'].value_counts()
    suspicious_ips = suspicious_ips[suspicious_ips > 3].index.tolist()
    suspicious_failed = auth_failed[auth_failed['ClientIP'].isin(suspicious_ips)]

    # ---------------------- MAIL FORWARDING ----------------------
    mail_forwarding = extract_events(parsed_df, "Set-Mailbox")
    mail_forwarding = mail_forwarding[mail_forwarding['RawData'].apply(lambda d: "ForwardingSmtpAddress" in json.dumps(d))]

    # ---------------------- MAIL ACCESS ----------------------
    mail_access = extract_events(parsed_df, "SendOnBehalf")
    mail_access = pd.concat([mail_access, extract_events(parsed_df, "Send")])

    # ---------------------- FILE ACCESS/DOWNLOADS ----------------------
    file_access = extract_events(parsed_df, "FileAccessed")
    file_download = extract_events(parsed_df, "FileDownloaded")
    file_events = pd.concat([file_access, file_download])

    # ---------------------- MFA CHANGES ----------------------
    mfa_events = extract_events(parsed_df, "MFA")
    mfa_events = pd.concat([
        mfa_events,
        extract_events(parsed_df, "StrongAuthentication"),
        extract_events(parsed_df, "UpdateMFA")
    ])

    # ---------------------- SAVE OUTPUT ----------------------
    auth_success.to_csv("successful_logins.csv", index=False)
    auth_failed.to_csv("failed_logins.csv", index=False)
    suspicious_failed.to_csv("suspicious_failed_logins.csv", index=False)
    mail_forwarding.to_csv("mail_forwarding_rules.csv", index=False)
    mail_access.to_csv("mail_access_events.csv", index=False)
    file_events.to_csv("file_events.csv", index=False)
    mfa_events.to_csv("mfa_changes.csv", index=False)

    # ---------------------- PLOTTING ----------------------
    top_10 = suspicious_failed['UserId'].value_counts().head(10)
    plt.figure(figsize=(10, 6))
    plt.bar(top_10.index, top_10.values, color='darkred')
    plt.title('Top 10 Suspicious Accounts by Failed Logins')
    plt.xlabel('UserId')
    plt.ylabel('Failed Attempts')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("suspicious_logins_bar_chart.png")
    plt.close()

    # ---------------------- SUMMARY ----------------------
    print("\n✅ Summary:")
    print(f"- Parsed records: {len(parsed_df)}")
    print(f"- Successful logins: {len(auth_success)}")
    print(f"- Failed logins: {len(auth_failed)}")
    print(f"- Suspicious failed: {len(suspicious_failed)}")
    print(f"- Mail forwarding rules: {len(mail_forwarding)}")
    print(f"- Mail access events: {len(mail_access)}")
    print(f"- File access/download events: {len(file_events)}")
    print(f"- MFA events: {len(mfa_events)}")

if __name__ == "__main__":
    main()
