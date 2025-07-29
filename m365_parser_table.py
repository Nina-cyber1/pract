import pandas as pd
import json
import sys

def parse_audit_json(row):
    try:
        return json.loads(row)
    except Exception:
        return None

def get_geo_location(ip):
    # Placeholder for IP geolocation - returns Unknown
    # You can integrate geoip libraries here (like geoip2) for real data
    if ip:
        return "Unknown"
    return ""

def extract_authentication_events(df):
    auth_ops = ['UserLoggedIn', 'UserLoginFailed']
    auth_events = df[df['Operation'].isin(auth_ops)]
    records = []
    for _, row in auth_events.iterrows():
        data = row['RawAuditData']
        record = {
            "Date & Time": data.get('CreationTime', ''),
            "User": data.get('UserId', ''),
            "IP Address": data.get('ClientIP', ''),
            "Geo Location": get_geo_location(data.get('ClientIP', '')),
            "User Agent": None,
            "Result": data.get('ResultStatus', '')
        }
        # Try to get UserAgent from ExtendedProperties if present
        props = data.get('ExtendedProperties', [])
        for prop in props:
            if prop.get('Name') == 'UserAgent':
                record["User Agent"] = prop.get('Value')
                break
        records.append(record)
    return pd.DataFrame(records)

def extract_mail_forwarding_rules(df):
    ops = ['New-InboxRule', 'Set-InboxRule']
    rules = df[df['Operation'].isin(ops)]
    records = []
    for _, row in rules.iterrows():
        data = row['RawAuditData']
        params = data.get('Parameters', [])
        # Extract forwarding addresses from Parameters if present
        forward_addresses = []
        for p in params:
            if 'ForwardTo' in p.get('Name', ''):
                forward_addresses.append(p.get('Value'))
        record = {
            "Date Created": data.get('CreationTime', ''),
            "User": data.get('UserId', ''),
            "Forwarding Addresses": ', '.join(forward_addresses) if forward_addresses else '',
            "IP Address": data.get('ClientIP', ''),
            "Parameters": '; '.join(f"{p.get('Name')}={p.get('Value')}" for p in params)
        }
        records.append(record)
    return pd.DataFrame(records)

def extract_mail_access_events(df):
    ops = ['MessageBind', 'MessageRead']
    mail_access = df[df['Operation'].isin(ops)]
    records = []
    for _, row in mail_access.iterrows():
        data = row['RawAuditData']
        record = {
            "Date & Time": data.get('CreationTime', ''),
            "User": data.get('UserId', ''),
            "Mailbox Accessed": data.get('MailboxOwnerUPN', ''),
            "IP Address": data.get('ClientIP', ''),
            "Parameters": ''
        }
        # Try to get parameters info if present
        params = data.get('Parameters', [])
        record["Parameters"] = '; '.join(f"{p.get('Name')}={p.get('Value')}" for p in params)
        records.append(record)
    return pd.DataFrame(records)

def extract_file_access_events(df):
    ops = ['FileAccessed', 'FileDownloaded']
    file_events = df[df['Operation'].isin(ops)]
    records = []
    for _, row in file_events.iterrows():
        data = row['RawAuditData']
        record = {
            "Date & Time": data.get('CreationTime', ''),
            "User": data.get('UserId', ''),
            "File Name": data.get('ObjectId', ''),
            "Action": data.get('Operation', ''),
            "IP Address": data.get('ClientIP', '')
        }
        records.append(record)
    return pd.DataFrame(records)

def extract_mfa_events(df):
    ops = ['Set-UserMFAPreference', 'Disable-UserMFAPreference']
    mfa_events = df[df['Operation'].isin(ops)]
    records = []
    for _, row in mfa_events.iterrows():
        data = row['RawAuditData']
        params = data.get('Parameters', [])
        details = '; '.join(f"{p.get('Name')}={p.get('Value')}" for p in params)
        record = {
            "Date & Time": data.get('CreationTime', ''),
            "User": data.get('UserId', ''),
            "Action": data.get('Operation', ''),
            "IP Address": data.get('ClientIP', ''),
            "Details": details
        }
        records.append(record)
    return pd.DataFrame(records)

def print_markdown_table(df, title):
    if df.empty:
        print(f"\n### {title} (No records found)\n")
        return
    print(f"\n### {title}\n")
    print(df.to_markdown(index=False))
    print("\n")

def main():
    if len(sys.argv) < 2:
        print("Usage: python m365_parser_cont.py <path_to_csv>")
        sys.exit(1)

    filename = sys.argv[1]

    try:
        df = pd.read_csv(filename, skiprows=1)
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        sys.exit(1)

    df = df[df['AuditData'].notna()]
    df['RawAuditData'] = df['AuditData'].apply(parse_audit_json)
    df = df.dropna(subset=['RawAuditData'])

    # Add an Operation column for easier filtering
    df['Operation'] = df['RawAuditData'].apply(lambda x: x.get('Operation') if x else None)

    # Extract and print/save all event categories
    auth_df = extract_authentication_events(df)
    forwarding_df = extract_mail_forwarding_rules(df)
    mail_access_df = extract_mail_access_events(df)
    file_access_df = extract_file_access_events(df)
    mfa_df = extract_mfa_events(df)

    # Print summary counts
    print(f"\n✅ Summary:")
    print(f"- Parsed records: {len(df)}")
    print(f"- Authentication events: {len(auth_df)}")
    print(f"- Mail forwarding rules: {len(forwarding_df)}")
    print(f"- Mail access events: {len(mail_access_df)}")
    print(f"- File access/download events: {len(file_access_df)}")
    print(f"- MFA alteration events: {len(mfa_df)}")

    # Print markdown tables
    print_markdown_table(auth_df, "Authentication Events")
    print_markdown_table(forwarding_df, "Mail Forwarding Rules")
    print_markdown_table(mail_access_df, "Accessed Mail Items")
    print_markdown_table(file_access_df, "File Access / Downloads")
    print_markdown_table(mfa_df, "MFA Alterations")

    # Save to CSV
    auth_df.to_csv("authentication_events.csv", index=False)
    forwarding_df.to_csv("mail_forwarding_rules.csv", index=False)
    mail_access_df.to_csv("mail_access_events.csv", index=False)
    file_access_df.to_csv("file_access_events.csv", index=False)
    mfa_df.to_csv("mfa_events.csv", index=False)

if __name__ == "__main__":
    main()
