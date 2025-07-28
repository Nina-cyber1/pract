import pandas as pd
from google.colab import files
uploaded = files.upload()

# Load the log file (replace the path if needed)
#df = pd.read_csv('fake_m365_logs.csv')
df = pd.read_csv('fake_m365_logs.csv')
# Step 1: Filter only failed login attempts
failed_logins = df[(df['Operation'] == 'Login') & (df['Status'] == 'Failure')]

# Step 2: Count how many failed logins per user (email)
fail_counts = failed_logins['UserId'].value_counts()

# Step 3: Define a threshold (e.g., more than 2 failed attempts = suspicious)
THRESHOLD = 1
suspicious_users = fail_counts[fail_counts > THRESHOLD]

# Step 4: Print suspicious users and their failed login counts
print("⚠️ Suspicious emails with too many failed login attempts:")
print(suspicious_users)

user_activity_counts = df['UserId'].value_counts()

# Define "dormant" as users with fewer than 2 log entries total
dormant_users = user_activity_counts[user_activity_counts < 2]

print("💤 Dormant/inactive accounts with any activity:")
print(dormant_users)
