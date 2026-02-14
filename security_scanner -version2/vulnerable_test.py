# vulnerable_test.py
import os

user_input = "some_data"
# This should be flagged:
os.system("rm -rf " + user_input)

# This should be safe:
print("Scanning complete")

# This should be flagged:
password = "super_secret_password_123"