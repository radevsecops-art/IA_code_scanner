import os
import subprocess

# --- SECTION 1: Safe Code ---
# The AI should ignore these because they follow safe patterns
print("Initialising system...")
current_dir = os.getcwd()
path = os.path.join(current_dir, "logs")

def get_status():
    return "System is running"

# --- SECTION 2: Vulnerable Code (Injection) ---
# The AI should flag these based on the training data
user_input = "ls -la; rm -rf /" 
os.system("echo " + user_input) # Dangerous: Command Injection

# --- SECTION 3: Vulnerable Code (Hardcoded Secrets) ---
db_password = "admin_password_12345" # Dangerous: Hardcoded Creds

# --- SECTION 4: Insecure Configuration ---
# Using shell=True is a common security risk
subprocess.Popen("cat /etc/passwd", shell=True)