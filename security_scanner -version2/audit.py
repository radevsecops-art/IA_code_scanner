import joblib
import sys
import os
import re

# Load model
if not os.path.exists('security_model.joblib'):
    print("Error: Train the model first!")
    sys.exit()

model = joblib.load('security_model.joblib')

# Vulnerability database with descriptions and fixes
VULNERABILITY_DB = {
    'sql_injection': {
        'pattern': r'SELECT|INSERT|UPDATE|DELETE.*\+.*%s|f[\'"].*SELECT',
        'name': 'SQL Injection',
        'severity': 'HIGH',
        'description': 'User input is directly concatenated into SQL queries, allowing attackers to manipulate database queries.',
        'fix': 'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
    },
    'command_injection': {
        'pattern': r'os\.system|subprocess\..*shell\s*=\s*True|os\.popen',
        'name': 'Command Injection',
        'severity': 'CRITICAL',
        'description': 'User input is passed to system shell commands, allowing arbitrary command execution.',
        'fix': 'Use subprocess with shell=False and pass arguments as list: subprocess.run(["ls", "-l"], shell=False)'
    },
    'hardcoded_secret': {
        'pattern': r'password\s*=|secret\s*=|api_key\s*=|token\s*=',
        'name': 'Hardcoded Secret',
        'severity': 'HIGH',
        'description': 'Sensitive credentials are hardcoded in source code, exposing them to version control and leaks.',
        'fix': 'Use environment variables: api_key = os.environ.get("API_KEY")'
    },
    'insecure_deserialization': {
        'pattern': r'pickle\.loads|yaml\.load|eval\s*\(|exec\s*\(',
        'name': 'Insecure Deserialization',
        'severity': 'CRITICAL',
        'description': 'Untrusted data is deserialized, potentially allowing remote code execution.',
        'fix': 'Use safe alternatives: yaml.safe_load() or json.loads()'
    },
    'ssl_verification_disabled': {
        'pattern': r'verify\s*=\s*False',
        'name': 'SSL Verification Disabled',
        'severity': 'MEDIUM',
        'description': 'SSL certificate verification is disabled, making connections vulnerable to man-in-the-middle attacks.',
        'fix': 'Always verify SSL certificates: requests.get(url, verify=True)'
    }
}

def detect_vulnerability_type(code_line):
    """Detect specific vulnerability type based on patterns"""
    code_lower = code_line.lower()
    
    for vuln_id, vuln_info in VULNERABILITY_DB.items():
        if re.search(vuln_info['pattern'], code_line, re.IGNORECASE):
            return vuln_info
    return None

def is_likely_safe_line(line):
    """Filter out obvious false positives"""
    line = line.strip()
    
    if line.startswith('import ') or line.startswith('from '):
        return True
    if re.match(r'^\w+\s*=\s*["\']', line):
        if not any(keyword in line.lower() for keyword in ['password', 'secret', 'token', 'key', 'pwd', 'api_key', 'aws']):
            return True
    if line.startswith('def ') or line.startswith('return '):
        return True
    if line.startswith('print('):
        return True
    return False

def run_audit(file_path):
    print(f"\n{'='*70}")
    print(f"🛡️  AI SECURITY AUDIT REPORT")
    print(f"{'='*70}")
    print(f"Target: {file_path}\n")
    
    if not os.path.exists(file_path):
        print(f"❌ Error: File '{file_path}' not found")
        return
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"❌ Error reading file: {e}")
        return
    
    issues = []
    skipped = 0
    
    for idx, line in enumerate(lines):
        clean_line = line.strip()
        
        if not clean_line or clean_line.startswith('#'):
            continue
        
        if is_likely_safe_line(clean_line):
            skipped += 1
            continue
        
        prob = model.predict_proba([clean_line])[0][1]
        
        if prob > 0.70:
            vuln_info = detect_vulnerability_type(clean_line)
            issues.append({
                'line': idx + 1,
                'code': clean_line,
                'confidence': prob,
                'vuln_info': vuln_info
            })
    
    # Print results
    if not issues:
        print("✅ NO VULNERABILITIES DETECTED")
        print(f"   Scanned {len(lines)} lines, skipped {skipped} safe patterns")
        print("   Your code appears secure!\n")
    else:
        print(f"🚨 FOUND {len(issues)} VULNERABILITY(IES)\n")
        
        for i, issue in enumerate(issues, 1):
            print(f"{'─'*70}")
            print(f"#{i} | Line {issue['line']} | Confidence: {issue['confidence']:.2%}")
            print(f"{'─'*70}")
            print(f"Code: {issue['code'][:60]}")
            
            if issue['vuln_info']:
                info = issue['vuln_info']
                print(f"\n⚠️  {info['severity']} SEVERITY: {info['name']}")
                print(f"Description: {info['description']}")
                print(f"\n💡 RECOMMENDED FIX:")
                print(f"   {info['fix']}")
            else:
                print(f"\n⚠️  UNKNOWN PATTERN")
                print(f"Description: This code pattern matches known dangerous signatures.")
                print(f"\n💡 RECOMMENDATION:")
                print(f"   Review this line carefully for security issues.")
            
            print()
        
        print(f"{'='*70}")
        print(f"SUMMARY: {len(issues)} issue(s) require attention")
        print(f"{'='*70}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python audit.py <filename.py>")
    else:
        run_audit(sys.argv[1])