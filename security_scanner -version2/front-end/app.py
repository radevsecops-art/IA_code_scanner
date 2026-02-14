from flask import Flask, request, render_template
import joblib
import os

app = Flask(__name__)

# Load model from parent directory
model_path = os.path.join('..', 'security_model.joblib')
model = joblib.load(model_path)

VULNERABILITY_DB = {
    'sql_injection': {
        'name': 'SQL Injection',
        'severity': 'HIGH',
        'description': 'User input concatenated directly into SQL queries.',
        'fix': 'Use parameterized queries: cursor.execute("SELECT * FROM table WHERE id = %s", (id,))'
    },
    'command_injection': {
        'name': 'Command Injection', 
        'severity': 'CRITICAL',
        'description': 'User input passed to system shell commands.',
        'fix': 'Use subprocess with shell=False: subprocess.run(["ls", "-l"], shell=False)'
    },
    'hardcoded_secret': {
        'name': 'Hardcoded Secret',
        'severity': 'HIGH', 
        'description': 'Sensitive credentials hardcoded in source code.',
        'fix': 'Use environment variables: os.environ.get("SECRET_KEY")'
    },
    'insecure_deserialization': {
        'name': 'Insecure Deserialization',
        'severity': 'CRITICAL',
        'description': 'Untrusted data deserialized (pickle, yaml, eval).',
        'fix': 'Use safe alternatives: yaml.safe_load(), json.loads()'
    },
    'ssl_disabled': {
        'name': 'SSL Verification Disabled',
        'severity': 'MEDIUM',
        'description': 'SSL certificate verification disabled.',
        'fix': 'Always verify SSL: requests.get(url, verify=True)'
    }
}

def detect_vulnerability(code):
    code_lower = code.lower()
    if 'select' in code_lower and ('+' in code or '%' in code or 'f"' in code):
        return VULNERABILITY_DB['sql_injection']
    if 'os.system' in code or ('subprocess' in code and 'shell=true' in code_lower):
        return VULNERABILITY_DB['command_injection']
    if any(x in code_lower for x in ['password=', 'secret=', 'api_key=', 'token=']):
        return VULNERABILITY_DB['hardcoded_secret']
    if any(x in code_lower for x in ['pickle.loads', 'yaml.load', 'eval(', 'exec(']):
        return VULNERABILITY_DB['insecure_deserialization']
    if 'verify=false' in code_lower:
        return VULNERABILITY_DB['ssl_disabled']
    return None

@app.route('/', methods=['GET', 'POST'])
def index():
    results = []
    summary = {'safe': 0, 'dangerous': 0}
    code = ''
    scanned = False  # Flag to track if scan was performed
    
    if request.method == 'POST':
        scanned = True
        code = request.form.get('code', '')
        
        if not code.strip():
            return render_template('index.html', results=[], summary=summary, code=code, scanned=True)
        
        lines = code.split('\n')
        
        for idx, line in enumerate(lines, 1):
            clean_line = line.strip()
            if not clean_line or clean_line.startswith('#'):
                continue
            
            # Skip obvious safe patterns
            if clean_line.startswith(('import ', 'from ', 'def ', 'return ', 'print(')):
                if not any(x in clean_line.lower() for x in ['password', 'secret', 'key', 'token']):
                    summary['safe'] += 1
                    continue
            
            try:
                prob = model.predict_proba([clean_line])[0][1]
            except Exception as e:
                continue
            
            if prob > 0.70:
                vuln = detect_vulnerability(clean_line)
                results.append({
                    'line': idx,
                    'code': clean_line,
                    'confidence': f"{prob:.2%}",
                    'status': 'danger',
                    'vulnerability': vuln
                })
                summary['dangerous'] += 1
            else:
                results.append({
                    'line': idx,
                    'code': clean_line,
                    'confidence': f"{prob:.2%}",
                    'status': 'safe',
                    'vulnerability': None
                })
                summary['safe'] += 1
    
    return render_template('index.html', results=results, summary=summary, code=code, scanned=scanned)

if __name__ == '__main__':
    app.run(debug=True, port=5000)