import pandas as pd
import os
import random

# --- CATEGORY 1: DANGEROUS PATTERNS (Label 1) ---
# We focus on the "Suspicious Keywords" mentioned in the project specs
dangerous_templates = [
    # SQL Injection - Concatenation & Formatting
    "query = 'SELECT * FROM users WHERE id = ' + {var}",
    "cursor.execute('SELECT * FROM accounts WHERE name = %s' % {var})",
    "db.execute(f'UPDATE users SET pass = {{{var}}} WHERE id = {{{id_var}}}')",
    "sql = 'DELETE FROM table WHERE id = ' + str({var})",
    "conn.execute('SELECT * FROM data WHERE user = ' + request.form['{key}'])",
    "query = \"SELECT email FROM members WHERE level = '\" + {var} + \"'\"",
    
    # Command Injection (os.system, subprocess with shell=True)
    "os.system('ping ' + {var})",
    "subprocess.Popen('ls ' + {var}, shell=True)",
    "os.popen('cat ' + {var}).read()",
    "subprocess.call(['bash', '-c', {var}], shell=True)",
    "os.system(f'echo {{{var}}} >> log.txt')",
    "subprocess.run('rm -rf ' + {var}, shell=True)",
    "os.system('chmod 777 ' + {var})",

    # Insecure Execution / Deserialization
    "eval(request.args.get('{var}'))",
    "exec(bytes.fromhex({var}).decode())",
    "pickle.loads({var}_binary)",
    "yaml.load({var}, Loader=yaml.Loader)",
    "eval('__import__(\"os\").system(\"ls\")')",
    
    # Hardcoded Secrets & Insecure Config
    "api_key = '{secret}'",
    "AWS_SECRET = '{secret}'",
    "password = 'admin_{num}'",
    "token = 'ghp_{secret}'",
    "db_connection = 'postgres://user:{secret}@localhost:5432/db'",
    "app.config['SECRET_KEY'] = '{secret}'",
    "requests.get(url, verify=False)" # SSL Verification disabled
]

# --- CATEGORY 2: SAFE PATTERNS (Label 0) ---
safe_templates = [
    # Safe SQL (Parameterized)
    "cursor.execute('SELECT * FROM users WHERE id = %s', ({var},))",
    "db.execute('UPDATE accounts SET name = ? WHERE id = ?', [{var}, {id_var}])",
    "query = 'SELECT count(*) FROM table'",
    "results = User.query.filter_by(username={var}).all()", # ORM is safe
    
    # Safe Commands (shell=False or no user input)
    "subprocess.run(['ls', '-l'], check=True)",
    "subprocess.call(['ping', '-c', '1', 'google.com'], shell=False)",
    "os.listdir('/var/log')",
    "subprocess.check_output(['git', 'status'])",
    
    # Standard Logic & UI
    "def {var}_handler(data): return data.strip()",
    "for i in range({num}): print(f'Step {{i}}')",
    "if user.is_authenticated: return redirect('/home')",
    "with open('config.json', 'r') as f: data = json.load(f)",
    "logging.info('Action performed by ' + user.name)",
    "items = [item.name for item in database.get_all()]",
    "api_key = os.environ.get('API_KEY')", # Proper way to handle secrets
    "print('Welcome to the secure portal')",
    "def calculate_sum(a, b): return a + b"
]

# --- VARIABLE POOLS FOR GENERATION ---
vars_list = ['user_input', 'data', 'payload', 'cmd', 'username', 'raw_path', 'temp_val']
secrets_list = ['AIzaSyA_8291', 'AKIAJSY3920', 'secret_key_123', 'password123', 'super-secret-token']

def generate_dataset(iterations=30):
    final_data = []
    
    for i in range(iterations):
        # Generate Dangerous variants
        for temp in dangerous_templates:
            line = temp.format(
                var=random.choice(vars_list),
                id_var=random.choice(['id', 'uid', 'pk']),
                key=random.choice(['user', 'token', 'id']),
                secret=random.choice(secrets_list),
                num=random.randint(100, 999)
            )
            final_data.append((line, 1))
            
        # Generate Safe variants
        for temp in safe_templates:
            line = temp.format(
                var=random.choice(vars_list),
                id_var=random.choice(['id', 'uid']),
                num=random.randint(5, 50)
            )
            final_data.append((line, 0))
            
    return final_data

# Create and Save
all_examples = generate_dataset(iterations=35) # Creates ~1,500 rows
df = pd.DataFrame(all_examples, columns=['code_snippet', 'target'])
df = df.drop_duplicates()

os.makedirs('data', exist_ok=True)
df.to_csv('data/security_dataset.csv', index=False)
print(f"✅ Success: Generated {len(df)} unique code snippets for training.")