import os
import pefile
import re
import tempfile
import shutil
import yara
import subprocess
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import filetype
from collections import Counter
from config import Config
from datetime import datetime
from collections import defaultdict

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

COMMON_NOISE_STRINGS = {
    "msvcrt.dll", "kernel32.dll", "user32.dll", "advapi32.dll", 
    "This program cannot be run in DOS mode",
}

### MODELS ###

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(255))
    role = db.Column(db.String(50), default='analyst')

class Sample(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255))
    filehash = db.Column(db.String(64))
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)
    static_analysis = db.Column(db.Text)
    dynamic_analysis = db.Column(db.Text)
    yara_rule = db.Column(db.Text)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

### HELPER FUNCTIONS ###

def initialize_db():
    db.create_all()
    if not User.query.filter_by(email="admin@example.com").first():
        admin_user = User(email="admin@example.com", password=generate_password_hash("admin123"), role="admin")
        db.session.add(admin_user)
        db.session.commit()

def extract_strings(file_path):
    try:
        result = subprocess.check_output(["strings", file_path], text=True, errors='ignore')
        lines = [s.strip() for s in result.splitlines() if len(s.strip()) > 4]
        return lines
    except Exception as e:
        print(f"Error extracting strings: {e}")
        return []

def filter_interesting_strings(strings_list, max_unique=10):
    filtered = [s for s in strings_list if s.lower() not in COMMON_NOISE_STRINGS]
    freq = Counter(filtered)
    threshold = 5
    final_candidates = [s for s in filtered if freq[s] < threshold]
    return final_candidates[:max_unique]

def generate_yara_rule(sample_name, strings_list, file_path=None):
    """
    Generates a YARA rule with a scoring mechanism to balance detection and false positives.
    
    Parameters:
    - sample_name (str): Name of the sample file.
    - strings_list (list): List of extracted strings from the file.
    - file_path (str): Path to the sample file for PE analysis.
    
    Returns:
    - str: Generated YARA rule.
    """
    
    # --- 1. Attempt to parse with pefile ---
    is_pe = False
    pe = None
    suspicious_imports_found = []
    section_entropy = {}
    
    try:
        if file_path:
            pe = pefile.PE(file_path)
            is_pe = True
            
            # Analyze sections for entropy
            for section in pe.sections:
                entropy = section.get_entropy()
                section_entropy[section.Name.decode().rstrip('\x00')] = entropy
    
    except Exception as e:
        # If not PE or error in parsing, proceed with caution
        print(f"[!] PE parse error: {e}")

    # --- 2. Suspicious Imports ---
    known_suspicious_apis = {
        "VirtualAlloc": 3,
        "VirtualProtect": 3,
        "CreateRemoteThread": 4,
        "WriteProcessMemory": 4,
        "URLDownloadToFileA": 5,
        "URLDownloadToFileW": 5,
        "WinHttpOpen": 3,
        "WinHttpConnect": 3,
        "WinExec": 4,
        "ShellExecuteA": 4,
        "ShellExecuteW": 4,
        "CreateProcessA": 3,
        "CreateProcessW": 3,
        "RegSetValueA": 3,
        "RegSetValueW": 3,
        "OpenSCManagerA": 3,
        "OpenSCManagerW": 3,
        # Add more APIs as needed
    }

    api_weights = defaultdict(int)
    
    if is_pe and hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
            for imp in entry.imports:
                if not imp.name:
                    continue
                api_name = imp.name.decode('utf-8', errors='ignore')
                if api_name in known_suspicious_apis:
                    api_weights[api_name] += known_suspicious_apis[api_name]
    
    # Aggregate suspicious imports
    for api, weight in api_weights.items():
        suspicious_imports_found.append((api, weight))
    
    # --- 3. Suspicious Strings ---
    suspicious_keywords = {
        "powershell": 3,
        "cmd.exe": 3,
        "appdata": 2,
        "startup": 2,
        "encrypt": 4,
        "shellcode": 5,
        "malware": 5,
        "debug": 2,
        "vmware": 1,
        "virtualbox": 1,
        "regsvr32": 3,
        "schtasks": 3,
        "winexec": 4,
        "virtualalloc": 4,
        "urlmon": 3,
        "wininet": 3,
        "secret_key": 5,
        "private_key": 5,
        # Add more strings as needed
    }
    
    string_weights = defaultdict(int)
    
    lowered_strings = [s.lower() for s in strings_list]
    
    for idx, original_str in enumerate(strings_list):
        lower_str = lowered_strings[idx]
        for kw, weight in suspicious_keywords.items():
            if kw in lower_str:
                string_weights[original_str] += weight
    
    # Aggregate suspicious strings
    suspicious_strings_found = list(string_weights.items())[:15]  # Limit to top 15
    
    # --- 4. Scoring Mechanism ---
    total_score = 0
    rule_strings = []
    
    # Assign scores for imports
    for api, weight in suspicious_imports_found:
        rule_strings.append(f'$api_{api} = "{api}" nocase')
        total_score += weight
    
    # Assign scores for strings
    for sstr, weight in suspicious_strings_found:
        escaped = sstr.replace('"', '\\"')
        rule_strings.append(f'$str_{hash(sstr)} = "{escaped}" ascii wide nocase')
        total_score += weight
    
    # Assign scores for PE characteristics
    if is_pe:
        # Check for MZ signature
        rule_strings.append('$mz = { 4D 5A }')  # MZ header
        total_score += 1  # Minimal weight for being a PE
    
        # Check for high entropy sections
        high_entropy_sections = [name for name, entropy in section_entropy.items() if entropy > 7.0]
        for section in high_entropy_sections:
            escaped_section = section.replace('"', '\\"')
            rule_strings.append(f'$section_{section} = "{escaped_section}" nocase')
            total_score += 2  # Moderate weight for suspicious sections
    
    # Define a threshold for suspicion
    suspicion_threshold = 7  # Adjust based on desired sensitivity
    
    if total_score < suspicion_threshold:
        # Return a minimal rule stating not enough indicators
        rule_name = f"NotSuspicious_{re.sub(r'[^a-zA-Z0-9_]', '_', sample_name)}"
        return f"""\
rule {rule_name}
{{
    meta:
        author = "Pratik"
        description = "No sufficient suspicious indicators for {sample_name}"
        date = "{datetime.utcnow().isoformat()}"
    condition:
        false
}}
"""
    
    # --- 5. Construct the YARA Rule ---
    rule_name = f"SuspiciousPE_{re.sub(r'[^a-zA-Z0-9_]', '_', sample_name)}"
    
    # Define condition based on cumulative score
    condition_clauses = []
    
    # Always check for PE signature if it's a PE
    if is_pe:
        condition_clauses.append('uint16(0) == 0x5A4D')  # MZ header
    
    # Any API or string matches contribute to the condition
    if rule_strings:
        condition_clauses.append('any of ($*)')
    
    condition = " and ".join(condition_clauses)
    
    strings_section = "\n        ".join(rule_strings)
    
    rule = f"""\
rule {rule_name}
{{
    meta:
        author = "Pratik"
        description = "Suspicious PE rule for {sample_name}"
        date = "{datetime.utcnow().isoformat()}"
    
    strings:
        {strings_section}
    
    condition:
        {condition}
}}
""".strip()
    
    return rule
def compute_filehash(file_path):
    import hashlib
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

### ROUTES ###

@app.route('/')
@login_required
def dashboard():
    samples = Sample.query.all()
    return render_template('dashboard.html', samples=samples, user=current_user)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_sample():
    if request.method == 'POST':
        if 'sample' not in request.files:
            flash("No file part.")
            return redirect(request.url)
        f = request.files['sample']
        if f.filename == '':
            flash("No selected file.")
            return redirect(request.url)

        filename = secure_filename(f.filename)
        tmp_dir = tempfile.mkdtemp()
        file_path = os.path.join(tmp_dir, filename)
        f.save(file_path)

        try:
            kind = filetype.guess(file_path)
            file_type = kind.extension if kind else "unknown"
            extracted_strings = extract_strings(file_path)
            yara_rule = generate_yara_rule(filename, extracted_strings)
            static_analysis = {
                "file_type": file_type,
                "string_count": len(extracted_strings)
            }
            dynamic_analysis = {
                "sandbox": "Not Implemented"
            }
            filehash = compute_filehash(file_path)

            sample = Sample(
                filename=filename,
                filehash=filehash,
                static_analysis=str(static_analysis),
                dynamic_analysis=str(dynamic_analysis),
                yara_rule=yara_rule
            )
            db.session.add(sample)
            db.session.commit()
        finally:
            shutil.rmtree(tmp_dir)

        flash("File uploaded and analyzed successfully!")
        return redirect(url_for('dashboard'))

    return render_template('upload.html')

@app.route('/view/<int:sample_id>')
@login_required
def view_report(sample_id):
    sample = Sample.query.get_or_404(sample_id)
    return render_template('view_report.html', sample=sample)

@app.route('/edit_rule/<int:sample_id>', methods=['GET', 'POST'])
@login_required
def edit_rule(sample_id):
    sample = Sample.query.get_or_404(sample_id)
    if request.method == 'POST':
        new_rule = request.form.get('yara_rule')
        sample.yara_rule = new_rule
        db.session.commit()
        flash("YARA rule updated!")
        return redirect(url_for('view_report', sample_id=sample_id))

    return render_template('edit_rule.html', sample=sample)

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials")
            return redirect(request.url)
    return render_template('login.html')

@app.route('/delete/<int:sample_id>', methods=['POST'])
@login_required
def delete_sample(sample_id):
    sample = Sample.query.get_or_404(sample_id)
    db.session.delete(sample)
    db.session.commit()
    flash("Sample and associated YARA rule deleted successfully!")
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == "__main__":
    with app.app_context():
        initialize_db()
    app.run(debug=True)
