"""
ServerOps Vulnerable Application - IT Dashboard with Pickle Deserialization Vulnerability

WARNING: This application contains an INTENTIONAL security vulnerability for educational purposes.
DO NOT deploy this application in any production environment.

The vulnerability exists in the /import route where user-supplied pickle data is
deserialized without any validation, allowing Remote Code Execution (RCE).
"""

import pickle
import base64
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from io import BytesIO
from models import ServerConfig

app = Flask(__name__)
app.secret_key = 'insecure-secret-key-for-demo'  # Intentionally weak for demo

# In-memory storage for server configurations
server_configs = []

# Default demo configurations
DEFAULT_CONFIGS = [
    ServerConfig('web-prod-01', '192.168.1.10', 'Web Server', 443),
    ServerConfig('db-master', '192.168.1.20', 'Database', 5432),
    ServerConfig('cache-01', '192.168.1.30', 'Cache Server', 6379),
]


def init_default_configs():
    """Initialize with default server configurations."""
    global server_configs
    if not server_configs:
        server_configs = DEFAULT_CONFIGS.copy()


@app.route('/')
def index():
    """Redirect to login page."""
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Simple login page with hardcoded credentials.
    Credentials: admin / admin
    """
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Hardcoded credentials for demo purposes
        if username == 'admin' and password == 'admin':
            session['logged_in'] = True
            session['username'] = username
            flash('Login successful! Welcome to ServerOps Dashboard.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Try admin/admin', 'danger')
    
    return render_template('login.html')


@app.route('/logout')
def logout():
    """Clear the session and redirect to login."""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    """
    Main dashboard showing server configurations.
    Allows adding new server configs.
    """
    if not session.get('logged_in'):
        flash('Please login first.', 'warning')
        return redirect(url_for('login'))
    
    init_default_configs()
    
    if request.method == 'POST':
        # Add new server configuration
        hostname = request.form.get('hostname', '')
        ip = request.form.get('ip', '')
        role = request.form.get('role', '')
        port = request.form.get('port', 22)
        
        try:
            port = int(port)
        except ValueError:
            port = 22
        
        if hostname and ip and role:
            new_config = ServerConfig(hostname, ip, role, port)
            server_configs.append(new_config)
            flash(f'Server "{hostname}" added successfully!', 'success')
        else:
            flash('Please fill in all required fields.', 'danger')
    
    return render_template('dashboard.html', configs=server_configs)


@app.route('/export')
def export_config():
    """
    Export all server configurations as a pickle file.
    The data is Base64 encoded and sent as a downloadable .ops file.
    """
    if not session.get('logged_in'):
        flash('Please login first.', 'warning')
        return redirect(url_for('login'))
    
    init_default_configs()
    
    # Serialize the configurations using pickle
    pickled_data = pickle.dumps(server_configs)
    
    # Base64 encode for safe transport
    encoded_data = base64.b64encode(pickled_data)
    
    # Create a file-like object for download
    buffer = BytesIO(encoded_data)
    buffer.seek(0)
    
    flash('Configuration exported successfully!', 'success')
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name='server_config.ops',
        mimetype='application/octet-stream'
    )


@app.route('/import', methods=['GET', 'POST'])
def import_config():
    """
    Import server configurations from an uploaded .ops file.
    
    !!! VULNERABILITY WARNING !!!
    This route contains an INSECURE DESERIALIZATION vulnerability.
    The pickle.loads() function is called directly on user-supplied data
    without any validation. An attacker can craft a malicious pickle file
    that executes arbitrary code when deserialized.
    
    Attack vector: Python's __reduce__ method allows arbitrary function execution
    during the unpickling process.
    """
    if not session.get('logged_in'):
        flash('Please login first.', 'warning')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if 'config_file' not in request.files:
            flash('No file uploaded.', 'danger')
            return redirect(url_for('import_config'))
        
        file = request.files['config_file']
        
        if file.filename == '':
            flash('No file selected.', 'danger')
            return redirect(url_for('import_config'))
        
        try:
            # Read the uploaded file content
            file_content = file.read()
            
            # Base64 decode the content
            decoded_data = base64.b64decode(file_content)
            
            # !!! VULNERABLE CODE !!!
            # pickle.loads() deserializes untrusted data without validation
            # This allows Remote Code Execution (RCE) via __reduce__
            imported_configs = pickle.loads(decoded_data)
            
            # Update the global configurations
            global server_configs
            if isinstance(imported_configs, list):
                server_configs = imported_configs
                flash(f'Successfully imported {len(imported_configs)} server configuration(s)!', 'success')
            else:
                server_configs = [imported_configs]
                flash('Configuration imported successfully!', 'success')
            
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            flash(f'Error importing configuration: {str(e)}', 'danger')
            return redirect(url_for('import_config'))
    
    return render_template('upload_config.html')


@app.route('/delete/<int:index>')
def delete_config(index):
    """Delete a server configuration by index."""
    if not session.get('logged_in'):
        flash('Please login first.', 'warning')
        return redirect(url_for('login'))
    
    init_default_configs()
    
    if 0 <= index < len(server_configs):
        deleted = server_configs.pop(index)
        flash(f'Server "{deleted.hostname}" deleted.', 'info')
    else:
        flash('Invalid server index.', 'danger')
    
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    print("\n" + "="*60)
    print("  ServerOps Dashboard - VULNERABLE VERSION")
    print("  FOR EDUCATIONAL PURPOSES ONLY")
    print("="*60)
    print("\n  Default credentials: admin / admin")
    print("  Server running at: http://127.0.0.1:5000")
    print("\n  WARNING: This app contains intentional vulnerabilities!")
    print("="*60 + "\n")
    
    app.run(debug=True, host='127.0.0.1', port=5000)
