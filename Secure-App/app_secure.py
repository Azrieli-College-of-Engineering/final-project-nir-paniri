"""
ServerOps Secure Application - IT Dashboard with Protected Serialization

This is the PATCHED version of the ServerOps application that demonstrates
secure deserialization practices.

SECURITY IMPROVEMENTS:
1. HMAC-SHA256 signature verification before deserializing pickle data
2. Option to use JSON serialization instead of pickle (safest)
3. Secret key management via environment variables
4. Comprehensive error handling and logging

The vulnerability is mitigated by:
- Signing serialized data with HMAC, preventing tampering
- Verifying signatures before deserializing
- Optionally using JSON which cannot execute code
"""

import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from io import BytesIO
from models import ServerConfig
from utils.secure_serializer import (
    HMACPickleSerializer,
    JSONSerializer,
    SignatureVerificationError
)

app = Flask(__name__)

app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'change-this-in-production')

SERIALIZATION_SECRET = os.environ.get(
    'SERVEROPS_SECRET_KEY',
    'default-hmac-secret-key-change-in-production-minimum-32-chars'
)

USE_JSON_SERIALIZER = os.environ.get('USE_JSON_SERIALIZER', 'false').lower() == 'true'

if USE_JSON_SERIALIZER:
    serializer = JSONSerializer()
    print("[SECURITY] Using JSON serializer (maximum security)")
else:
    serializer = HMACPickleSerializer(SERIALIZATION_SECRET)
    print("[SECURITY] Using HMAC-signed pickle serializer")

server_configs = []

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
        
        if username == 'admin' and password == 'admin':
            session['logged_in'] = True
            session['username'] = username
            flash('Login successful! Welcome to ServerOps Dashboard (Secure Version).', 'success')
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
    
    return render_template('dashboard.html', configs=server_configs, secure_mode=True)


@app.route('/export')
def export_config():
    """
    Export all server configurations as a signed file.
    
    SECURITY: Data is either:
    - HMAC-signed pickle (tamper-proof)
    - JSON (inherently safe)
    """
    if not session.get('logged_in'):
        flash('Please login first.', 'warning')
        return redirect(url_for('login'))
    
    init_default_configs()
    
    signed_data = serializer.serialize(server_configs)
    
    buffer = BytesIO(signed_data)
    buffer.seek(0)
    
    flash('Configuration exported with cryptographic signature!', 'success')
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name='server_config_secure.ops',
        mimetype='application/octet-stream'
    )


@app.route('/import', methods=['GET', 'POST'])
def import_config():
    """
    Import server configurations from an uploaded file.
    
    SECURITY MEASURES:
    1. For HMAC mode: Verifies signature before deserializing
       - Rejects tampered data immediately
       - Prevents execution of malicious payloads
    
    2. For JSON mode: No code execution possible
       - JSON only handles primitive data types
       - Cannot instantiate arbitrary objects
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
            file_content = file.read()
            
            if USE_JSON_SERIALIZER:
                imported_configs = serializer.deserialize(file_content, ServerConfig)
            else:
                imported_configs = serializer.deserialize(file_content)
            
            global server_configs
            if isinstance(imported_configs, list):
                server_configs = imported_configs
                flash(
                    f'Successfully imported {len(imported_configs)} server configuration(s)! '
                    'Signature verified.',
                    'success'
                )
            else:
                server_configs = [imported_configs]
                flash('Configuration imported successfully! Signature verified.', 'success')
            
            return redirect(url_for('dashboard'))
            
        except SignatureVerificationError as e:
            flash(
                f'SECURITY ALERT: {str(e)} '
                'The file may have been tampered with!',
                'danger'
            )
            app.logger.warning(f"Signature verification failed: {e}")
            return redirect(url_for('import_config'))
            
        except ValueError as e:
            flash(f'Invalid configuration format: {str(e)}', 'danger')
            return redirect(url_for('import_config'))
            
        except Exception as e:
            flash(f'Error importing configuration: {str(e)}', 'danger')
            app.logger.error(f"Import error: {e}")
            return redirect(url_for('import_config'))
    
    return render_template('upload_config.html', secure_mode=True)


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
    print("  ServerOps Dashboard - SECURE VERSION")
    print("  Insecure Deserialization MITIGATED")
    print("="*60)
    print("\n  Default credentials: admin / admin")
    print("  Server running at: http://127.0.0.1:5001")
    print(f"\n  Serializer: {'JSON' if USE_JSON_SERIALIZER else 'HMAC-Signed Pickle'}")
    print("  Set USE_JSON_SERIALIZER=true for maximum security")
    print("="*60 + "\n")
    
    app.run(debug=True, host='127.0.0.1', port=5001)
