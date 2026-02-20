# ServerOps - Insecure Deserialization Lab

A comprehensive security research project demonstrating **Python Pickle Insecure Deserialization** vulnerabilities, exploitation techniques, and mitigation strategies.

## Project Overview

This project implements a realistic IT Dashboard application (`ServerOps`) that allows administrators to export and import server configuration profiles. The vulnerable version uses Python's `pickle` module to serialize data, which is susceptible to Remote Code Execution (RCE) attacks.

### Educational Purpose

This project is designed for:
- Security researchers and students
- Understanding deserialization vulnerabilities
- Learning secure coding practices
- Demonstrating the importance of input validation

> **WARNING:** This project contains intentional security vulnerabilities. DO NOT deploy in production environments. Use only in isolated lab environments for educational purposes.

## Architecture

```
ServerOps-Project/
├── Vulnerable-App/          # Vulnerable application (victim)
│   ├── app.py               # Flask server with pickle vulnerability
│   ├── models.py            # ServerConfig data model
│   ├── requirements.txt     # Dependencies
│   ├── static/              # CSS styling
│   └── templates/           # HTML templates
│
├── Secure-App/              # Patched application (defense)
│   ├── app_secure.py        # Flask server with HMAC protection
│   ├── models.py            # Same data model
│   └── utils/
│       └── secure_serializer.py  # HMAC & JSON serializers
│
├── Attack-Tools/            # Exploitation toolkit
│   ├── exploit_generator.py # Malicious payload generator
│   └── payloads/            # Generated exploit files
│
├── Docs/                    # Documentation
└── README.md
```

## The Vulnerability

### What is Insecure Deserialization?

Python's `pickle` module can serialize arbitrary Python objects. During deserialization (`pickle.loads()`), the module can execute code through the `__reduce__` method, which specifies how to reconstruct objects.

### Vulnerable Code

```python
# In Vulnerable-App/app.py - /import route
file_content = file.read()
decoded_data = base64.b64decode(file_content)
imported_configs = pickle.loads(decoded_data)  # VULNERABLE!
```

### Attack Vector

An attacker creates a malicious class with `__reduce__`:

```python
class RCE:
    def __reduce__(self):
        return (os.system, ("calc.exe",))  # Executes calc.exe

malicious_payload = pickle.dumps(RCE())
```

When the server deserializes this payload, `os.system("calc.exe")` is executed with the server's privileges.

## Quick Start

### Prerequisites

- Python 3.8+
- pip

### Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/ServerOps-Project.git
   cd ServerOps-Project
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv venv
   
   # Windows
   .\venv\Scripts\activate
   
   # Linux/Mac
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r Vulnerable-App/requirements.txt
   ```

## Usage

### Running the Vulnerable Application

```bash
cd Vulnerable-App
python app.py
```

Access at: `http://127.0.0.1:5000`
- **Credentials:** admin / admin

### Running the Secure Application

```bash
cd Secure-App
python app_secure.py
```

Access at: `http://127.0.0.1:5001`
- **Credentials:** admin / admin

### Generating Exploit Payloads

```bash
cd Attack-Tools
python exploit_generator.py
```

Follow the interactive menu to generate various payloads:
1. Windows Calculator (PoC)
2. File creation proof
3. Reverse shells
4. Custom commands

## Demonstration Steps

### 1. Normal Operation

1. Start the vulnerable app
2. Login with admin/admin
3. View the dashboard with server configs
4. Click "Export Config" to download `server_config.ops`
5. This is a legitimate Base64-encoded pickle file

### 2. Exploit Execution

1. Run `exploit_generator.py`
2. Select option `[1]` for Windows Calculator
3. A malicious `.ops` file is created in `payloads/`
4. In the vulnerable app, go to "Import Config"
5. Upload the malicious file
6. **Calculator opens** - demonstrating RCE!

### 3. Defense Verification

1. Start the secure app on port 5001
2. Try to upload the same malicious file
3. **Attack is blocked** with "Signature Mismatch" error
4. Only files signed by the server are accepted

## Defense Mechanisms

### 1. HMAC Signature Verification

The secure app signs all exports with HMAC-SHA256:

```python
# Export: data + signature
signed_data = base64.b64encode(pickle_data) + b"." + base64.b64encode(hmac_signature)

# Import: verify before deserializing
if not hmac.compare_digest(expected_sig, provided_sig):
    raise SignatureVerificationError("Tampered data!")
```

### 2. JSON Serialization (Alternative)

Replace pickle entirely with JSON:

```python
# JSON cannot execute code
serializer = JSONSerializer()
safe_data = serializer.serialize(configs)  # Pure data, no code
```

Enable JSON mode:
```bash
set USE_JSON_SERIALIZER=true  # Windows
export USE_JSON_SERIALIZER=true  # Linux/Mac
python app_secure.py
```

## Technical Details

### Why Pickle is Dangerous

| Feature | Pickle | JSON |
|---------|--------|------|
| Code Execution | Yes (via `__reduce__`) | No |
| Arbitrary Objects | Yes | No (primitives only) |
| Security | Unsafe for untrusted data | Safe |

### CVE References

This vulnerability class is documented in:
- CWE-502: Deserialization of Untrusted Data
- OWASP Top 10: A8 - Insecure Deserialization

## Project Requirements Checklist

- [x] Research topic not covered in course (Pickle Deserialization)
- [x] Practical PoC demonstration (Attack-Tools)
- [x] Defense mechanisms explained (Secure-App)
- [x] Professional documentation
- [x] Clean, organized codebase

## Files Description

| File | Description |
|------|-------------|
| `Vulnerable-App/app.py` | Flask server with insecure `pickle.loads()` |
| `Vulnerable-App/models.py` | ServerConfig class definition |
| `Attack-Tools/exploit_generator.py` | Interactive payload generator |
| `Secure-App/app_secure.py` | Patched server with HMAC verification |
| `Secure-App/utils/secure_serializer.py` | HMAC and JSON serialization utilities |

## License

This project is for educational purposes only. MIT License.

## Disclaimer

**This software is provided for educational and authorized security testing purposes only.**

- Do NOT use these tools against systems without explicit authorization
- Unauthorized computer access is illegal
- The authors are not responsible for misuse of this software

## Contributing

Contributions are welcome! Please ensure any additions maintain the educational focus and include appropriate documentation.

## Acknowledgments

- OWASP for security guidelines
- Python Security documentation
- Academic security research community
