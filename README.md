# SecureCodeAnalyzer

SecureCodeAnalyzer is a Python tool designed to analyze source code for the **OWASP Top 10 vulnerabilities** in **PHP**, **Python**, **Java**, and **Ruby**.

---

## Features
✅ Detects OWASP Top 10 vulnerabilities:
- SQL Injection
- Cross-Site Scripting (XSS)
- Insecure Deserialization
- Broken Authentication
- Sensitive Data Exposure
- Security Misconfiguration
- XML External Entities (XXE)
- Broken Access Control
- Using Components with Known Vulnerabilities
- Insufficient Logging & Monitoring

✅ Supports analysis of:
- Individual files
- Entire directories
- Public GitHub repositories

✅ Generates a detailed **HTML report** with a full vulnerability summary.

---

## Installation
Clone the repository:
```
git clone https://github.com/yourusername/SecureCodeAnalyzer.git
cd SecureCodeAnalyzer
```
Install dependencies:
```
pip install -r requirements.txt
```
## Usage
Analyze a single file:
```
python SecureCodeAnalyzer.py --file test.py --language python
```
Analyze a directory:
```
python SecureCodeAnalyzer.py --dir /path/to/code --language php
```
Analyze a public GitHub repository:
```
python SecureCodeAnalyzer.py --github https://github.com/r3ds3ctor/dict-maker --language python
```
Generate an HTML report:
```
python SecureCodeAnalyzer.py --file test.py --language python --output report.html
```

Display help:
```
python SecureCodeAnalyzer.py --help
```
## output
<img width="1509" alt="Screenshot 2025-03-18 at 8 35 36 PM" src="https://github.com/user-attachments/assets/d6407e3d-2ada-4d88-a50d-90bdcd57dbdb" />


## Report
<img width="1453" alt="Screenshot 2025-03-18 at 8 38 27 PM" src="https://github.com/user-attachments/assets/1b57d1e0-3a3e-4e55-9537-0999850e1a2b" />


# Contributing to SecureCodeAnalyzer

We welcome contributions from the community! Here's how you can help:

## Reporting Issues
- If you encounter a bug, please create an issue with a detailed description.
- Include any error messages and steps to reproduce the issue.

## Submitting a Pull Request
1. Fork the repository.
2. Create a new branch.
3. Make your changes and test thoroughly.
4. Create a pull request describing your changes.

## Code Style
- Follow PEP8 for Python code.
- Ensure proper comments and clear documentation.

---
 **Support Development**  
If you find this tool helpful and would like to support its development:  
👉 [Buy me a coffee](https://buymeacoffee.com/alexboteroh)


## License
This project is licensed under the MIT License - see the LICENSE file for details.

🔥 Developed by Alexander
