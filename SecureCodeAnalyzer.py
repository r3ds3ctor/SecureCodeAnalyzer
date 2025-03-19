import os
import re
import argparse
from prettytable import PrettyTable

# ✅ OWASP Top 10 Patterns by Language (Completo)
PATTERNS = {
    'php': {
        'SQL Injection': [
            re.compile(r'(mysqli_query|PDO::query).*?(SELECT|INSERT|UPDATE|DELETE).*?(\?|%s|\{)')
        ],
        'Cross-Site Scripting (XSS)': [
            re.compile(r'<script>.*?</script>', re.IGNORECASE),
            re.compile(r'echo\s+\$_GET|echo\s+\$_POST')
        ],
        'Insecure Deserialization': [
            re.compile(r'serialize\(|unserialize\(')
        ],
        'Broken Authentication': [
            re.compile(r'password\s*=|passwd\s*=|secret\s*=')
        ],
        'Sensitive Data Exposure': [
            re.compile(r'(SSN|credit card|password|api_key)', re.IGNORECASE)
        ],
        'Security Misconfiguration': [
            re.compile(r'(DEBUG = True|allowAllOrigins|access-control-allow-origin: \*)')
        ],
        'XML External Entities (XXE)': [
            re.compile(r'file_get_contents\(|simplexml_load_file\(')
        ],
        'Broken Access Control': [
            re.compile(r'(chmod\(|chown\(|setuid\()')
        ],
        'Using Components with Known Vulnerabilities': [
            re.compile(r'(require\s|include\s)')
        ],
        'Insufficient Logging & Monitoring': [
            re.compile(r'error_reporting\(|log\(')
        ]
    },
    'java': {
        'SQL Injection': [
            re.compile(r'executeQuery\(|executeUpdate\(')
        ],
        'Cross-Site Scripting (XSS)': [
            re.compile(r'response\.getWriter\(.*\)')
        ],
        'Insecure Deserialization': [
            re.compile(r'ObjectInputStream\(')
        ],
        'Broken Authentication': [
            re.compile(r'login\(|authenticate\(')
        ],
        'Sensitive Data Exposure': [
            re.compile(r'(password|ssn|credit card)')
        ],
        'Security Misconfiguration': [
            re.compile(r'@CrossOrigin')
        ],
        'XML External Entities (XXE)': [
            re.compile(r'DocumentBuilderFactory\.setFeature\(')
        ],
        'Broken Access Control': [
            re.compile(r'request\.getSession\(')
        ],
        'Using Components with Known Vulnerabilities': [
            re.compile(r'org\.apache\.|commons-collections')
        ],
        'Insufficient Logging & Monitoring': [
            re.compile(r'logger\.debug\(|System\.out\.println\(')
        ]
    },
    'python': {
        'SQL Injection': [
            re.compile(r'execute\(.*%(.*)%')
        ],
        'Cross-Site Scripting (XSS)': [
            re.compile(r'render_template_string\(')
        ],
        'Insecure Deserialization': [
            re.compile(r'(pickle\.loads|marshal\.loads|eval\()', re.IGNORECASE)
        ],
        'Broken Authentication': [
            re.compile(r'(password|secret|token)')
        ],
        'Sensitive Data Exposure': [
            re.compile(r'(password|credit card|ssn)')
        ],
        'Security Misconfiguration': [
            re.compile(r'debug=True')
        ],
        'XML External Entities (XXE)': [
            re.compile(r'xml\.etree\.ElementTree\.parse\(')
        ],
        'Broken Access Control': [
            re.compile(r'os\.chmod\(|os\.chown\(')
        ],
        'Using Components with Known Vulnerabilities': [
            re.compile(r'import\s+urllib|import\s+requests')
        ],
        'Insufficient Logging & Monitoring': [
            re.compile(r'print\(|logging\.debug\(')
        ]
    },
    'ruby': {
        'SQL Injection': [
            re.compile(r'execute\(|find_by_sql\(')
        ],
        'Cross-Site Scripting (XSS)': [
            re.compile(r'ERB\.new\(')
        ],
        'Insecure Deserialization': [
            re.compile(r'YAML\.load\(')
        ],
        'Broken Authentication': [
            re.compile(r'(password|secret|token)')
        ],
        'Sensitive Data Exposure': [
            re.compile(r'(password|credit card|ssn)')
        ],
        'Security Misconfiguration': [
            re.compile(r'config\.allow_concurrency = true')
        ],
        'XML External Entities (XXE)': [
            re.compile(r'REXML::Document\.new\(')
        ],
        'Broken Access Control': [
            re.compile(r'File\.chmod\(|File\.chown\(')
        ],
        'Using Components with Known Vulnerabilities': [
            re.compile(r'require\s+"rails"')
        ],
        'Insufficient Logging & Monitoring': [
            re.compile(r'logger\.debug\(|puts\(')
        ]
    }
}

# ✅ Solutions for each vulnerability type
SOLUTIONS = {
    'SQL Injection': 'Use parameterized queries or prepared statements.',
    'Cross-Site Scripting (XSS)': 'Use encoding libraries and input sanitization.',
    'Insecure Deserialization': 'Avoid deserializing untrusted data.',
    'Broken Authentication': 'Use strong authentication mechanisms and multi-factor authentication.',
    'Sensitive Data Exposure': 'Encrypt sensitive data and limit exposure.',
    'Security Misconfiguration': 'Follow secure configuration guidelines and disable debugging.',
    'XML External Entities (XXE)': 'Use secure XML parsers and disable DTDs.',
    'Broken Access Control': 'Enforce proper access control mechanisms and least privilege.',
    'Using Components with Known Vulnerabilities': 'Keep dependencies up to date and avoid insecure components.',
    'Insufficient Logging & Monitoring': 'Implement logging and monitor for suspicious activity.'
}

# ✅ Function to analyze code (COMPLETA)
def analyze_code(file_path, language):
    vulnerabilities = []
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        lines = file.readlines()
        for i, line in enumerate(lines):
            for vuln_type, patterns in PATTERNS[language].items():
                for pattern in patterns:
                    if pattern.search(line):
                        vulnerabilities.append({
                            'file': file_path,
                            'line_num': i + 1,
                            'type': vuln_type,
                            'code': line.strip()
                        })
    return vulnerabilities

# ✅ Function to display results (Terminal + HTML)
def display_results(vulnerabilities, output_file=None):
    table = PrettyTable(['File', 'Line', 'Vulnerability', 'Code', 'Solution'])

    for vuln in vulnerabilities:
        solution = SOLUTIONS.get(vuln['type'], 'No solution available')
        table.add_row([vuln['file'], vuln['line_num'], vuln['type'], vuln['code'], solution])

    print(table)

    if output_file:
        with open(output_file, 'w') as f:
            f.write(table.get_html_string())
        print(f"\n✅ Report saved to {output_file}")

# ✅ MAIN FUNCTION
def main():
    parser = argparse.ArgumentParser(description="Secure Code Analyzer for OWASP Top 10.")
    parser.add_argument('--file')
    parser.add_argument('--dir')
    parser.add_argument('--github')
    parser.add_argument('--language', required=True)
    parser.add_argument('--output')

    args = parser.parse_args()

    vulnerabilities = analyze_code(args.file, args.language)
    if vulnerabilities:
        display_results(vulnerabilities, args.output)

if __name__ == "__main__":
    main()
