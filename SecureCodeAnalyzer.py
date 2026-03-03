#!/usr/bin/env python3
"""
SecureCodeAnalyzer — Static Analysis Tool for OWASP Top 10 Vulnerabilities
Supports: Python, Java, PHP, Ruby, C# (.NET)
Modes: Single file, directory scan, GitHub repository clone + scan
"""

import os
import re
import sys
import shutil
import tempfile
import argparse
import subprocess
from datetime import datetime

try:
    from prettytable import PrettyTable
except ImportError:
    print("[!] Missing dependency: prettytable. Install with: pip install prettytable")
    sys.exit(1)

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False
    class Fore:
        RED = YELLOW = GREEN = CYAN = MAGENTA = WHITE = RESET = ""
    class Style:
        BRIGHT = RESET_ALL = ""

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

BANNER = r"""
  ___                        ___         _        _                _
 / __| ___  __ _  _ _  ___  / __| ___  __| | ___  /_\  _ _   __ _ | | _  _  ___ ___  _ _
 \__ \/ -_)/ _| || | '_/ -_)| (__ / _ \/ _` |/ -_)/ _ \| ' \ / _` || || || ||_ // -_)| '_|
 |___/\___|\__|\_,_|_| \___| \___|\___/\__,_|\___/_/ \_\_||_|\__,_||_| \_, //__|\___||_|
                                                                        |__/
"""

VERSION = "2.0.0"

# Severity levels
CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"

SEVERITY_COLOR = {
    CRITICAL: Fore.RED + Style.BRIGHT,
    HIGH:     Fore.RED,
    MEDIUM:   Fore.YELLOW,
    LOW:      Fore.GREEN,
}

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}

# File extension → language mapping
EXT_MAP = {
    ".py":   "python",
    ".java": "java",
    ".php":  "php",
    ".rb":   "ruby",
    ".cs":   "csharp",
}

SUPPORTED_LANGUAGES = list(EXT_MAP.values())

# ─────────────────────────────────────────────────────────────────────────────
# OWASP Top 10 Vulnerability Patterns (by language)
# Each pattern entry: (compiled_regex, severity)
# ─────────────────────────────────────────────────────────────────────────────

PATTERNS = {
    # ── PHP ──────────────────────────────────────────────────────────────
    "php": {
        "SQL Injection": [
            (re.compile(r'(?:mysql_query|mysqli_query|pg_query)\s*\(.*?\$', re.IGNORECASE), CRITICAL),
            (re.compile(r'\$\w+\s*=\s*["\'].*?(SELECT|INSERT|UPDATE|DELETE).*?\.\s*\$_(GET|POST|REQUEST)', re.IGNORECASE), CRITICAL),
        ],
        "Cross-Site Scripting (XSS)": [
            (re.compile(r'echo\s+\$_(GET|POST|REQUEST|COOKIE)\[', re.IGNORECASE), HIGH),
            (re.compile(r'<script>.*?\$_(GET|POST)', re.IGNORECASE), HIGH),
            (re.compile(r'print\s+\$_(GET|POST|REQUEST)', re.IGNORECASE), HIGH),
        ],
        "Command Injection": [
            (re.compile(r'(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\(.*?\$', re.IGNORECASE), CRITICAL),
            (re.compile(r'`.*?\$_(GET|POST|REQUEST)', re.IGNORECASE), CRITICAL),
        ],
        "Insecure Deserialization": [
            (re.compile(r'unserialize\s*\(.*?\$', re.IGNORECASE), HIGH),
        ],
        "Hardcoded Credentials": [
            (re.compile(r'(?:password|passwd|pwd|secret|api_key|apikey|token)\s*=\s*["\'][^"\']{3,}["\']', re.IGNORECASE), HIGH),
        ],
        "Sensitive Data Exposure": [
            (re.compile(r'(?:md5|sha1)\s*\(', re.IGNORECASE), MEDIUM),
        ],
        "Security Misconfiguration": [
            (re.compile(r'display_errors\s*=\s*(?:On|1|true)', re.IGNORECASE), MEDIUM),
            (re.compile(r'error_reporting\s*\(\s*E_ALL\s*\)', re.IGNORECASE), LOW),
            (re.compile(r'header\s*\(\s*["\']Access-Control-Allow-Origin:\s*\*', re.IGNORECASE), MEDIUM),
        ],
        "XML External Entities (XXE)": [
            (re.compile(r'simplexml_load_string\s*\(|simplexml_load_file\s*\(', re.IGNORECASE), MEDIUM),
            (re.compile(r'LIBXML_NOENT', re.IGNORECASE), HIGH),
        ],
        "Path Traversal": [
            (re.compile(r'(?:file_get_contents|include|require|fopen)\s*\(.*?\$_(GET|POST|REQUEST)', re.IGNORECASE), HIGH),
        ],
        "Broken Access Control": [
            (re.compile(r'chmod\s*\(\s*.*?,\s*0?777\s*\)', re.IGNORECASE), MEDIUM),
        ],
        "Insufficient Logging & Monitoring": [
            (re.compile(r'(?:catch|except).*?(?:pass|//\s*todo|//\s*ignore)', re.IGNORECASE), LOW),
        ],
    },

    # ── Java ─────────────────────────────────────────────────────────────
    "java": {
        "SQL Injection": [
            (re.compile(r'(?:executeQuery|executeUpdate|execute)\s*\(.*?\+\s*', re.IGNORECASE), CRITICAL),
            (re.compile(r'Statement\s.*?(?:executeQuery|execute)\s*\(', re.IGNORECASE), CRITICAL),
            (re.compile(r'createQuery\s*\(.*?\+\s*', re.IGNORECASE), CRITICAL),
        ],
        "Cross-Site Scripting (XSS)": [
            (re.compile(r'response\.getWriter\(\)\.(?:print|println|write)\s*\(.*?request\.getParameter', re.IGNORECASE), HIGH),
            (re.compile(r'out\.(?:print|println)\s*\(.*?request\.getParameter', re.IGNORECASE), HIGH),
        ],
        "Command Injection": [
            (re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\(', re.IGNORECASE), CRITICAL),
            (re.compile(r'ProcessBuilder\s*\(.*?\+\s*', re.IGNORECASE), CRITICAL),
        ],
        "Insecure Deserialization": [
            (re.compile(r'ObjectInputStream\s*\(', re.IGNORECASE), HIGH),
            (re.compile(r'readObject\s*\(\s*\)', re.IGNORECASE), HIGH),
        ],
        "Hardcoded Credentials": [
            (re.compile(r'(?:password|passwd|pwd|secret|apiKey|token)\s*=\s*"[^"]{3,}"', re.IGNORECASE), HIGH),
        ],
        "Sensitive Data Exposure": [
            (re.compile(r'MessageDigest\.getInstance\s*\(\s*"(?:MD5|SHA-1)"\s*\)', re.IGNORECASE), MEDIUM),
        ],
        "Security Misconfiguration": [
            (re.compile(r'@CrossOrigin\s*\(\s*origins\s*=\s*"\*"', re.IGNORECASE), MEDIUM),
            (re.compile(r'setAllowedOrigins\s*\(\s*Arrays\.asList\(\s*"\*"', re.IGNORECASE), MEDIUM),
        ],
        "XML External Entities (XXE)": [
            (re.compile(r'DocumentBuilderFactory\.newInstance\(\)', re.IGNORECASE), MEDIUM),
            (re.compile(r'SAXParserFactory\.newInstance\(\)', re.IGNORECASE), MEDIUM),
            (re.compile(r'XMLInputFactory\.newInstance\(\)', re.IGNORECASE), MEDIUM),
        ],
        "Path Traversal": [
            (re.compile(r'new\s+File\s*\(.*?request\.getParameter', re.IGNORECASE), HIGH),
        ],
        "Broken Access Control": [
            (re.compile(r'request\.getSession\(\)\.getAttribute\(', re.IGNORECASE), LOW),
        ],
        "Insufficient Logging & Monitoring": [
            (re.compile(r'catch\s*\(.*?\)\s*\{[\s\n]*\}', re.IGNORECASE), LOW),
            (re.compile(r'e\.printStackTrace\(\)', re.IGNORECASE), LOW),
        ],
    },

    # ── Python ───────────────────────────────────────────────────────────
    "python": {
        "SQL Injection": [
            (re.compile(r'execute\s*\(.*?%\s*\(', re.IGNORECASE), CRITICAL),
            (re.compile(r'execute\s*\(.*?\.format\s*\(', re.IGNORECASE), CRITICAL),
            (re.compile(r'execute\s*\(\s*f["\']', re.IGNORECASE), CRITICAL),
            (re.compile(r'execute\s*\(.*?\+\s*', re.IGNORECASE), CRITICAL),
        ],
        "Cross-Site Scripting (XSS)": [
            (re.compile(r'render_template_string\s*\(', re.IGNORECASE), HIGH),
            (re.compile(r'Markup\s*\(.*?request\.(args|form)', re.IGNORECASE), HIGH),
        ],
        "Command Injection": [
            (re.compile(r'os\.system\s*\(', re.IGNORECASE), CRITICAL),
            (re.compile(r'subprocess\.(?:call|run|Popen)\s*\(.*?shell\s*=\s*True', re.IGNORECASE), CRITICAL),
            (re.compile(r'eval\s*\(', re.IGNORECASE), CRITICAL),
            (re.compile(r'exec\s*\(', re.IGNORECASE), CRITICAL),
            (re.compile(r'__import__\s*\(', re.IGNORECASE), HIGH),
        ],
        "Insecure Deserialization": [
            (re.compile(r'pickle\.(?:loads?|Unpickler)\s*\(', re.IGNORECASE), HIGH),
            (re.compile(r'marshal\.loads?\s*\(', re.IGNORECASE), HIGH),
            (re.compile(r'yaml\.(?:load|unsafe_load)\s*\(', re.IGNORECASE), HIGH),
        ],
        "Hardcoded Credentials": [
            (re.compile(r'(?:password|passwd|pwd|secret|api_key|apikey|token|secret_key)\s*=\s*["\'][^"\']{3,}["\']', re.IGNORECASE), HIGH),
        ],
        "Sensitive Data Exposure": [
            (re.compile(r'hashlib\.(?:md5|sha1)\s*\(', re.IGNORECASE), MEDIUM),
        ],
        "Security Misconfiguration": [
            (re.compile(r'debug\s*=\s*True', re.IGNORECASE), MEDIUM),
            (re.compile(r'CORS\s*\(\s*app\s*\)', re.IGNORECASE), MEDIUM),
            (re.compile(r'verify\s*=\s*False', re.IGNORECASE), MEDIUM),
        ],
        "XML External Entities (XXE)": [
            (re.compile(r'xml\.etree\.ElementTree\.parse\s*\(', re.IGNORECASE), MEDIUM),
            (re.compile(r'lxml\.etree\.parse\s*\(', re.IGNORECASE), MEDIUM),
        ],
        "Path Traversal": [
            (re.compile(r'open\s*\(.*?request\.(args|form)', re.IGNORECASE), HIGH),
            (re.compile(r'send_file\s*\(.*?request\.(args|form)', re.IGNORECASE), HIGH),
        ],
        "Broken Access Control": [
            (re.compile(r'os\.chmod\s*\(.*?0o?777', re.IGNORECASE), MEDIUM),
        ],
        "Insufficient Logging & Monitoring": [
            (re.compile(r'except\s*:\s*$', re.IGNORECASE), LOW),
            (re.compile(r'except\s+.*?:\s*pass\s*$', re.IGNORECASE), LOW),
        ],
    },

    # ── Ruby ─────────────────────────────────────────────────────────────
    "ruby": {
        "SQL Injection": [
            (re.compile(r'(?:find_by_sql|execute|select_all)\s*\(.*?#\{', re.IGNORECASE), CRITICAL),
            (re.compile(r'\.where\s*\(.*?#\{', re.IGNORECASE), CRITICAL),
        ],
        "Cross-Site Scripting (XSS)": [
            (re.compile(r'\.html_safe', re.IGNORECASE), HIGH),
            (re.compile(r'raw\s*\(', re.IGNORECASE), HIGH),
            (re.compile(r'ERB\.new\s*\(.*?params', re.IGNORECASE), HIGH),
        ],
        "Command Injection": [
            (re.compile(r'system\s*\(.*?params', re.IGNORECASE), CRITICAL),
            (re.compile(r'`.*?#\{.*?params', re.IGNORECASE), CRITICAL),
            (re.compile(r'exec\s*\(.*?params', re.IGNORECASE), CRITICAL),
            (re.compile(r'%x\[.*?#\{', re.IGNORECASE), CRITICAL),
        ],
        "Insecure Deserialization": [
            (re.compile(r'YAML\.load\s*\(', re.IGNORECASE), HIGH),
            (re.compile(r'Marshal\.load\s*\(', re.IGNORECASE), HIGH),
        ],
        "Hardcoded Credentials": [
            (re.compile(r'(?:password|passwd|secret|api_key|token)\s*=\s*["\'][^"\']{3,}["\']', re.IGNORECASE), HIGH),
        ],
        "Sensitive Data Exposure": [
            (re.compile(r'Digest::(?:MD5|SHA1)', re.IGNORECASE), MEDIUM),
        ],
        "Security Misconfiguration": [
            (re.compile(r'config\.force_ssl\s*=\s*false', re.IGNORECASE), MEDIUM),
            (re.compile(r'config\.consider_all_requests_local\s*=\s*true', re.IGNORECASE), MEDIUM),
        ],
        "XML External Entities (XXE)": [
            (re.compile(r'Nokogiri::XML\s*\(', re.IGNORECASE), MEDIUM),
            (re.compile(r'REXML::Document\.new\s*\(', re.IGNORECASE), MEDIUM),
        ],
        "Path Traversal": [
            (re.compile(r'File\.(?:read|open|write)\s*\(.*?params', re.IGNORECASE), HIGH),
            (re.compile(r'send_file\s*\(.*?params', re.IGNORECASE), HIGH),
        ],
        "Broken Access Control": [
            (re.compile(r'File\.chmod\s*\(\s*0?777', re.IGNORECASE), MEDIUM),
        ],
        "Insufficient Logging & Monitoring": [
            (re.compile(r'rescue\s*=>\s*\w+\s*$', re.IGNORECASE), LOW),
        ],
    },

    # ── C# / .NET ────────────────────────────────────────────────────────
    "csharp": {
        "SQL Injection": [
            (re.compile(r'(?:SqlCommand|OleDbCommand|OdbcCommand)\s*\(.*?\+\s*', re.IGNORECASE), CRITICAL),
            (re.compile(r'CommandText\s*=.*?\+\s*', re.IGNORECASE), CRITICAL),
            (re.compile(r'ExecuteSqlRaw\s*\(.*?\+\s*', re.IGNORECASE), CRITICAL),
            (re.compile(r'FromSqlRaw\s*\(\s*\$"', re.IGNORECASE), CRITICAL),
        ],
        "Cross-Site Scripting (XSS)": [
            (re.compile(r'Response\.Write\s*\(.*?Request', re.IGNORECASE), HIGH),
            (re.compile(r'@Html\.Raw\s*\(', re.IGNORECASE), HIGH),
            (re.compile(r'HtmlString\s*\(.*?Request', re.IGNORECASE), HIGH),
        ],
        "Command Injection": [
            (re.compile(r'Process\.Start\s*\(.*?\+\s*', re.IGNORECASE), CRITICAL),
            (re.compile(r'ProcessStartInfo\s*\(.*?\+\s*', re.IGNORECASE), CRITICAL),
        ],
        "Insecure Deserialization": [
            (re.compile(r'BinaryFormatter\s*\(\s*\)', re.IGNORECASE), HIGH),
            (re.compile(r'JsonConvert\.DeserializeObject\s*\(', re.IGNORECASE), MEDIUM),
            (re.compile(r'XmlSerializer\s*\(.*?typeof', re.IGNORECASE), MEDIUM),
            (re.compile(r'SoapFormatter\s*\(\s*\)', re.IGNORECASE), HIGH),
        ],
        "Hardcoded Credentials": [
            (re.compile(r'(?:password|passwd|pwd|connectionString|secret|apiKey)\s*=\s*"[^"]{3,}"', re.IGNORECASE), HIGH),
        ],
        "Sensitive Data Exposure": [
            (re.compile(r'MD5\.Create\s*\(\s*\)|SHA1\.Create\s*\(\s*\)', re.IGNORECASE), MEDIUM),
            (re.compile(r'DESCryptoServiceProvider', re.IGNORECASE), MEDIUM),
        ],
        "Security Misconfiguration": [
            (re.compile(r'<customErrors\s+mode\s*=\s*"Off"', re.IGNORECASE), MEDIUM),
            (re.compile(r'<compilation\s+debug\s*=\s*"true"', re.IGNORECASE), MEDIUM),
            (re.compile(r'AllowAnyOrigin\s*\(\s*\)', re.IGNORECASE), MEDIUM),
            (re.compile(r'RequireHttpsMetadata\s*=\s*false', re.IGNORECASE), MEDIUM),
        ],
        "XML External Entities (XXE)": [
            (re.compile(r'XmlReader\.Create\s*\(', re.IGNORECASE), MEDIUM),
            (re.compile(r'XmlDocument\s*\(\s*\)', re.IGNORECASE), MEDIUM),
            (re.compile(r'DtdProcessing\.Parse', re.IGNORECASE), HIGH),
        ],
        "Path Traversal": [
            (re.compile(r'File\.(?:ReadAllText|ReadAllBytes|OpenRead)\s*\(.*?Request', re.IGNORECASE), HIGH),
            (re.compile(r'Path\.Combine\s*\(.*?Request', re.IGNORECASE), HIGH),
        ],
        "Broken Access Control": [
            (re.compile(r'\[AllowAnonymous\]', re.IGNORECASE), LOW),
        ],
        "Insufficient Logging & Monitoring": [
            (re.compile(r'catch\s*\(.*?\)\s*\{\s*\}', re.IGNORECASE), LOW),
            (re.compile(r'catch\s*\{\s*\}', re.IGNORECASE), LOW),
        ],
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# Solutions & Remediation Guidance
# ─────────────────────────────────────────────────────────────────────────────

SOLUTIONS = {
    "SQL Injection":
        "Use parameterized queries or prepared statements. Never concatenate user input into SQL strings.",
    "Cross-Site Scripting (XSS)":
        "Apply context-aware output encoding. Use Content-Security-Policy headers and avoid rendering unsanitized user input.",
    "Command Injection":
        "Avoid calling system commands with user input. Use safe APIs and allowlist-based input validation.",
    "Insecure Deserialization":
        "Never deserialize untrusted data. Use safe formats like JSON with strict schemas.",
    "Hardcoded Credentials":
        "Store secrets in environment variables, vaults, or secure configuration managers. Never commit credentials.",
    "Sensitive Data Exposure":
        "Use strong hashing (bcrypt, Argon2) and encryption (AES-256). Deprecate MD5/SHA1 for security purposes.",
    "Security Misconfiguration":
        "Disable debug mode in production. Enforce HTTPS, restrict CORS, and follow hardening guides.",
    "XML External Entities (XXE)":
        "Disable DTD processing and external entity resolution in XML parsers.",
    "Path Traversal":
        "Validate and sanitize file paths. Use allowlists and chroot/jail environments.",
    "Broken Access Control":
        "Enforce least-privilege access. Validate permissions server-side on every request.",
    "Insufficient Logging & Monitoring":
        "Log security-relevant events. Never swallow exceptions silently. Implement alerting for anomalies.",
}

# ─────────────────────────────────────────────────────────────────────────────
# Core Analysis Functions
# ─────────────────────────────────────────────────────────────────────────────

def detect_language(file_path):
    """Auto-detect language from file extension."""
    ext = os.path.splitext(file_path)[1].lower()
    return EXT_MAP.get(ext)


def analyze_file(file_path, language):
    """Scan a single file for vulnerability patterns. Returns a list of findings."""
    if language not in PATTERNS:
        return []

    vulnerabilities = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except (IOError, OSError) as e:
        print(f"{Fore.YELLOW}[!] Could not read {file_path}: {e}{Style.RESET_ALL}")
        return []

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
            continue  # skip comments and blank lines to reduce noise
        for vuln_type, pattern_list in PATTERNS[language].items():
            for pattern, severity in pattern_list:
                if pattern.search(line):
                    vulnerabilities.append({
                        "file": file_path,
                        "line_num": i,
                        "type": vuln_type,
                        "severity": severity,
                        "code": stripped[:120],  # truncate long lines
                    })
    return vulnerabilities


def scan_directory(dir_path, language=None):
    """Recursively scan a directory. Auto-detects language per file if not specified."""
    all_vulns = []
    files_scanned = 0
    skipped_dirs = {".git", "__pycache__", "node_modules", "venv", ".venv", "vendor", "bin", "obj"}

    for root, dirs, files in os.walk(dir_path):
        dirs[:] = [d for d in dirs if d not in skipped_dirs]
        for fname in files:
            fpath = os.path.join(root, fname)
            lang = language or detect_language(fpath)
            if lang and lang in PATTERNS:
                files_scanned += 1
                all_vulns.extend(analyze_file(fpath, lang))

    return all_vulns, files_scanned


def clone_and_scan(repo_url, language=None):
    """Clone a GitHub repository to a temp directory, scan it, then clean up."""
    tmp_dir = tempfile.mkdtemp(prefix="sca_")
    try:
        print(f"{Fore.CYAN}[*] Cloning repository: {repo_url}{Style.RESET_ALL}")
        result = subprocess.run(
            ["git", "clone", "--depth=1", repo_url, tmp_dir],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            print(f"{Fore.RED}[!] Git clone failed: {result.stderr.strip()}{Style.RESET_ALL}")
            return [], 0
        print(f"{Fore.GREEN}[✓] Clone successful. Scanning...{Style.RESET_ALL}")
        return scan_directory(tmp_dir, language)
    except FileNotFoundError:
        print(f"{Fore.RED}[!] 'git' is not installed or not in PATH.{Style.RESET_ALL}")
        return [], 0
    except subprocess.TimeoutExpired:
        print(f"{Fore.RED}[!] Git clone timed out after 120 seconds.{Style.RESET_ALL}")
        return [], 0
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────────────
# Output & Reporting
# ─────────────────────────────────────────────────────────────────────────────

def severity_badge(severity):
    """Return a colored severity label for terminal output."""
    color = SEVERITY_COLOR.get(severity, "")
    return f"{color}{severity}{Style.RESET_ALL}"


def display_results(vulnerabilities, files_scanned=0, output_file=None):
    """Display results as a terminal table and optional styled HTML report."""
    if not vulnerabilities:
        print(f"\n{Fore.GREEN}{'═'*60}")
        print(f"  ✅  No vulnerabilities detected.")
        if files_scanned:
            print(f"      Files scanned: {files_scanned}")
        print(f"{'═'*60}{Style.RESET_ALL}\n")
        return

    # Sort by severity
    vulnerabilities.sort(key=lambda v: SEVERITY_ORDER.get(v["severity"], 99))

    # Terminal table
    table = PrettyTable()
    table.field_names = ["#", "Severity", "Vulnerability", "File", "Line", "Code Snippet"]
    table.align["Code Snippet"] = "l"
    table.align["File"] = "l"
    table.max_width["Code Snippet"] = 60
    table.max_width["File"] = 40

    for idx, vuln in enumerate(vulnerabilities, 1):
        table.add_row([
            idx,
            severity_badge(vuln["severity"]),
            vuln["type"],
            os.path.basename(vuln["file"]),
            vuln["line_num"],
            vuln["code"][:60],
        ])

    # Summary stats
    stats = {}
    sev_counts = {}
    for v in vulnerabilities:
        stats[v["type"]] = stats.get(v["type"], 0) + 1
        sev_counts[v["severity"]] = sev_counts.get(v["severity"], 0) + 1

    print(f"\n{Fore.CYAN}{'═'*70}")
    print(f"  SecureCodeAnalyzer v{VERSION} — Scan Results")
    print(f"{'═'*70}{Style.RESET_ALL}")
    print(f"  Files scanned : {files_scanned}")
    print(f"  Total findings: {len(vulnerabilities)}")
    for sev in [CRITICAL, HIGH, MEDIUM, LOW]:
        cnt = sev_counts.get(sev, 0)
        if cnt:
            print(f"    {severity_badge(sev):>20s} : {cnt}")
    print(f"{Fore.CYAN}{'─'*70}{Style.RESET_ALL}\n")
    print(table)
    print()

    # HTML report
    if output_file:
        _generate_html_report(vulnerabilities, files_scanned, stats, sev_counts, output_file)


def _generate_html_report(vulnerabilities, files_scanned, stats, sev_counts, output_file):
    """Generate a styled HTML vulnerability report."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sev_color_html = {
        CRITICAL: "#e74c3c",
        HIGH: "#e67e22",
        MEDIUM: "#f1c40f",
        LOW: "#2ecc71",
    }

    rows = ""
    for idx, v in enumerate(vulnerabilities, 1):
        color = sev_color_html.get(v["severity"], "#ccc")
        solution = SOLUTIONS.get(v["type"], "N/A")
        code_escaped = (
            v["code"]
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
        rows += f"""
        <tr>
            <td>{idx}</td>
            <td><span class="badge" style="background:{color}">{v['severity']}</span></td>
            <td>{v['type']}</td>
            <td title="{v['file']}">{os.path.basename(v['file'])}</td>
            <td>{v['line_num']}</td>
            <td><code>{code_escaped}</code></td>
            <td class="solution">{solution}</td>
        </tr>"""

    summary_rows = ""
    for vtype, count in sorted(stats.items(), key=lambda x: -x[1]):
        summary_rows += f"<tr><td>{vtype}</td><td>{count}</td></tr>"

    sev_summary = ""
    for sev in [CRITICAL, HIGH, MEDIUM, LOW]:
        cnt = sev_counts.get(sev, 0)
        color = sev_color_html.get(sev, "#ccc")
        sev_summary += f'<span class="badge" style="background:{color}">{sev}: {cnt}</span> '

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecureCodeAnalyzer Report</title>
<style>
  :root {{ --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9; --accent: #58a6ff; }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; }}
  h1 {{ color: var(--accent); margin-bottom: .5rem; font-size: 1.8rem; }}
  .meta {{ color: #8b949e; margin-bottom: 1.5rem; font-size: .9rem; }}
  .cards {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
  .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.5rem; min-width: 140px; }}
  .card .num {{ font-size: 2rem; font-weight: 700; color: #fff; }}
  .card .label {{ font-size: .85rem; color: #8b949e; }}
  .badge {{ display:inline-block; padding: 2px 10px; border-radius: 12px; color: #fff; font-size: .75rem; font-weight: 700; }}
  table {{ width: 100%; border-collapse: collapse; background: var(--card); border-radius: 8px; overflow: hidden; margin-bottom: 2rem; }}
  th {{ background: #21262d; text-align: left; padding: 12px 14px; font-size: .8rem; text-transform: uppercase; letter-spacing: .5px; color: #8b949e; }}
  td {{ padding: 10px 14px; border-top: 1px solid var(--border); font-size: .85rem; vertical-align: top; }}
  tr:hover {{ background: #1c2128; }}
  code {{ background: #1c2128; padding: 2px 6px; border-radius: 4px; font-size: .8rem; word-break: break-all; }}
  .solution {{ color: #8b949e; font-size: .8rem; max-width: 250px; }}
  .summary-table {{ max-width: 400px; }}
  footer {{ text-align: center; margin-top: 3rem; color: #484f58; font-size: .8rem; }}
</style>
</head>
<body>
<h1>🔒 SecureCodeAnalyzer Report</h1>
<p class="meta">Generated: {timestamp} · v{VERSION}</p>

<div class="cards">
  <div class="card"><div class="num">{files_scanned}</div><div class="label">Files Scanned</div></div>
  <div class="card"><div class="num">{len(vulnerabilities)}</div><div class="label">Total Findings</div></div>
  <div class="card"><div class="label">Severity Breakdown</div><div style="margin-top:.5rem">{sev_summary}</div></div>
</div>

<h2 style="color:var(--accent);margin-bottom:.8rem">Findings</h2>
<table>
<thead><tr><th>#</th><th>Severity</th><th>Vulnerability</th><th>File</th><th>Line</th><th>Code</th><th>Remediation</th></tr></thead>
<tbody>{rows}
</tbody>
</table>

<h2 style="color:var(--accent);margin-bottom:.8rem">Summary by Category</h2>
<table class="summary-table">
<thead><tr><th>Vulnerability Type</th><th>Count</th></tr></thead>
<tbody>{summary_rows}</tbody>
</table>

<footer>SecureCodeAnalyzer v{VERSION} — OWASP Top 10 Static Analysis</footer>
</body>
</html>"""

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"{Fore.GREEN}[✓] HTML report saved to: {output_file}{Style.RESET_ALL}")
    except IOError as e:
        print(f"{Fore.RED}[!] Failed to write report: {e}{Style.RESET_ALL}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print(f"{Fore.CYAN}{BANNER}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}v{VERSION} — OWASP Top 10 Static Code Analyzer{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Supported languages: Python · Java · PHP · Ruby · C# (.NET){Style.RESET_ALL}\n")

    parser = argparse.ArgumentParser(
        description="SecureCodeAnalyzer — Static analysis for OWASP Top 10 vulnerabilities.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --file app.py --language python
  %(prog)s --dir ./src --language java
  %(prog)s --dir ./project                          (auto-detect languages)
  %(prog)s --github https://github.com/user/repo
  %(prog)s --file app.cs --language csharp --output report.html
        """,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", metavar="PATH", help="Analyze a single source file")
    group.add_argument("--dir", metavar="PATH", help="Recursively scan a directory")
    group.add_argument("--github", metavar="URL", help="Clone and scan a public GitHub repository")

    parser.add_argument(
        "--language", "-l",
        choices=SUPPORTED_LANGUAGES,
        default=None,
        help="Target language (optional for --dir/--github; auto-detected from extensions)",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Save results as a styled HTML report",
    )

    args = parser.parse_args()

    # ── Validate ─────────────────────────────────────────────────────────
    if args.file:
        if not os.path.isfile(args.file):
            print(f"{Fore.RED}[!] File not found: {args.file}{Style.RESET_ALL}")
            sys.exit(1)
        if not args.language:
            args.language = detect_language(args.file)
            if not args.language:
                print(f"{Fore.RED}[!] Could not detect language for '{args.file}'. Use --language.{Style.RESET_ALL}")
                sys.exit(1)
            print(f"{Fore.CYAN}[*] Auto-detected language: {args.language}{Style.RESET_ALL}")

    if args.dir and not os.path.isdir(args.dir):
        print(f"{Fore.RED}[!] Directory not found: {args.dir}{Style.RESET_ALL}")
        sys.exit(1)

    # ── Run scan ─────────────────────────────────────────────────────────
    if args.file:
        print(f"{Fore.CYAN}[*] Scanning file: {args.file} [{args.language}]{Style.RESET_ALL}")
        vulns = analyze_file(args.file, args.language)
        display_results(vulns, files_scanned=1, output_file=args.output)

    elif args.dir:
        print(f"{Fore.CYAN}[*] Scanning directory: {args.dir}{Style.RESET_ALL}")
        vulns, scanned = scan_directory(args.dir, args.language)
        display_results(vulns, files_scanned=scanned, output_file=args.output)

    elif args.github:
        vulns, scanned = clone_and_scan(args.github, args.language)
        display_results(vulns, files_scanned=scanned, output_file=args.output)


if __name__ == "__main__":
    main()
