# (●°u°●)​ 」 DeepKi Configuration
# Xiao Qi's settings file~ adjust me!

import os
from pathlib import Path

# ── Paths ──
BASE_DIR = Path(__file__).resolve().parent.parent
WORDLIST_DIR = BASE_DIR / "wordlists"
RESULT_DIR = BASE_DIR / "results"
TEMPLATE_DIR = BASE_DIR / "app" / "templates"
STATIC_DIR = BASE_DIR / "app" / "static"

# ── Database ──
DATABASE_URL = os.getenv("DEEPKI_DB", f"sqlite+aiosqlite:///{BASE_DIR}/deepki.db")

# ── Scan Settings ──
MAX_CONCURRENT_REQUESTS = int(os.getenv("DEEPKI_CONCURRENT", "50"))
REQUEST_TIMEOUT = int(os.getenv("DEEPKI_TIMEOUT", "10"))
SCAN_RATE_LIMIT = int(os.getenv("DEEPKI_RATE", "0"))  # 0 = no limit
USER_AGENT = "Deepki/1.0 (Xiao Qi Scanner; +https://github.com/deepki/scanner)"

# ── Module Defaults ──
DEFAULT_SCAN_MODE = "full"  # full | quick | custom

SCAN_MODULES = {
    "subdomain": {
        "enabled": True,
        "icon": "🔍",
        "name": "Subdomain Enum",
        "wordlist": "subdomains.txt",
    },
    "portscan": {
        "enabled": True,
        "icon": "🔌",
        "name": "Port Scanner",
        "ports": "80,443,8080,8443,3000,5000,8000,9090",
    },
    "directory": {
        "enabled": True,
        "icon": "📁",
        "name": "Directory Brute",
        "wordlist": "common_dirs.txt",
    },
    "tech_detect": {
        "enabled": True,
        "icon": "🖥️",
        "name": "Tech Fingerprint",
    },
    "vuln_scan": {
        "enabled": True,
        "icon": "💉",
        "name": "Vulnerability Scan",
        "templates_dir": "nuclei_templates",
    },
    "header_audit": {
        "enabled": True,
        "icon": "📋",
        "name": "Security Headers",
    },
    "cors_test": {
        "enabled": True,
        "icon": "🌐",
        "name": "CORS Tester",
    },
    "port_knock": {
        "enabled": False,
        "icon": "🚪",
        "name": "403 Bypass",
    },
}

# ── Vuln Signatures ──
VULN_SIGNATURES = {
    "sql_error": [
        "SQL syntax", "mysql_fetch", "ORA-\\d{5}", "PostgreSQL",
        "SQLite3::", "unclosed quotation mark", "Warning.*mysql_",
        "Microsoft OLE DB", "ODBC Driver", "JDBC.*error",
        "SQLSTATE", "syntax error.*at or near",
    ],
    "xss_reflect": [
        "XSS_TEST_MARKER_37291",
    ],
    "sensitive_files": [
        ".env", ".git/config", "wp-config.php.bak", "config.yml.bak",
        "backup.sql", "dump.sql", "adminer.php", "phpinfo.php",
    ],
    "open_redirect": [
        "redirect_uri", "redirect_url", "callback_url", "next=",
        "return_url", "target_url", "dest=",
    ],
}

# ── Server ──
HOST = os.getenv("DEEPKI_HOST", "0.0.0.0")
PORT = int(os.getenv("DEEPKI_PORT", "5000"))
DEBUG = os.getenv("DEEPKI_DEBUG", "true").lower() == "true"
