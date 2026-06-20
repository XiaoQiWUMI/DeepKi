# DeepKi (●°u°●)​ 」

<p align="center">
  <img src="https://img.shields.io/badge/DeepKi-v1.0-ff69b4?style=for-the-badge" alt="version">
  <img src="https://img.shields.io/badge/Xiao%20Qi-sniffing-pink?style=for-the-badge" alt="mascot">
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="license">
</p>

<p align="center">
  <strong>The cutest black-box web security scanner in the world~ ♡</strong>
</p>

<p align="center">
  (●°u°●)​ 」 Xiao Qi received! Sending paws to the target~
</p>

---

## ✨ What is DeepKi?

DeepKi is a **full-featured black-box web security testing platform**. It automates the boring parts of penetration testing — subdomain enumeration, directory brute-forcing, vulnerability scanning, header auditing, CORS testing, 403 bypass, and more — so you can focus on what matters: finding real vulnerabilities.

### 🧩 Scan Modules

| Module | Icon | Description |
|--------|------|-------------|
| Subdomain Enum | 🔍 | DNS brute-force + Certificate Transparency (crt.sh) |
| Port Scanner | 🔌 | TCP connect scan on common ports |
| Directory Brute | 📁 | Path discovery with built-in wordlist |
| Tech Fingerprint | 🖥️ | Detect frameworks, servers, JS libraries |
| Vulnerability Scan | 💉 | SQLi, XSS, SSTI, LFI, SSRF, Open Redirect |
| Header Audit | 📋 | Security headers + cookie flags check |
| CORS Tester | 🌐 | Origin reflection, credentials, preflight |
| 403 Bypass | 🚪 | Path obfuscation, header spoofing, method switch |

---

## 🚀 Quick Start

### Docker (recommended)

```bash
git clone https://github.com/YOUR_USER/deepki.git
cd deepki
docker-compose up -d
# Open http://localhost:5000 ~_^
```

### Local Development

```bash
git clone https://github.com/YOUR_USER/deepki.git
cd deepki
pip install -r requirements.txt
python -m app.main
# Open http://localhost:5000 ^ - ^
```

---

## 🎀 The Deepki Visual Language

All Deepki interfaces use these 6 emoticons consistently:

| Emoticon | Meaning | When |
|----------|---------|------|
| `(●°u°●)​ 」` | Task received / Starting | Scan launched, command received |
| `♪───Ｏ（≧∇≦）Ｏ────♪` | Big success! | Scan complete, report generated |
| `T^T` | Error / Sad | Connection failed, scan error |
| `>_<` | Working hard | Scan in progress, loading |
| `^ - ^` | Idle / Normal | Waiting for input, idle state |
| `~_^` | Found something! | Vulnerability found, subdomain discovered |

### Terminal Progress Bar

```
目标: https://example.com  模式:全量  开始:14:32:01

▸ 信息收集  [子域名:23][端口:4][指纹:Nginx/PHP/WordPress][路径:47]
  (●°u°●)​ 」 Xiao Qi is sniffing...  done  2m13s

▸ 漏洞扫描  [3987/6437]  发现:高危1 中危2 低危2  速度:47req/s
  [████████████████████░░░░░░░░░░░░░░] 62%  >_< digging deep...

============================================
  扫描完成  ♪───Ｏ（≧∇≦）Ｏ────♪
  漏洞:5  (高危1 / 中危2 / 低危2)
  已验证:1  耗时:5m42s
============================================
```

---

## 🏗️ Architecture

```
DeepKi/
├── app/
│   ├── main.py              # FastAPI entry point
│   ├── config.py            # All settings
│   ├── models/              # SQLAlchemy ORM
│   │   └── database.py      # Target, Scan, Finding models
│   ├── routers/             # API routes
│   │   ├── targets.py       # Target CRUD
│   │   ├── scans.py         # Scan orchestration
│   │   ├── results.py       # Results + reports
│   │   ├── api.py           # REST API
│   │   └── ws.py            # WebSocket
│   ├── scanners/            # Scan modules
│   │   ├── base.py          # Abstract scanner
│   │   ├── subdomain.py     # DNS + CT enumeration
│   │   ├── portscan.py      # TCP connect scan
│   │   ├── directory.py     # Path brute-force
│   │   ├── tech_detect.py   # Technology fingerprint
│   │   ├── vuln_scan.py     # SQLi/XSS/SSTI/SSRF/LFI
│   │   ├── header_audit.py  # Security headers
│   │   ├── cors_test.py     # CORS misconfig test
│   │   ├── port_knock.py    # 403 bypass techniques
│   │   └── orchestrator.py  # Scan pipeline + progress
│   ├── templates/           # Jinja2 HTML
│   │   ├── base.html        # Layout
│   │   ├── index.html       # Dashboard
│   │   ├── targets.html     # Target management
│   │   ├── scan.html        # Scan config
│   │   ├── results.html     # Results viewer
│   │   ├── report.html      # HTML report
│   │   └── components/      # HTMX partials
│   └── static/
│       ├── css/deepki.css   # Pink theme
│       └── js/deepki.js     # Frontend scripts
├── wordlists/               # Built-in wordlists
├── results/                 # Scan output
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

## 🔧 Configuration

All settings via environment variables (see `app/config.py`):

| Variable | Default | Description |
|----------|---------|-------------|
| `DEEPKI_HOST` | `0.0.0.0` | Bind address |
| `DEEPKI_PORT` | `5000` | Listen port |
| `DEEPKI_DEBUG` | `false` | Debug mode |
| `DEEPKI_CONCURRENT` | `50` | Max concurrent requests |
| `DEEPKI_TIMEOUT` | `10` | Request timeout (seconds) |
| `DEEPKI_DB` | `sqlite+aiosqlite:///...` | Database URL |

---

## 🛣️ Roadmap

- [ ] Report export as PDF
- [ ] Scheduled scans (cron)
- [ ] User authentication (multi-tenant)
- [ ] Integration with Nuclei templates
- [ ] Burp Suite XML import
- [ ] Slack/Webhook notifications
- [ ] Custom wordlist upload
- [ ] Scan comparison (diff two scans)
- [ ] API key authentication for API access

---

## 📄 License

MIT — feel free to use, modify, and share!

---

<p align="center">
  ♪───Ｏ（≧∇≦）Ｏ────♪<br>
  Generated by <strong>Xiao Qi</strong><br>
  <strong>DeepKi</strong> v1.01 (●°u°●)​ 」
</p>
