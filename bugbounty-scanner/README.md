# 🔍 AI-Powered Bug Bounty Autonomous Scanner

> **⚠️ LEGAL DISCLAIMER**: This tool is designed exclusively for authorized security testing, bug bounty programs, and educational research. Unauthorized use against systems you do not own or have explicit permission to test is illegal. The authors accept no liability for misuse.

---

## 🧠 Overview

The **AI-Powered Bug Bounty Autonomous Scanner** is a production-grade, modular autonomous vulnerability discovery system that mimics intelligent attacker behavior to discover security vulnerabilities in web applications.

### What Makes It Different

Unlike traditional rule-based scanners, this system:
- **Simulates attacker decision trees** using heuristic AI
- **Learns from bug bounty disclosures** to improve detection
- **Chains multi-step attacks** rather than isolated checks
- **Adapts payloads** based on application responses
- **Scores risks** using CVSS-like methodology

---

## 🏗️ Architecture

```
bugbounty-scanner/
├── core/               # Shared utilities, config, session management
├── recon/              # Reconnaissance engine (subdomains, DNS, WHOIS)
├── crawler/            # AI-powered web crawler
├── scanner/            # Vulnerability scanning modules
│   ├── sqli.py         # SQL Injection
│   ├── xss.py          # Cross-Site Scripting
│   ├── cmdi.py         # Command Injection
│   ├── idor.py         # IDOR detection
│   ├── auth.py         # Broken authentication
│   ├── upload.py       # File upload vulnerabilities
│   ├── traversal.py    # Directory traversal
│   └── api.py          # API misconfiguration
├── ai_engine/          # Heuristic AI + ML decision engine
├── risk_engine/        # CVSS-based risk scoring
├── reporter/           # HTML/JSON/Markdown report generation
├── cli/                # Command-line interface
├── dashboard/          # React/Next.js web dashboard
├── payloads/           # Payload wordlists
└── tests/              # Unit and integration tests
```

---

## 🚀 Quick Start

### Prerequisites

```bash
Python 3.10+
Node.js 18+
PostgreSQL 14+
```

### Backend Setup

```bash
# Clone and navigate
cd bugbounty-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your database credentials

# Initialize database
python -m core.database init

# Run API server
uvicorn core.api:app --reload --port 8000
```

### Frontend Setup

```bash
cd dashboard
npm install
npm run dev
# Open http://localhost:3000
```

### CLI Usage

```bash
# Basic scan
python -m cli.main scan --target example.com

# Full scan with all modules
python -m cli.main scan --target example.com --full --output report.html

# Recon only
python -m cli.main recon --target example.com

# Custom scan
python -m cli.main scan --target example.com \
  --modules sqli,xss,idor \
  --depth 3 \
  --threads 10 \
  --output json

# Continuous mode
python -m cli.main scan --target example.com --continuous --interval 3600
```

---

## 📦 Modules

| Module | Description | Status |
|--------|-------------|--------|
| Reconnaissance | Subdomain enum, DNS, WHOIS, port scan | ✅ Active |
| Web Crawler | AI-guided recursive crawling | ✅ Active |
| SQL Injection | Blind, error-based, time-based | ✅ Active |
| XSS | Reflected, stored, DOM-based | ✅ Active |
| Command Injection | OS command injection | ✅ Active |
| IDOR | Horizontal/vertical privilege escalation | ✅ Active |
| Auth Testing | Session, JWT, OAuth flaws | ✅ Active |
| File Upload | Malicious upload detection | ✅ Active |
| Directory Traversal | Path traversal attacks | ✅ Active |
| API Misconfig | REST/GraphQL security testing | ✅ Active |
| AI Attack Engine | Heuristic decision-making | ✅ Active |
| Risk Scoring | CVSS-based severity engine | ✅ Active |
| Report Generator | HTML/JSON/Markdown reports | ✅ Active |
| Dashboard | Real-time React dashboard | ✅ Active |

---

## ⚙️ Configuration

Edit `config.yaml`:

```yaml
scanner:
  max_depth: 5
  max_threads: 20
  timeout: 30
  user_agent: "BugBountyScanner/1.0"
  
ai_engine:
  confidence_threshold: 0.7
  learning_enabled: true
  
risk_scoring:
  cvss_version: "3.1"
  auto_escalate: true
  
reporting:
  formats: ["html", "json", "markdown"]
  include_poc: true
```

---

## 🔒 Ethics & Legal

This tool is intended for:
- ✅ Authorized penetration testing
- ✅ Bug bounty programs (HackerOne, Bugcrowd, etc.)
- ✅ Security research on owned systems
- ✅ CTF challenges

This tool must NOT be used for:
- ❌ Unauthorized scanning
- ❌ Production systems without permission
- ❌ Any illegal activity

---

## 📄 License

MIT License — See LICENSE file for details.
