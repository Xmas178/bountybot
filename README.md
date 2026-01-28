# BountyBot - Automated Bug Bounty Reconnaissance Platform

Automated security testing platform combining reconnaissance, vulnerability scanning, and AI-powered analysis for bug bounty hunting.

**Status:** Phase 2.5 Complete + AI Features - Production Ready

## Features

### Core Scanning (Phase 2.5 - COMPLETE ✅)
- **Subdomain Enumeration** - subfinder integration for passive DNS discovery
- **Port Scanning** - nmap with configurable profiles (quick/standard/deep)
- **HTTP Probing** - httpx for live endpoint detection
- **Technology Detection** - WhatWeb for stack fingerprinting
- **CVE Scanning** - nuclei templates for known vulnerabilities
- **SQL Injection Testing** - SQLMap with intelligent DBMS detection
- **XSS Detection** - dalfox for reflected/stored XSS
- **Web Server Scanning** - nikto for common misconfigurations
- **Directory Fuzzing** - ffuf with profile-based wordlists
- **WordPress Scanning** - wpscan for WP-specific vulnerabilities

### AI-Powered Analysis (Phase 4.1 - COMPLETE ✅)
- **Intelligent Prioritization** - Claude Sonnet 4.5 analyzes findings and recommends TOP 10 targets
- **Actionable Guidance** - Specific manual testing steps for each finding
- **Bounty Estimation** - AI estimates potential payout ranges
- **Time Estimates** - Realistic testing time per vulnerability
- **Burp Suite Integration** - Concrete next steps for manual testing

### PoC Generation (Phase 4.2 - COMPLETE ✅)
- **Automated Exploit Scripts** - Python/Bash PoC generation using Claude API
- **VDP Compliance** - Safe, passive-only testing for VDP programs
- **Multiple Formats** - Python scripts, Bash scripts, cURL commands, HackerOne reports
- **Educational** - Clear comments explaining each test step
- **Customizable** - TODO markers for user-specific modifications

### Error Handling (Phase 2.5 - COMPLETE ✅)
- **Graceful Failures** - Tools continue even if one scanner fails
- **Retry Logic** - Automatic retries (2-3x) for transient failures
- **Centralized Logging** - Per-scan log files in `logs/scan_<id>.log`
- **Tool Validation** - Pre-scan checks for all required security tools
- **User-Friendly Errors** - Clear error messages with solutions

## Technology Stack

- **Backend:** Django 5.0, PostgreSQL, Redis
- **CLI:** Typer, Rich (colored terminal output)
- **AI Integration:** Anthropic Claude Sonnet 4.5
- **Security Tools:** 10 integrated scanners (subfinder, nmap, httpx, nuclei, sqlmap, dalfox, nikto, ffuf, wpscan, whatweb)
- **Infrastructure:** Docker, Docker Compose

## Installation

### Prerequisites

```bash
# System requirements
- Python 3.12
- Docker & Docker Compose
- Git

# Security tools (auto-checked at scan start)
- subfinder
- nmap
- httpx
- nuclei
- sqlmap
- dalfox
- nikto
- ffuf
- wpscan
- whatweb
```

### Quick Start

```bash
# Clone repository
git clone https://github.com/Xmas178/bountybot.git
cd bountybot

# Start services
docker compose up -d

# Setup Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and add ANTHROPIC_API_KEY

# Initialize database
python manage.py migrate

# Install CLI
pip install -e .
```

## Usage

### Basic Workflow

```bash
# 1. Add target
bountybot target add example.com --name "Example Inc" --type domain

# 2. Start scan
bountybot scan start 1 --profile standard --execute

# 3. Analyze with AI
bountybot analyze prioritize --scan 1

# 4. Generate PoC for top finding
bountybot finding generate-poc 123

# 5. Run PoC (review first!)
python pocs/poc_123_*.py
```

### Scan Profiles

- **quick** - Fast reconnaissance (5-10 min)
  - Subdomain enum, port scan, HTTP probe
  - Skip slow scanners (nikto, ffuf)

- **standard** - Balanced approach (20-30 min)
  - All reconnaissance phases
  - Selective vulnerability scanning
  - User prompts for slow tools

- **deep** - Comprehensive audit (60-90 min)
  - Full reconnaissance
  - All vulnerability scanners
  - Large wordlists, aggressive scanning

### AI Prioritization

```bash
# Get TOP 10 findings with actionable steps
bountybot analyze prioritize --scan 1

# Filter by severity
bountybot analyze prioritize --scan 1 --min-severity high

# Get TOP 5 instead of 10
bountybot analyze prioritize --scan 1 --top 5
```

**Output Example:**
```
🎯 TOP 10 MANUAL TESTING TARGETS

#1 [HIGH] SQL Injection in /api/users endpoint
   Why: PostgreSQL backend allows UNION SELECT for data extraction
   Action: Burp Suite: test user_id param with UNION queries
   Time: 30-45 min | Bounty: $2k-10k

#2 [CRITICAL] cardmanager subdomain exposed
   Why: Payment card data handling, potential IDOR vulnerabilities
   Action: Test /api/cards endpoint for card enumeration
   Time: 45-60 min | Bounty: $10k-25k
```

### PoC Generation

```bash
# Generate Python PoC (default)
bountybot finding generate-poc 123

# Generate HackerOne report
bountybot finding generate-poc 123 --format report

# Generate Bash script
bountybot finding generate-poc 123 --format bash

# Custom output location
bountybot finding generate-poc 123 --output /tmp/exploit.py
```

## Command Reference

### Target Management
```bash
bountybot target add <domain/ip> --name "Name" --type <domain|ip|url>
bountybot target list
bountybot target show <id>
```

### Scan Management
```bash
bountybot scan start <target_id> --profile <quick|standard|deep> --execute
bountybot scan list
bountybot scan show <id>
```

### Finding Management
```bash
bountybot finding list --scan <id>
bountybot finding show <id>
bountybot finding generate-poc <id> [--format python|bash|report]
```

### AI Analysis
```bash
bountybot analyze prioritize --scan <id> [--top N] [--min-severity LEVEL]
```

## Project Status

### ✅ Completed (Phase 2.5 + AI)
- [x] Django backend with PostgreSQL
- [x] CLI interface (Typer + Rich)
- [x] 10 security tool integrations
- [x] Multi-phase scanning pipeline
- [x] Error handling & retry logic
- [x] Centralized logging system
- [x] Tool validation checks
- [x] AI-powered prioritization (Claude Sonnet 4.5)
- [x] Automated PoC generation
- [x] VDP-compliant testing modes

### 🚧 In Progress (Phase 3-4)
- [ ] Unified report generation (PDF/HTML/MD/JSON)
- [ ] Finding deduplication
- [ ] SQLMap output parsing improvements
- [ ] Async/parallel scanning operations

### 📋 Planned (Phase 5+)
- [ ] n8n intelligence monitoring (new programs, scope changes)
- [ ] Web GUI (React + FastAPI)
- [ ] Screenshot capture
- [ ] Additional scanners (organic growth based on needs)

### 🔐 Future Projects
- [ ] **Web3Bot** - Smart contract security scanner (Slither, Mythril, Echidna) for DeFi bug bounties ($10k-100k+)

## Architecture

```
bountybot/
├── cli/                    # CLI commands and utilities
│   ├── commands/          # Typer command modules
│   │   ├── target.py
│   │   ├── scan.py
│   │   ├── finding.py
│   │   └── analyze.py     # AI prioritization
│   └── utils/             # Scanning utilities
│       ├── scanners/      # Tool integrations (10 scanners)
│       ├── scan_executor.py
│       ├── logger.py      # Centralized logging
│       ├── error_handler.py
│       ├── ai_analyzer.py # Claude API integration
│       └── poc_generator.py
├── findings/              # Django app for findings
├── scans/                 # Django app for scans
├── targets/               # Django app for targets
├── pocs/                  # Generated PoC scripts
├── logs/                  # Per-scan log files
└── docker-compose.yml
```

## Security & Ethics

### Responsible Disclosure
- Only test targets with explicit permission
- Bug bounty programs with valid scope
- Your own infrastructure for testing
- Authorized penetration testing engagements

### VDP Compliance
BountyBot generates VDP-safe PoCs by default:
- No brute force attacks
- No authentication bypass attempts
- No denial of service
- Passive reconnaissance only

### Legal Notice
**Use BountyBot responsibly and legally:**
- ✅ Bug bounty programs (read scope!)
- ✅ Your own systems
- ✅ Authorized pentests
- ❌ Unauthorized systems
- ❌ Systems without permission

Unauthorized access to computer systems is illegal. Always obtain explicit written permission before testing.

## Development

### Running Tests
```bash
python manage.py test
```

### Database Migrations
```bash
python manage.py makemigrations
python manage.py migrate
```

### Adding New Scanners
See `cli/utils/scanners/` for examples. Each scanner should:
1. Implement error handling
2. Return standardized findings
3. Support profile-based configuration
4. Include retry logic for failures

## License

MIT License - see LICENSE file for details

## Author

**Sami Tommilammi** (CodeNob Dev)
- GitHub: [@Xmas178](https://github.com/Xmas178)
- Portfolio: [tommilammi.fi](https://tommilammi.fi)

## Acknowledgments

- Security tools: subfinder, nmap, httpx, nuclei, sqlmap, dalfox, nikto, ffuf, wpscan, whatweb
- AI: Anthropic Claude Sonnet 4.5
- Framework: Django, Typer, Rich
- Bug bounty platforms: HackerOne, Bugcrowd, Intigriti

---

**Note:** BountyBot automates the ~10% reconnaissance phase of bug bounty hunting. The remaining ~90% requires manual testing with tools like Burp Suite to find business logic flaws, complex IDOR chains, and authentication bypasses.
