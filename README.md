# BountyBot

**Automated Bug Bounty Hunter - Security Testing & Vulnerability Discovery Platform**

BountyBot is a comprehensive automation suite for ethical hackers and security researchers. It automates the entire bug bounty workflow from reconnaissance to reporting, allowing hunters to find more vulnerabilities in less time while maintaining professional standards.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![Django 4.2](https://img.shields.io/badge/django-4.2-green.svg)](https://www.djangoproject.com/)

---

## Table of Contents

- [Features](#features)
- [Project Status](#project-status)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Usage](#cli-usage)
- [How It Works](#how-it-works)
- [Scanning Pipeline](#scanning-pipeline)
- [Tech Stack](#tech-stack)
- [Development](#development)
- [Roadmap](#roadmap)
- [License](#license)

---

## Features

### Phase 1: Reconnaissance (COMPLETED ✅)

**Automated Information Gathering:**
- **Subdomain Enumeration** - Discover hidden subdomains using passive techniques
- **Port Scanning** - Identify open ports and running services
- **HTTP Probing** - Verify live HTTP endpoints and extract metadata
- **Technology Detection** - Identify web servers, frameworks, and technologies

**Key Capabilities:**
- 3-phase automated scanning pipeline
- Multiple scan profiles (quick, standard, deep)
- Real-time progress tracking
- Automatic finding storage and categorization
- Rich CLI with colored output and tables

### Phase 2: Vulnerability Scanning (PLANNED)

- CVE scanning with Nuclei (10,000+ templates)
- SQL injection testing with SQLMap
- XSS detection with Dalfox
- Directory fuzzing with FFuf
- WordPress scanning with WPScan

### Phase 3: Exploitation & Reporting (PLANNED)

- Automated proof-of-concept generation
- AI-powered report writing (Claude API)
- Multiple export formats (PDF, JSON, HTML)
- CVSS scoring and risk assessment

---

## Project Status

**Current Version:** 0.1.0 (Alpha)
**Development Phase:** Phase 1 Complete, Phase 2 In Progress

### What's Built

✅ **CLI Framework**
- Command-line interface with Typer + Rich
- Installable package (`pip install -e .`)
- Global `bountybot` command

✅ **Database Layer**
- PostgreSQL with Django ORM
- Models: Target, Scan, Finding
- Admin interface for data management

✅ **Scanner Integrations**
- Nmap (port scanning)
- HTTPx (HTTP probing)
- Subfinder (subdomain enumeration)

✅ **Automated Pipeline**
- 3-phase scanning workflow
- Automatic finding creation
- Scan status tracking
- Profile-based configuration

### What's Next

🔜 **Nuclei Integration** (CVE Scanning)
🔜 **SQLMap Integration** (SQL Injection)
🔜 **Dalfox Integration** (XSS Detection)
🔜 **Async Task Queue** (Celery for background scans)
🔜 **Report Generation** (PDF/JSON exports)

---

## Architecture

### Project Structure
```
bountybot/
├── bountybot/              # Django project settings
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
│
├── cli/                    # Command-line interface
│   ├── main.py            # CLI entry point
│   ├── commands/          # CLI command groups
│   │   ├── target.py     # Target management
│   │   ├── scan.py       # Scan execution
│   │   └── finding.py    # Finding management
│   └── utils/
│       └── scanners/      # Security tool integrations
│           ├── nmap_scanner.py
│           ├── httpx_prober.py
│           └── subfinder_enum.py
│
├── targets/               # Django app: Target management
│   ├── models.py         # Target model
│   ├── admin.py          # Admin interface
│   └── migrations/
│
├── scans/                 # Django app: Scan management
│   ├── models.py         # Scan model
│   ├── admin.py
│   └── migrations/
│
├── findings/              # Django app: Finding management
│   ├── models.py         # Finding model
│   ├── admin.py
│   └── migrations/
│
├── common/                # Shared utilities
│   ├── models.py         # Base models
│   └── utils.py
│
├── docker-compose.yml     # PostgreSQL + Redis
├── Dockerfile             # Container definition
├── requirements.txt       # Python dependencies
├── setup.py              # CLI installation
├── manage.py             # Django management
└── README.md             # This file
```

### Technology Stack

**Backend:**
- Python 3.12
- Django 4.2 (ORM, Admin, Database)
- PostgreSQL 16 (Primary database)
- Redis 7 (Caching, future task queue)

**CLI:**
- Typer 0.9 (CLI framework)
- Rich 13.7 (Terminal formatting)
- Click 8.1 (Typer dependency)

**Security Tools:**
- Nmap 7.94 (Port scanning)
- HTTPx 1.7.4 (HTTP probing)
- Subfinder 2.12.0 (Subdomain enumeration)
- Go 1.22.2 (Tool runtime)

**DevOps:**
- Docker & Docker Compose
- GitHub (Version control)
- Hetzner VPS (Production deployment)

---

## Installation

### Prerequisites

- Python 3.12
- Docker & Docker Compose
- Go 1.22+ (for security tools)
- Git

### 1. Clone Repository
```bash
git clone https://github.com/Xmas178/bountybot.git
cd bountybot
```

### 2. Install System Dependencies
```bash
# Install Nmap
sudo apt update
sudo apt install nmap -y

# Install Go (if not installed)
sudo apt install golang-go -y

# Verify installations
nmap --version
go version
```

### 3. Install Security Tools
```bash
# Add Go bin to PATH
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc

# Install Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install HTTPx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Verify installations
~/go/bin/subfinder -version
~/go/bin/httpx -version
```

### 4. Setup Python Environment
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Install BountyBot CLI
pip install -e .
```

### 5. Configure Environment
```bash
# Copy environment template
cp .env.example .env

# Edit .env with your settings
# Set SECRET_KEY, DATABASE_URL, etc.
```

### 6. Start Services
```bash
# Start PostgreSQL and Redis
docker compose up -d

# Run database migrations
python manage.py migrate

# Create admin user
python manage.py createsuperuser
```

### 7. Verify Installation
```bash
# Test CLI
bountybot --help
bountybot version

# Test database connection
python manage.py dbshell
```

---

## Quick Start

### Start Development Environment
```bash
# Navigate to project
cd /home/crake178/projects/bountybot

# Start databases
docker compose up -d

# Activate virtual environment
source venv/bin/activate
```

### Run Your First Scan
```bash
# 1. Add a target
bountybot target add scanme.nmap.org --name "Nmap Test Target" --type domain

# 2. Start a quick scan
bountybot scan start 1 --profile quick --execute

# 3. View results
bountybot scan status 1
bountybot finding list --scan 1

# 4. View detailed finding
bountybot finding show 1
```

### Stop Services
```bash
# Stop databases
docker compose down

# Deactivate virtual environment
deactivate
```

---

## CLI Usage

### Target Management
```bash
# Add targets
bountybot target add example.com --name "Example Inc" --type domain
bountybot target add 192.168.1.100 --name "Internal Server" --type ip
bountybot target add https://api.example.com --name "API" --type url

# List all targets
bountybot target list

# List only active targets
bountybot target list --active

# Delete target
bountybot target delete 1
bountybot target delete 1 --force  # Skip confirmation
```

### Scan Management
```bash
# Create scan (pending state)
bountybot scan start 1

# Create and execute immediately
bountybot scan start 1 --execute

# Use different scan profiles
bountybot scan start 1 --profile quick --execute     # Top 100 ports (~10s)
bountybot scan start 1 --profile standard --execute  # All ports (~1min)
bountybot scan start 1 --profile deep --execute      # Full scan (~5min)

# List all scans
bountybot scan list

# Filter scans
bountybot scan list --target 1
bountybot scan list --status completed

# Check scan status
bountybot scan status 1
```

### Finding Management
```bash
# List all findings
bountybot finding list

# Filter findings
bountybot finding list --scan 1
bountybot finding list --severity critical
bountybot finding list --status new

# View detailed finding
bountybot finding show 1

# Manually add finding
bountybot finding add 1 \
  --title "SQL Injection in login" \
  --severity critical \
  --description "Username parameter vulnerable to SQLi"
```

### General Commands
```bash
# Show help
bountybot --help
bountybot scan --help
bountybot target --help

# Show version
bountybot version
```

---

## How It Works

### 3-Phase Scanning Pipeline

BountyBot executes scans in three automated phases:

#### Phase 0: Subdomain Enumeration (Domain targets only)

**Tool:** Subfinder
**Purpose:** Discover hidden subdomains
**Duration:** 20-60 seconds

**What happens:**
1. Query 40+ passive sources (crt.sh, VirusTotal, Shodan, etc.)
2. Discover subdomains (api.example.com, dev.example.com, etc.)
3. Create finding for each subdomain

**Example output:**
```
Phase 0: Subdomain enumeration...
  Found 6 subdomains
```

#### Phase 1: Port Scanning

**Tool:** Nmap
**Purpose:** Identify open ports and services
**Duration:** 10-300 seconds (depends on profile)

**What happens:**
1. Scan ports based on profile:
   - Quick: Top 100 common ports
   - Standard: All 65535 ports
   - Deep: All ports + OS detection + NSE scripts
2. Identify running services (SSH, HTTP, MySQL, etc.)
3. Create finding for each open port

**Example output:**
```
Phase 1: Port scanning with nmap...
  Found 2 open ports
```

#### Phase 2: HTTP Probing

**Tool:** HTTPx
**Purpose:** Verify HTTP endpoints and detect technologies
**Duration:** 5-30 seconds

**What happens:**
1. Test all discovered ports for HTTP/HTTPS
2. Extract metadata:
   - HTTP status codes
   - Page titles
   - Web servers (nginx, Apache, etc.)
   - Technologies (WordPress, React, etc.)
   - Content lengths
3. Create finding for each live HTTP endpoint

**Example output:**
```
Phase 2: Probing HTTP endpoints...
  Found 2 active HTTP endpoints

✓ Scan completed!
  Open Ports: 2
  HTTP Endpoints: 2
  Total Findings: 10
  Duration: 0:01:04
```

### Scan Profiles

| Profile | Ports Scanned | Service Detection | OS Detection | Duration | Use Case |
|---------|--------------|-------------------|--------------|----------|----------|
| **quick** | Top 100 | ✅ | ❌ | ~10s | Fast recon |
| **standard** | All 65535 | ✅ | ❌ | ~1-2min | Thorough scan |
| **deep** | All 65535 | ✅ | ✅ | ~5-10min | Complete analysis |

### Finding Severity Levels

| Severity | Color | Description | Examples |
|----------|-------|-------------|----------|
| **CRITICAL** | Red | Immediate security risk | SQL injection, RCE |
| **HIGH** | Red | Serious vulnerability | XSS, Authentication bypass |
| **MEDIUM** | Yellow | Potential security issue | Missing headers, Outdated software |
| **LOW** | Blue | Minor security concern | Information disclosure |
| **INFO** | Gray | Informational only | Open ports, Subdomains |

---

## Tech Stack

### Core Technologies

**Python 3.12**
- Primary programming language
- Type hints throughout codebase
- Async/await support

**Django 4.2**
- ORM for database operations
- Admin interface for data management
- Model-based architecture

**PostgreSQL 16**
- Primary data storage
- Stores targets, scans, findings
- Full-text search capabilities

**Redis 7**
- Caching layer
- Future: Celery task queue backend

### CLI Framework

**Typer 0.9**
- Modern CLI framework
- Type-based command definition
- Automatic help generation

**Rich 13.7**
- Beautiful terminal output
- Tables, progress bars, colors
- Professional UI/UX

### Security Tools

**Nmap** (System package)
- Industry-standard port scanner
- Service version detection
- OS fingerprinting
- NSE scripting engine

**HTTPx** (Go binary)
- Fast HTTP probing
- Technology detection
- JSON output support
- 1000+ URLs per second

**Subfinder** (Go binary)
- Passive subdomain enumeration
- 40+ data sources
- Fast concurrent queries
- No rate limiting issues

### Development Tools

**Docker & Docker Compose**
- Containerized databases
- Consistent development environment
- Easy deployment

**Git & GitHub**
- Version control
- Collaboration
- CI/CD ready

---

## Development

### Development Setup
```bash
# Start databases
docker compose up -d

# Activate venv
source venv/bin/activate

# Run migrations
python manage.py migrate

# Start Django development server (optional)
python manage.py runserver
```

### Access Admin Interface
```bash
# Create superuser (first time only)
python manage.py createsuperuser

# Start server
python manage.py runserver

# Visit http://localhost:8000/admin
```

### Database Management
```bash
# Create migrations after model changes
python manage.py makemigrations

# Apply migrations
python manage.py migrate

# Drop into database shell
python manage.py dbshell

# Django shell
python manage.py shell
```

### Running Tests
```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_nmap.py

# Run with coverage
pytest --cov=cli --cov=targets --cov=scans --cov=findings
```

### Code Quality
```bash
# Format code with Black
black .

# Lint with Ruff
ruff check .

# Type checking
mypy cli/
```

---

## Roadmap

### Phase 1: Reconnaissance ✅ (COMPLETED)

- ✅ CLI framework with Typer + Rich
- ✅ Django models (Target, Scan, Finding)
- ✅ Nmap integration (port scanning)
- ✅ HTTPx integration (HTTP probing)
- ✅ Subfinder integration (subdomain enumeration)
- ✅ 3-phase automated pipeline
- ✅ PostgreSQL database
- ✅ Admin interface

### Phase 2: Vulnerability Scanning 🔄 (IN PROGRESS)

**Priority 1:**
- 🔜 Nuclei integration (CVE scanning with 10,000+ templates)
- 🔜 Whatweb integration (deep technology detection)

**Priority 2:**
- 🔜 SQLMap integration (SQL injection testing)
- 🔜 Dalfox integration (XSS detection)
- 🔜 Nikto integration (web vulnerability scanner)

**Priority 3:**
- 🔜 FFuf integration (directory fuzzing)
- 🔜 WPScan integration (WordPress scanning)
- 🔜 Arjun integration (parameter discovery)

### Phase 3: Performance & Scale 📅 (PLANNED)

- Celery task queue (async scanning)
- Real-time progress updates
- Scan result caching
- Multi-target batch scanning
- API rate limiting
- Distributed scanning support

### Phase 4: Reporting & AI 📅 (PLANNED)

- PDF report generation
- JSON export functionality
- Claude API integration (AI-powered reports)
- CVSS scoring automation
- Risk assessment engine
- Finding deduplication
- Executive summary generation

### Phase 5: Web Interface 📅 (FUTURE)

- React frontend
- Real-time scan monitoring
- Finding management dashboard
- Target organization
- Scan scheduling
- Team collaboration features

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Guidelines

1. **Code Style**
   - Follow PEP 8 for Python
   - Use type hints
   - Write docstrings for all functions
   - Keep functions under 50 lines

2. **Commits**
   - Use conventional commit messages
   - One feature per commit
   - Test before committing

3. **Documentation**
   - Update README for new features
   - Add docstrings to new functions
   - Include usage examples

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Author

**Sami Tommilammi**
Website: [tommilammi.fi](https://tommilammi.fi)
GitHub: [@Xmas178](https://github.com/Xmas178)

---

## Disclaimer

This tool is for educational and authorized security testing purposes only. Always obtain proper authorization before scanning any systems you do not own. The author is not responsible for any misuse or damage caused by this tool.

---

## Acknowledgments

- ProjectDiscovery for HTTPx and Subfinder
- Nmap Project for the industry-standard port scanner
- Django Project for the excellent web framework
- Typer and Rich for making beautiful CLIs easy

---

**Happy Bug Hunting! 🎯🐛**