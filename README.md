# BountyBot

**Automated Bug Bounty Reconnaissance & Vulnerability Discovery Platform**

A comprehensive security testing automation suite designed for ethical hackers and bug bounty hunters. BountyBot automates the entire workflow from reconnaissance to vulnerability detection, enabling researchers to find more security issues in less time.

---

## Project Vision

BountyBot aims to be the ultimate all-in-one bug bounty automation platform, integrating 60+ industry-standard security tools into a unified CLI interface with intelligent automation, real-time monitoring, and AI-powered reporting.

**"First to report wins"** - BountyBot's n8n intelligence platform monitors bug bounty programs 24/7, automatically triggering scans on new targets to give you the competitive edge.

---

## Current Status: Phase 2.5 Complete (10/63 Tools Integrated)

### Phase 1: Reconnaissance Engine - COMPLETE
**Subdomain Enumeration & Port Scanning**

- **subfinder** - Fast passive subdomain discovery (40+ sources)
- **nmap** - Network port scanner (TCP/UDP, service enumeration)
- **httpx** - HTTP probing with technology detection

**Capabilities:**
- Automated subdomain discovery
- Comprehensive port scanning (65,535 ports)
- HTTP/HTTPS endpoint identification
- Service version detection

---

### Phase 2: Vulnerability Scanning Pipeline - COMPLETE
**Comprehensive Security Testing (7 Scanner Categories)**

#### Technology Detection
- **whatweb** - Website fingerprinting (1,800+ plugins)
  - CMS detection (WordPress, Joomla, Drupal)
  - Framework identification (Laravel, Django, React)
  - Server software (Apache, nginx, IIS)
  - Database hints (MySQL, PostgreSQL, MongoDB)

#### CVE & Exploit Detection
- **nuclei** - Template-based vulnerability scanner (10,000+ templates)
  - Known CVEs (2015-2024)
  - Misconfigurations
  - Exposed panels
  - Sensitive file exposure

#### Injection Vulnerabilities
- **sqlmap** - SQL injection testing
  - Boolean-based blind
  - Time-based blind
  - Error-based
  - UNION query-based
  - Stacked queries
  - Database: MySQL, PostgreSQL, SQLite, MSSQL, Oracle

- **dalfox** - XSS (Cross-Site Scripting) detection
  - Reflected XSS
  - Stored XSS
  - DOM-based XSS
  - 1,000+ payloads

#### Web Server Security
- **nikto** - Web server vulnerability scanner (6,700+ tests)
  - Server misconfigurations
  - Default files/directories
  - Outdated software versions
  - Dangerous files/programs
  - Missing security headers

#### Content Discovery
- **ffuf** - Fast web fuzzer
  - Hidden directories (/admin, /backup, /test)
  - Backup files (.bak, .old, database.sql)
  - Configuration files (.env, config.php)
  - Source code exposure (.git, .svn)
  - API endpoints

#### CMS-Specific Testing
- **wpscan** - WordPress security scanner (conditional)
  - WordPress core vulnerabilities
  - Plugin vulnerabilities (30,000+ known issues)
  - Theme vulnerabilities
  - User enumeration
  - Configuration issues

**Pipeline Features:**
- Sequential 9-phase execution (Phase 0-9)
- Three scan profiles (quick/standard/deep)
- Non-interactive mode with --yes flag
- Interactive confirmations for slow scanners (Nikto, FFuf, WPScan)
- Conditional scanning (WordPress-only when detected)
- Intelligent DBMS detection (WhatWeb to SQLMap optimization)
- Automatic severity classification (critical/high/medium/low/info)
- PostgreSQL storage with full finding details
- Comprehensive PoC and remediation guidance

---

## Phase 2.5: Optimizations - COMPLETE

**Performance & Intelligence Improvements**

- **Deep Profile Non-Interactive Mode**
  - --yes flag bypasses all user prompts
  - Enables fully automated scanning
  - Production-ready for scheduled scans

- **Custom Scanner Parameters**
  - SQLMap: --sqlmap-level, --sqlmap-risk, --sqlmap-threads
  - Nuclei: --nuclei-severity, --nuclei-tags
  - FFuf: --ffuf-wordlist, --ffuf-threads

- **WhatWeb to SQLMap Integration**
  - Auto-detect database type from WhatWeb
  - Pass --dbms to SQLMap (9x faster scans)
  - Skip unnecessary database tests

- **Scan Pipeline Refactoring**
  - Reduced scan.py from 1000+ to 200 lines
  - Created modular scan_executor.py
  - Phase-specific functions for better maintenance
  - Improved code organization

- **Permission & Sudo Fixes**
  - Deep profile works without sudo requirements
  - Fixed httpx/subfinder sudo detection
  - Removed problematic Nmap OS detection

- **Performance Optimizations**
  - Duplicate result elimination
  - Proper timeout handling
  - Multi-threading support
  - Configurable output paths for VPS deployment

---

## Phase 3: n8n Intelligence Platform (PLANNED)

**Automated Bug Bounty Program Monitoring**

**The "First to Report Wins" Advantage:**

BountyBot's n8n workflow automation monitors bug bounty platforms 24/7, detecting new programs and scope changes in real-time. When a new target is discovered, BountyBot automatically triggers a scan, giving you hours or days head start over competitors.

### Monitoring Capabilities

**Platform Integration:**
- HackerOne API integration
- Bugcrowd API integration
- Intigriti API integration
- YesWeHack API integration
- HackenProof API integration

**Detection Features:**
- New program detection
- Scope change alerts (new domains/IPs added)
- Bounty amount changes
- Program status updates (public/private)

**Intelligent Filtering:**
- Minimum bounty threshold filtering
- Technology stack preferences (WordPress, React, etc.)
- Scope complexity analysis
- Target country/region filtering

**Automation & Notifications:**
- Discord real-time notifications
  - New programs matching criteria
  - Scope changes on monitored programs
  - Scan completion alerts
  - High/critical findings detected

- Auto-scan triggers
  - Automatic BountyBot scan on new programs
  - Configurable scan profile (quick/standard/deep)
  - Rate limiting and scheduling

**Competitive Analysis:**
- Track program age (early detection = less competition)
- Monitor disclosed report trends
- Identify underexplored programs

---

## Phase 4: AI-Powered Reporting & PoC Generation (PLANNED)

**Claude API Integration for Professional Security Reports**

### Automated Report Generation

**AI Report Writer:**
- Claude Sonnet 4 integration
- Context-aware vulnerability descriptions
- Professional technical writing
- CVSS 3.1 scoring with justification
- Impact analysis and risk assessment

**Export Formats:**
- PDF reports (professional formatting)
- HTML reports (interactive)
- JSON exports (API integration)
- Markdown (GitHub/documentation)

**Proof of Concept Generation:**
- Automated PoC scripts
- Step-by-step reproduction guides
- cURL commands for API vulnerabilities
- Browser automation scripts (Selenium/Playwright)
- Video recording of exploitation (asciinema)

**Report Templates:**
- HackerOne report format
- Bugcrowd submission format
- Custom vulnerability disclosure
- Penetration testing reports

**Intelligence Features:**
- Duplicate vulnerability detection
- Similar finding aggregation
- Remediation priority recommendations
- Executive summary generation

---

## Phase 5: Web GUI (PLANNED - After Phase 4)

**Modern React + FastAPI Web Interface**

### Frontend (React + TypeScript)

**Dashboard:**
- Real-time scan progress visualization
- Finding statistics and charts
- Severity breakdown (critical/high/medium/low)
- Recent scans timeline

**Scan Management:**
- Interactive scan configuration
  - Target input with validation
  - Profile selection (quick/standard/deep)
  - Phase selection (enable/disable individual scanners)
  - Advanced options per scanner (SQLMap levels, Nuclei tuning, etc.)
- Live scan output streaming
- Pause/resume/cancel scans
- Scan scheduling and queuing

**Finding Management:**
- Filterable finding list (severity, tool, status)
- Finding detail view with PoC
- Status workflow (new, reviewing, verified, reported, duplicate, false positive)
- Notes and collaboration
- Export individual findings

**Target Management:**
- Target database with tags
- Historical scan results per target
- Scope definition and validation
- Asset inventory

**Configuration:**
- User preferences
- Scanner configuration (enable/disable tools)
- Notification settings
- API key management
- n8n workflow configuration

### Backend (FastAPI)

**API Endpoints:**
- RESTful API for all operations
- WebSocket for real-time updates
- Authentication (JWT tokens)
- Rate limiting
- API documentation (Swagger/OpenAPI)

**Background Tasks:**
- Celery task queue for scans
- Redis for caching and real-time updates
- Scan scheduling system
- Notification delivery

---

## Phase 6+: Additional Security Tools (PLANNED - 50+ Tools)

**Comprehensive Tool Integration (Organic Growth)**

The following tools are planned for integration based on user needs and bug bounty requirements. Priority will be determined by real-world testing feedback.

### Reconnaissance Tools (19 remaining)

**Subdomain Enumeration:**
- **Amass** - In-depth subdomain enumeration (OWASP)
- **Assetfinder** - Find domains and subdomains
- **Findomain** - Cross-platform subdomain enumerator

**Port Scanning:**
- **Masscan** - Fast TCP port scanner (1M packets/sec)
- **RustScan** - Modern port scanner (Rust-based)

**Technology Detection:**
- **Wappalyzer** - Technology profiler
- **Webanalyze** - Technology detection CLI

**Visual Reconnaissance:**
- **Aquatone** - Visual reconnaissance (screenshots)
- **EyeWitness** - Screenshot tool with reporting
- **Gowitness** - Website screenshot utility (Go-based)

**Content Discovery:**
- **Gobuster** - Directory/file bruteforcer
- **Dirsearch** - Web path scanner
- **Feroxbuster** - Content discovery (Rust-based)

**Parameter Discovery:**
- **ParamSpider** - Parameter mining from archives
- **Arjun** - HTTP parameter discovery
- **x8** - Hidden parameter finder

**JavaScript Analysis:**
- **LinkFinder** - Endpoint discovery in JavaScript
- **SecretFinder** - Secrets in JavaScript files
- **JSParser** - JavaScript code analyzer

**OSINT & Data Gathering:**
- **gau** - Fetch known URLs (getallurls)
- **waybackurls** - Wayback Machine URL fetcher
- **theHarvester** - OSINT gathering tool
- **Hunter.io** - Email address finder
- **Shodan** - Internet-connected device search
- **Censys** - Internet scan data platform

### Vulnerability Scanners (6 remaining)

**Web Application Security:**
- **OWASP ZAP** - Comprehensive web app security scanner
- **Burp Suite Community** - Web vulnerability scanner
- **Wapiti** - Web application vulnerability scanner

**Injection Vulnerabilities:**
- **NoSQLMap** - NoSQL injection exploitation
- **XSStrike** - Advanced XSS detection
- **XSSer** - XSS detection and exploitation
- **SSRFmap** - SSRF exploitation framework
- **XXEinjector** - XXE injection testing
- **tplmap** - Server-side template injection
- **CRLFuzz** - CRLF injection fuzzer

**SSL/TLS Testing:**
- **testssl.sh** - SSL/TLS vulnerability scanner

### Authentication & API Tools (3 tools)

**Browser Automation:**
- **Selenium** - Web browser automation
- **Playwright** - Modern browser automation
- **Puppeteer** - Headless Chrome/Chromium

**API Security:**
- **jwt_tool** - JWT security testing

### Infrastructure Security (6 tools)

**Cloud Security:**
- **bucket-stream** - AWS S3 bucket finder
- **S3Scanner** - S3 bucket scanner and dumper

**Subdomain Takeover:**
- **SubOver** - Subdomain takeover detection
- **subjack** - Subdomain takeover scanner

**DNS Security:**
- **DNSRecon** - DNS enumeration tool
- **fierce** - DNS reconnaissance scanner

### Utility Tools (6 tools)

**HTTP Utilities:**
- **curl** - Command-line data transfer
- **jq** - JSON processor
- **yq** - YAML processor

**Recording & Documentation:**
- **asciinema** - Terminal session recorder

### Custom BountyBot Tools (3 tools)

**Proprietary Logic:**
- **BountyBot Custom Scanner** - Unique vulnerability detection logic
- **BountyBot AI Analyzer** - Claude-powered intelligent analysis
- **BountyBot Reporter** - Advanced report generation

---

## Tech Stack

### Backend
- **Python 3.12** - Core language (locked, do NOT upgrade to 3.13)
- **Django 4.2** - Web framework and ORM
- **PostgreSQL 16** - Primary database
- **Redis 7** - Caching and task queue
- **Celery** - Distributed task queue (planned Phase 5)

### CLI Interface
- **Typer** - CLI framework
- **Rich** - Terminal formatting and tables
- **Click** - Command-line utilities

### Frontend (Planned Phase 5)
- **React 18** - UI framework
- **TypeScript** - Type safety
- **Tailwind CSS** - Styling
- **Material-UI** - Component library
- **Recharts** - Data visualization

### DevOps
- **Docker** - Containerization
- **Docker Compose** - Multi-container orchestration
- **GitHub Actions** - CI/CD (planned)

### Security Tools
- **subfinder** - Subdomain enumeration
- **nmap** - Port scanning
- **httpx** - HTTP probing
- **nuclei** - CVE scanning
- **whatweb** - Technology detection
- **sqlmap** - SQL injection testing
- **dalfox** - XSS detection
- **nikto** - Web server vulnerabilities
- **ffuf** - Web fuzzing
- **wpscan** - WordPress scanning

### AI Integration (Phase 4)
- **Claude API (Anthropic)** - Sonnet 4 for report generation
- **OpenAI API** - GPT-4 alternative (optional)

### Automation (Phase 3)
- **n8n** - Workflow automation platform
- **Discord API** - Real-time notifications

---

## Installation

### Prerequisites

- **Python 3.12** (do NOT use 3.13)
- **Docker & Docker Compose**
- **Git**
- **Go 1.20+** (for Go-based tools)
- **Ruby 3.0+** (for WPScan)

### System Setup

#### 1. Clone Repository
```bash
git clone git@github.com:Xmas178/bountybot.git
cd bountybot
```

#### 2. Install Security Tools
```bash
# Subdomain enumeration
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# HTTP probing
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# CVE scanning
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates

# XSS detection
go install github.com/hahwul/dalfox/v2@latest

# Web fuzzing
go install github.com/ffuf/ffuf/v2@latest

# Port scanning (already installed on most systems)
sudo apt install nmap

# Web fingerprinting
sudo apt install whatweb

# SQL injection testing
sudo apt install sqlmap

# Web server scanning
sudo apt install nikto

# WordPress scanning
sudo apt install ruby ruby-dev build-essential
sudo gem install wpscan

# Wordlists for fuzzing
sudo git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists
```

#### 3. Python Environment
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

#### 4. Environment Configuration
```bash
# Copy environment template
cp .env.example .env

# Edit .env file with your settings
# Required: DATABASE_URL, REDIS_URL
# Optional: CLAUDE_API_KEY (Phase 4), DISCORD_WEBHOOK (Phase 3)
```

#### 5. Start Services
```bash
# Start PostgreSQL and Redis
docker compose up -d

# Run database migrations
python manage.py migrate

# Create admin user
python manage.py createsuperuser
```

---

## Usage

### Basic Workflow

#### 1. Start Services
```bash
# Start Docker containers (PostgreSQL + Redis)
sudo systemctl start docker
cd /home/crake178/projects/BountyBot
docker compose up -d

# Activate Python virtual environment
source venv/bin/activate
```

#### 2. Add Target
```bash
# Add domain target
bountybot target add example.com --name "Example Inc" --type domain

# Add IP target
bountybot target add 192.168.1.1 --name "Production Server" --type ip

# Add specific URL
bountybot target add https://api.example.com/v1 --name "API Endpoint" --type url

# List all targets
bountybot target list
```

#### 3. Run Scan

**Quick Scan (5-10 minutes):**
```bash
bountybot scan start 1 --profile quick --execute
```
- Subdomain enumeration (top sources)
- Port scan (100 common ports)
- HTTP probing
- Technology detection
- CVE scanning (critical/high only)
- SQL injection (level 1)
- XSS detection
- **Skips:** Nikto, FFuf, WPScan

**Standard Scan (10-30 minutes) - RECOMMENDED:**
```bash
bountybot scan start 1 --profile standard --execute
```
- Subdomain enumeration (all sources)
- Port scan (all 65,535 ports)
- HTTP probing with detailed tech detection
- CVE scanning (all severities)
- SQL injection (level 2 - includes cookies)
- XSS detection (full)
- **Interactive:** Nikto (5-10 min/endpoint), FFuf (2-5 min/endpoint)
- WordPress scanning (if detected)

**Deep Scan (30-90 minutes):**
```bash
bountybot scan start 1 --profile deep --execute
```
- Comprehensive subdomain enumeration
- Port scan with service detection
- HTTP probing with extensive headers
- CVE scanning (all templates)
- SQL injection (level 3 - includes headers)
- XSS detection (comprehensive)
- **Interactive:** Nikto (15-30 min/endpoint), FFuf (10-30 min/endpoint)
- WordPress comprehensive scan

**Non-Interactive Mode (Fully Automated):**
```bash
bountybot scan start 1 --profile deep --execute --yes
```
- Bypasses all user prompts
- Runs all scanners automatically
- Perfect for scheduled/automated scans

**Custom Parameters:**
```bash
# SQLMap with custom settings
bountybot scan start 1 --profile deep --execute --sqlmap-level 3 --sqlmap-risk 2 --sqlmap-threads 5

# Nuclei with specific severity
bountybot scan start 1 --profile standard --execute --nuclei-severity critical,high

# FFuf with custom wordlist
bountybot scan start 1 --profile deep --execute --ffuf-wordlist /path/to/wordlist.txt --ffuf-threads 40
```

#### 4. View Results
```bash
# List all scans
bountybot scan list

# List all findings
bountybot finding list

# Filter by severity
bountybot finding list --severity critical
bountybot finding list --severity high

# Filter by scan
bountybot finding list --scan 1

# View specific finding with full details
bountybot finding show 42
```

#### 5. Stop Services
```bash
# Stop Docker containers
docker compose down

# Deactivate virtual environment
deactivate
```

---

## Scan Pipeline Explained

### Phase 0: Subdomain Enumeration
- **Tool:** subfinder
- **Purpose:** Discover subdomains (api.example.com, dev.example.com)
- **Output:** List of subdomains for target domain
- **Skip:** If target is IP or URL

### Phase 1: Port Scanning
- **Tool:** nmap
- **Purpose:** Identify open ports and services
- **Profiles:**
  - Quick: Top 100 ports (~10 seconds)
  - Standard: All 65,535 ports (~5-10 minutes)
  - Deep: All ports + service detection (~15-30 minutes)

### Phase 2: HTTP Probing
- **Tool:** httpx
- **Purpose:** Test which ports serve HTTP/HTTPS
- **Detection:** Status codes, redirects, title extraction

### Phase 3: Technology Detection
- **Tool:** whatweb
- **Purpose:** Fingerprint web technologies
- **Detects:** CMS, frameworks, servers, databases, JavaScript libraries
- **Aggression:** Level 1 (passive)

### Phase 4: CVE Scanning
- **Tool:** nuclei
- **Purpose:** Test for known vulnerabilities using templates
- **Templates:** 10,000+ (CVEs, misconfigurations, exposures)
- **Severity:** Critical, High, Medium, Low, Info

### Phase 5: SQL Injection Testing
- **Tool:** sqlmap
- **Purpose:** Detect SQL injection vulnerabilities
- **Profiles:**
  - Quick: Level 1 (URL parameters only)
  - Standard: Level 2 (URL + cookies)
  - Deep: Level 3 (URL + cookies + User-Agent)
- **Risk:** Always 1 (safe for bug bounty, no OR-based queries)
- **Optimization:** Auto-detects database type from Phase 3 (WhatWeb)

### Phase 6: XSS Detection
- **Tool:** dalfox
- **Purpose:** Find Cross-Site Scripting vulnerabilities
- **Types:** Reflected, DOM-based, Stored
- **Payloads:** 1,000+ XSS vectors

### Phase 7: Web Server Scanning (Interactive)
- **Tool:** nikto
- **Purpose:** Detect web server vulnerabilities and misconfigurations
- **Tests:** 6,700+ checks
- **Profiles:**
  - Standard: Level 1 tuning (~5-10 min/endpoint)
  - Deep: Full scan (~15-30 min/endpoint)
- **User Prompt:** "Run Nikto web server scan? [y/N]" (unless --yes flag)

### Phase 8: Directory/File Fuzzing (Interactive)
- **Tool:** ffuf
- **Purpose:** Discover hidden files and directories
- **Wordlists:**
  - Standard: common.txt (~4,700 entries, 2-5 min)
  - Deep: medium.txt (~220,000 entries, 10-30 min)
- **Finds:** /admin, /backup, .git, .env, config files
- **User Prompt:** "Run FFuf directory fuzzing? [y/N]" (unless --yes flag)

### Phase 9: WordPress Scanning (Conditional)
- **Tool:** wpscan
- **Purpose:** Scan WordPress installations for vulnerabilities
- **Conditional:** Only runs if WhatWeb detected WordPress in Phase 3
- **Enumerates:**
  - Vulnerable plugins (30,000+ known issues)
  - Vulnerable themes
  - WordPress core vulnerabilities
  - User accounts
- **User Prompt:** "Run WPScan WordPress security scan? [y/N]" (if WordPress detected and no --yes flag)
- **Auto-Skip:** "No WordPress detected - skipping WPScan" (if not detected)

---

## Features

### Current Features (Phase 1-2.5)

**Automated Scanning Pipeline**
- 9-phase sequential execution
- 10 integrated security tools
- Intelligent workflow (tech detection, conditional scanning)

**Three Scan Profiles**
- Quick: Fast reconnaissance (5-10 min)
- Standard: Balanced coverage (10-30 min)
- Deep: Comprehensive audit (30-90 min)

**Non-Interactive Mode**
- --yes flag for fully automated scanning
- No user prompts or confirmations
- Perfect for scheduled scans

**Custom Scanner Parameters**
- SQLMap: level, risk, threads
- Nuclei: severity filtering, tag selection
- FFuf: custom wordlists, thread control

**Interactive Controls**
- User confirmation for slow scanners (Nikto, FFuf, WPScan)
- Prevents unnecessary waiting on non-critical tools

**Intelligent Scanning**
- Conditional WordPress scanning (only when detected)
- DBMS auto-detection for SQLMap optimization
- Performance-optimized with duplicate removal

**Database Storage**
- PostgreSQL for all findings
- Structured data (severity, tool, PoC, remediation)
- Historical scan tracking

**Rich CLI Interface**
- Color-coded output
- Real-time progress indicators
- Formatted tables (targets, scans, findings)
- Severity-based filtering

**Comprehensive Finding Details**
- Vulnerability description
- Proof of concept
- Remediation steps
- CVSS scoring (estimated)
- References (CVE, OWASP, vendor advisories)

**VPS Deployment Ready**
- Configurable output paths
- Works without sudo (when possible)
- Docker containerization
- Production-ready architecture

---

## Development

### Project Structure
```
bountybot/
├── bountybot/          # Django project settings
├── cli/                # CLI commands and utilities
│   ├── commands/       # Typer CLI commands (scan, target, finding)
│   └── utils/
│       ├── scanners/   # Scanner integrations (10 tools)
│       └── scan_executor.py  # Modular scan execution
├── common/             # Shared utilities
├── findings/           # Finding model and database
├── targets/            # Target model and database
├── scans/              # Scan model and database
├── docker-compose.yml  # PostgreSQL + Redis containers
├── requirements.txt    # Python dependencies
└── manage.py           # Django management
```

### Development Workflow
```bash
# Start services
docker compose up -d
source venv/bin/activate

# Make changes to code

# Test changes
bountybot scan start 1 --profile quick --execute

# Run migrations (if models changed)
python manage.py makemigrations
python manage.py migrate

# Access Django admin
python manage.py runserver
# Visit http://localhost:8000/admin
```

### Adding New Scanners

1. Create scanner module in `cli/utils/scanners/`
2. Implement scanner function (accepts target, scan_id, returns findings)
3. Add parser for tool output
4. Import and integrate in `cli/utils/scan_executor.py`
5. Update Phase Results and scan notes
6. Test with real targets

**Example skeleton:**
```python
# cli/utils/scanners/newtool_scanner.py

def scan_with_newtool(target: str, scan_id: int) -> List[Dict]:
    """Run newtool scanner."""
    # Execute tool
    # Parse output
    # Return findings
    return findings
```

---

## Testing

### Test Targets

**Safe and Legal Test Targets:**

- **scanme.nmap.org** - Official Nmap test server
- **testphp.vulnweb.com** - Intentionally vulnerable PHP site
- **demo.testfire.net** - Altoro Mutual test site
- **Your own infrastructure** - Always best option

**Never scan without permission - Unauthorized scanning is illegal.**

### Test Commands
```bash
# Quick test (scanme.nmap.org)
bountybot target add scanme.nmap.org --name "Nmap Test" --type domain
bountybot scan start 1 --profile quick --execute

# Standard test (your own server)
bountybot target add yourdomain.com --name "My Server" --type domain
bountybot scan start 2 --profile standard --execute
```

---

## Performance

### Scan Durations (Approximate)

| Target Type | Quick | Standard | Deep |
|-------------|-------|----------|------|
| Single domain (1-5 subdomains) | 5-10 min | 15-30 min | 45-90 min |
| Medium scope (10-50 subdomains) | 10-20 min | 30-60 min | 90-180 min |
| Large scope (100+ subdomains) | 20-40 min | 60-120 min | 3-6 hours |

**Bottlenecks:**
- Nmap (all 65k ports): 5-15 minutes per host
- Nikto: 5-30 minutes per HTTP endpoint
- FFuf: 2-30 minutes per endpoint (wordlist size)
- SQLMap: 2-20 minutes per URL with parameters

**Phase 2.5 Optimizations have reduced scan times by 20-40%.**

---

## Security & Ethics

### Legal Disclaimer

BountyBot is designed for authorized security testing only. Users are responsible for:

- Obtaining proper authorization before scanning
- Complying with bug bounty program rules
- Following responsible disclosure practices
- Adhering to local laws and regulations

**Unauthorized scanning is illegal in most jurisdictions.**

### Ethical Guidelines

**DO:**
- Scan only authorized targets
- Follow bug bounty program scope
- Report vulnerabilities responsibly
- Respect rate limits
- Keep findings confidential

**DON'T:**
- Scan without permission
- Exploit vulnerabilities for personal gain
- Share findings publicly before disclosure
- DoS/DDoS targets
- Access unauthorized data

---

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

**Priority areas:**
- Scanner integrations (see Phase 6+ list)
- Performance optimizations
- Error handling improvements
- Documentation

---

## License

MIT License - See LICENSE file for details.

---

## Author

**Sami Tommilammi**
- GitHub: @Xmas178
- Portfolio: tommilammi.fi

---

## Acknowledgments

**Security Tools:**
- ProjectDiscovery (subfinder, httpx, nuclei)
- sqlmap team
- Nikto contributors
- ffuf (Joona Hoikkala)
- WPScan team
- All open-source security tool developers

**Frameworks:**
- Django, Typer, Rich
- PostgreSQL, Redis
- Docker

---

## Resources

**Bug Bounty Platforms:**
- HackerOne (hackerone.com)
- Bugcrowd (bugcrowd.com)
- Intigriti (intigriti.com)
- YesWeHack (yeswehack.com)
- HackenProof (hackenproof.com)

**Learning:**
- OWASP Top 10 (owasp.org/www-project-top-ten/)
- PortSwigger Web Security Academy (portswigger.net/web-security)
- HackerOne Hacker101 (hacker101.com)

**Tools Documentation:**
- Nuclei Templates (github.com/projectdiscovery/nuclei-templates)
- SQLMap Wiki (github.com/sqlmapproject/sqlmap/wiki)
- SecLists (github.com/danielmiessler/SecLists)