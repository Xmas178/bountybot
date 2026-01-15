# BountyBot

Advanced Security Testing & Vulnerability Discovery Platform

## Overview

BountyBot is a comprehensive automation suite for ethical hackers and security researchers. It automates the entire bug bounty workflow from reconnaissance to reporting, allowing hunters to find more vulnerabilities in less time while maintaining professional standards.

## Features

### Phase 1 (Current Development)
- Subdomain enumeration (Amass, Subfinder, Assetfinder)
- Port scanning (Nmap)
- Screenshot capture (Aquatone)
- PostgreSQL database storage
- CLI interface with rich formatting

### Planned Features
- Web application vulnerability scanning (OWASP ZAP, Burp Suite)
- SQL injection testing (SQLMap)
- XSS detection (XSStrike, Dalfox)
- AI-powered report generation (Claude API)
- Template-based CVE scanning (Nuclei)
- API testing module
- Authentication testing
- Multiple export formats (PDF, HTML, JSON)

## Tech Stack

- Python 3.12
- FastAPI (API backend)
- PostgreSQL 16 (database)
- Redis 7 (caching & task queue)
- Docker (containerization)
- Typer + Rich (CLI interface)
- SQLAlchemy 2.0 (ORM)

## Installation

### Prerequisites
- Python 3.12
- Docker & Docker Compose
- Git

### Setup

1. Clone the repository:
```bash
git clone git@github.com:Xmas178/bountybot.git
cd bountybot
```

2. Create Python virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Copy environment file:
```bash
cp .env.example .env
```

5. Start PostgreSQL and Redis:
```bash
docker compose up -d db redis
```

6. Run database migrations:
```bash
python manage.py migrate
```

7. Create admin user:
```bash
python manage.py createsuperuser
```

## Usage

### Start Development Server
```bash
# Start PostgreSQL and Redis (if not running)
docker compose up -d db redis

# Activate virtual environment
source venv/bin/activate

# Start Django development server
python manage.py runserver
```

Access admin panel at: http://localhost:8000/admin

### Stop Services
```bash
# Stop Django: Ctrl+C in the terminal

# Stop PostgreSQL and Redis
docker compose down
```

## Development Workflow

The project uses a hybrid setup:
- **PostgreSQL + Redis**: Running in Docker containers
- **Django application**: Running locally with venv

This setup provides the benefits of containerized databases while maintaining fast local development.

## Development Status

This project is in active development. Current focus: Phase 1 MVP (Reconnaissance Engine).

## License

TBD

## Author

Sami Tommilammi