"""
BountyBot - Automated Bug Bounty Security Testing Platform

Setup configuration for CLI installation.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="bountybot",
    version="0.1.0",
    author="Sami T",
    author_email="sami@tommilammi.fi",
    description="Automated security testing platform for bug bounty hunting",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Xmas178/bountybot",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.12",
    install_requires=[
        # Django Framework
        "django>=4.2.9",
        "djangorestframework>=3.14.0",
        "django-cors-headers>=4.3.1",
        "django-environ>=0.11.2",
        # Database
        "psycopg2-binary>=2.9.9",
        # Redis & Celery
        "redis>=5.0.1",
        "celery>=5.3.4",
        "django-celery-beat>=2.5.0",
        "django-celery-results>=2.5.1",
        # CLI
        "typer>=0.9.0",
        "rich>=13.7.0",
        "click>=8.1.7",
        # HTTP Client
        "httpx>=0.25.1",
        "requests>=2.31.0",
        # Security Tools Integration
        "python-nmap>=0.7.1",
        # AI Integration
        "anthropic>=0.7.8",
        # Utilities
        "python-dotenv>=1.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.3",
            "pytest-django>=4.7.0",
            "pytest-asyncio>=0.21.1",
            "black>=23.12.0",
            "ruff>=0.1.8",
        ],
    },
    entry_points={
        "console_scripts": [
            "bountybot=cli.main:main",
        ],
    },
)
