"""
Finding model for storing discovered vulnerabilities and security issues.

A Finding represents a single security issue discovered during a Scan.
Each finding includes severity, description, evidence, and remediation guidance.
"""

from django.db import models
from django.utils import timezone
from scans.models import Scan


class Finding(models.Model):
    """
    Represents a security vulnerability or issue discovered during scanning.

    Stores all information needed for reporting: severity, description,
    proof of concept, affected URLs, remediation steps, and evidence.
    """

    # Severity levels (CVSS-inspired)
    SEVERITY_CHOICES = [
        ("critical", "Critical"),  # CVSS 9.0-10.0 - Immediate action required
        ("high", "High"),  # CVSS 7.0-8.9 - Should be fixed soon
        ("medium", "Medium"),  # CVSS 4.0-6.9 - Should be fixed eventually
        ("low", "Low"),  # CVSS 0.1-3.9 - Minor issue
        ("info", "Info"),  # CVSS 0.0 - Informational only
    ]

    # Finding status for tracking remediation
    STATUS_CHOICES = [
        ("new", "New"),  # Just discovered
        ("confirmed", "Confirmed"),  # Verified as valid
        ("false_positive", "False Positive"),  # Not a real issue
        ("accepted_risk", "Accepted Risk"),  # Known but accepted
        ("fixed", "Fixed"),  # Remediated
        ("retest", "Needs Retest"),  # Fix deployed, needs verification
    ]

    # Vulnerability categories (OWASP-inspired)
    CATEGORY_CHOICES = [
        ("sqli", "SQL Injection"),
        ("xss", "Cross-Site Scripting"),
        ("ssrf", "Server-Side Request Forgery"),
        ("xxe", "XML External Entity"),
        ("rce", "Remote Code Execution"),
        ("lfi", "Local File Inclusion"),
        ("rfi", "Remote File Inclusion"),
        ("idor", "Insecure Direct Object Reference"),
        ("broken_auth", "Broken Authentication"),
        ("sensitive_data", "Sensitive Data Exposure"),
        ("xxe", "XML External Entity"),
        ("broken_access", "Broken Access Control"),
        ("security_misconfig", "Security Misconfiguration"),
        ("using_known_vulnerable", "Using Components with Known Vulnerabilities"),
        ("insufficient_logging", "Insufficient Logging & Monitoring"),
        ("csrf", "Cross-Site Request Forgery"),
        ("open_redirect", "Open Redirect"),
        ("clickjacking", "Clickjacking"),
        ("cors_misconfig", "CORS Misconfiguration"),
        ("missing_headers", "Missing Security Headers"),
        ("ssl_tls", "SSL/TLS Issues"),
        ("info_disclosure", "Information Disclosure"),
        ("other", "Other"),
    ]

    # Link to the scan that discovered this finding
    scan = models.ForeignKey(
        Scan,
        on_delete=models.CASCADE,  # Delete findings if scan is deleted
        related_name="findings",  # Access via scan.findings.all()
        help_text="The scan that discovered this finding",
    )

    # Core finding information
    title = models.CharField(
        max_length=500, help_text="Brief, descriptive title of the vulnerability"
    )

    category = models.CharField(
        max_length=50,
        choices=CATEGORY_CHOICES,
        default="other",
        help_text="Type of vulnerability",
    )

    severity = models.CharField(
        max_length=20,
        choices=SEVERITY_CHOICES,
        default="info",
        help_text="Severity level of the finding",
    )

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="new",
        help_text="Current remediation status",
    )

    # Detailed description
    description = models.TextField(
        help_text="Detailed explanation of the vulnerability"
    )

    # Technical details
    affected_url = models.URLField(
        max_length=1000, blank=True, help_text="URL where the vulnerability was found"
    )

    affected_parameter = models.CharField(
        max_length=500,
        blank=True,
        help_text="Vulnerable parameter name (if applicable)",
    )

    # Proof of Concept
    proof_of_concept = models.TextField(
        blank=True, help_text="Steps to reproduce or exploit the vulnerability"
    )

    # HTTP request/response evidence
    http_request = models.TextField(
        blank=True, help_text="Raw HTTP request demonstrating the issue"
    )

    http_response = models.TextField(
        blank=True, help_text="Raw HTTP response showing the vulnerability"
    )
    # Extra structured data (JSON) - tool-specific details
    extra_data = models.JSONField(
        null=True,
        blank=True,
        help_text="Additional structured data from security tools (JSON format). "
        "Examples: SQLMap databases/tables, nuclei matched patterns, etc.",
    )
    # Tool that discovered this finding
    discovered_by = models.CharField(
        max_length=100,
        blank=True,
        help_text="Security tool that found this issue (e.g., 'nmap', 'sqlmap', 'nuclei')",
    )

    # CVSS scoring (optional, for advanced users)
    cvss_score = models.DecimalField(
        max_digits=3,
        decimal_places=1,
        null=True,
        blank=True,
        help_text="CVSS 3.1 score (0.0 - 10.0)",
    )

    cvss_vector = models.CharField(
        max_length=200, blank=True, help_text="CVSS 3.1 vector string"
    )

    # Remediation guidance
    remediation = models.TextField(
        blank=True, help_text="Steps to fix this vulnerability"
    )

    # References and resources
    references = models.TextField(
        blank=True, help_text="External links, CVEs, or documentation (one per line)"
    )

    # File attachments (screenshots, evidence files)
    screenshot_path = models.CharField(
        max_length=500, blank=True, help_text="Path to screenshot evidence file"
    )

    evidence_path = models.CharField(
        max_length=500, blank=True, help_text="Path to additional evidence files"
    )

    # Timestamps
    discovered_at = models.DateTimeField(
        default=timezone.now, help_text="When this finding was discovered"
    )

    verified_at = models.DateTimeField(
        null=True, blank=True, help_text="When this finding was manually verified"
    )

    fixed_at = models.DateTimeField(
        null=True, blank=True, help_text="When this vulnerability was remediated"
    )

    # Internal notes
    notes = models.TextField(blank=True, help_text="Internal notes about this finding")

    class Meta:
        ordering = ["-severity", "-discovered_at"]  # Critical first, newest first
        verbose_name = "Finding"
        verbose_name_plural = "Findings"

        # Database indexes for performance
        indexes = [
            models.Index(fields=["severity"]),  # Fast filtering by severity
            models.Index(fields=["status"]),  # Fast filtering by status
            models.Index(fields=["category"]),  # Fast filtering by category
            models.Index(fields=["-discovered_at"]),  # Fast sorting by date
        ]

    def __str__(self):
        """String representation shown in Django admin."""
        return f"[{self.severity.upper()}] {self.title}"

    def get_severity_color(self):
        """
        Return color code for severity level (useful for UI).

        Returns:
            str: CSS color name or hex code
        """
        colors = {
            "critical": "#8B0000",  # Dark red
            "high": "#FF0000",  # Red
            "medium": "#FFA500",  # Orange
            "low": "#FFD700",  # Gold
            "info": "#87CEEB",  # Sky blue
        }
        return colors.get(self.severity, "#808080")  # Gray as fallback
