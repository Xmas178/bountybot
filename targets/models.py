"""
Target model for storing scan targets (domains, IPs, URLs).
"""

from django.db import models
from django.utils import timezone


class Target(models.Model):
    """
    Represents a target for security scanning.
    Can be a domain, IP address, or URL.
    """

    TARGET_TYPES = [
        ("domain", "Domain"),
        ("ip", "IP Address"),
        ("url", "URL"),
        ("subnet", "Subnet"),
    ]

    STATUS_CHOICES = [
        ("active", "Active"),
        ("inactive", "Inactive"),
        ("archived", "Archived"),
    ]

    name = models.CharField(max_length=255, help_text="Target name or identifier")
    target_type = models.CharField(
        max_length=20, choices=TARGET_TYPES, default="domain"
    )
    value = models.CharField(
        max_length=500, unique=True, help_text="Domain, IP, or URL"
    )
    description = models.TextField(blank=True, help_text="Optional description")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="active")

    # Metadata
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Target"
        verbose_name_plural = "Targets"

    def __str__(self):
        return f"{self.name} ({self.value})"
