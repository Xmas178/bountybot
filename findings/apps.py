"""
Django app configuration for findings application.
"""

from django.apps import AppConfig


class FindingsConfig(AppConfig):
    """Configuration for the findings app."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "findings"
    verbose_name = "Security Findings"
