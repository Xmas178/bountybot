"""
Django app configuration for targets application.
"""

from django.apps import AppConfig


class TargetsConfig(AppConfig):
    """Configuration for the targets app."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "targets"
    verbose_name = "Scan Targets"
