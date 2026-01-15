"""
Django app configuration for common application.
"""

from django.apps import AppConfig


class CommonConfig(AppConfig):
    """Configuration for the common utilities app."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "common"
    verbose_name = "Common Utilities"
