"""
Django admin configuration for Target model.

Customizes how targets appear in the admin panel with
list views, filters, search, and display options.
"""

from django.contrib import admin
from .models import Target


@admin.register(Target)
class TargetAdmin(admin.ModelAdmin):
    """
    Admin interface for Target model.

    Provides search, filtering, and organized display
    of scan targets in the Django admin panel.
    """

    # Columns to display in the list view
    list_display = [
        "name",
        "target_type",
        "value",
        "status",
        "created_at",
    ]

    # Fields that can be clicked to open detail view
    list_display_links = ["name", "value"]

    # Filters in the right sidebar
    list_filter = [
        "target_type",
        "status",
        "created_at",
    ]

    # Search functionality
    search_fields = [
        "name",
        "value",
        "description",
    ]

    # Default ordering (newest first)
    ordering = ["-created_at"]

    # Fields to show in the detail view
    fieldsets = (
        (
            "Basic Information",
            {"fields": ("name", "target_type", "value", "description")},
        ),
        ("Status", {"fields": ("status",)}),
        (
            "Timestamps",
            {
                "fields": ("created_at", "updated_at"),
                "classes": ("collapse",),  # Collapsed by default
            },
        ),
    )

    # Read-only fields (can't be edited)
    readonly_fields = ["created_at", "updated_at"]
