"""
Django admin configuration for Finding model.

Customizes how findings (vulnerabilities) appear in the admin panel
with severity-based colors, filtering, search, and detailed views.
"""

from django.contrib import admin
from django.utils.html import format_html
from .models import Finding


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    """
    Admin interface for Finding model.

    Provides comprehensive vulnerability management with
    severity highlighting, status tracking, and detailed evidence display.
    """

    # Columns to display in the list view
    list_display = [
        "severity_badge",  # Custom colored severity
        "title",
        "category",
        "status_badge",  # Custom colored status
        "scan",
        "discovered_by",
        "discovered_at",
    ]

    # Fields that can be clicked to open detail view
    list_display_links = ["title"]

    # Filters in the right sidebar
    list_filter = [
        "severity",
        "category",
        "status",
        "discovered_by",
        "discovered_at",
        "scan__target",  # Filter by target through scan relationship
    ]

    # Search functionality
    search_fields = [
        "title",
        "description",
        "affected_url",
        "affected_parameter",
        "proof_of_concept",
    ]

    # Default ordering (critical first, newest first)
    ordering = ["-severity", "-discovered_at"]

    # Fields to show in the detail view
    fieldsets = (
        (
            "Basic Information",
            {
                "fields": (
                    "scan",
                    "title",
                    "category",
                    "severity",
                    "status",
                )
            },
        ),
        ("Description", {"fields": ("description",)}),
        (
            "Technical Details",
            {
                "fields": (
                    "affected_url",
                    "affected_parameter",
                    "discovered_by",
                )
            },
        ),
        (
            "Proof of Concept",
            {
                "fields": ("proof_of_concept",),
                "classes": ("collapse",),  # Collapsed by default
            },
        ),
        (
            "HTTP Evidence",
            {
                "fields": ("http_request", "http_response"),
                "classes": ("collapse",),
            },
        ),
        (
            "CVSS Scoring",
            {
                "fields": ("cvss_score", "cvss_vector"),
                "classes": ("collapse",),
            },
        ),
        (
            "Remediation",
            {
                "fields": ("remediation", "references"),
            },
        ),
        (
            "Evidence Files",
            {
                "fields": ("screenshot_path", "evidence_path"),
                "classes": ("collapse",),
            },
        ),
        (
            "Timestamps",
            {
                "fields": ("discovered_at", "verified_at", "fixed_at"),
            },
        ),
        (
            "Notes",
            {
                "fields": ("notes",),
                "classes": ("collapse",),
            },
        ),
    )

    # Read-only fields
    readonly_fields = ["discovered_at"]

    def severity_badge(self, obj):
        """
        Display severity level with color-coded badge.

        Uses standard security severity colors:
        - Critical: Dark red
        - High: Red
        - Medium: Orange
        - Low: Yellow/Gold
        - Info: Blue

        Args:
            obj: Finding instance

        Returns:
            HTML formatted severity badge
        """
        colors = {
            "critical": "#8B0000",  # Dark red
            "high": "#FF0000",  # Red
            "medium": "#FFA500",  # Orange
            "low": "#FFD700",  # Gold
            "info": "#87CEEB",  # Sky blue
        }
        color = colors.get(obj.severity, "#808080")
        return format_html(
            '<span style="background-color: {}; color: white; padding: 5px 12px; border-radius: 3px; font-weight: bold;">{}</span>',
            color,
            obj.get_severity_display().upper(),
        )

    severity_badge.short_description = "Severity"
    severity_badge.admin_order_field = "severity"  # Allow sorting by this column

    def status_badge(self, obj):
        """
        Display finding status with color-coded badge.

        Args:
            obj: Finding instance

        Returns:
            HTML formatted status badge
        """
        colors = {
            "new": "#1E90FF",  # Blue
            "confirmed": "#FF8C00",  # Dark orange
            "false_positive": "#808080",  # Gray
            "accepted_risk": "#DDA0DD",  # Plum
            "fixed": "#32CD32",  # Green
            "retest": "#FFD700",  # Gold
        }
        color = colors.get(obj.status, "#808080")
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 10px; border-radius: 3px;">{}</span>',
            color,
            obj.get_status_display(),
        )

    status_badge.short_description = "Status"
    status_badge.admin_order_field = "status"

    # Actions for bulk operations
    actions = [
        "mark_as_confirmed",
        "mark_as_false_positive",
        "mark_as_fixed",
    ]

    def mark_as_confirmed(self, request, queryset):
        """Bulk action: Mark selected findings as confirmed."""
        updated = queryset.update(status="confirmed")
        self.message_user(request, f"{updated} finding(s) marked as confirmed.")

    mark_as_confirmed.short_description = "Mark selected as Confirmed"

    def mark_as_false_positive(self, request, queryset):
        """Bulk action: Mark selected findings as false positives."""
        updated = queryset.update(status="false_positive")
        self.message_user(request, f"{updated} finding(s) marked as false positive.")

    mark_as_false_positive.short_description = "Mark selected as False Positive"

    def mark_as_fixed(self, request, queryset):
        """Bulk action: Mark selected findings as fixed."""
        from django.utils import timezone

        updated = queryset.update(status="fixed", fixed_at=timezone.now())
        self.message_user(request, f"{updated} finding(s) marked as fixed.")

    mark_as_fixed.short_description = "Mark selected as Fixed"
