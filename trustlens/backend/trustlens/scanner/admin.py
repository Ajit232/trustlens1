from django.contrib import admin

from .models import URLCheckRecord, UserReport


@admin.register(URLCheckRecord)
class URLCheckRecordAdmin(admin.ModelAdmin):
    list_display = (
        "domain",
        "verdict",
        "risk_score",
        "confidence",
        "source_context",
        "extension_version",
        "created_at",
    )
    list_filter = ("verdict", "source_context")
    search_fields = ("domain", "normalized_url_hash")
    readonly_fields = (
        "normalized_url_hash",
        "domain",
        "verdict",
        "risk_score",
        "confidence",
        "source_context",
        "extension_version",
        "created_at",
    )

    def has_add_permission(self, request):
        # Records are created only by the API, never manually in admin —
        # this table is an audit log, not editable operator data.
        return False


@admin.register(UserReport)
class UserReportAdmin(admin.ModelAdmin):
    list_display = ("domain", "report_type", "created_at")
    list_filter = ("report_type",)
    search_fields = ("domain", "normalized_url_hash")
    readonly_fields = ("normalized_url_hash", "domain", "report_type", "comment", "created_at")

    def has_add_permission(self, request):
        # No public submission endpoint exists yet in this phase; when one
        # is added, reports should still arrive only via the API, not be
        # hand-authored in admin.
        return False
