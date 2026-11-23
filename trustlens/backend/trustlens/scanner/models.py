from django.db import models


class URLCheckRecord(models.Model):
    """
    A record of one URL check request/response.

    Security decision: we store a SHA-256 hash of the normalized URL, not
    the raw URL string. A hash lets us dedupe/index without retaining a
    reversible copy of what was checked. The raw URL is never written here.

    Field types are chosen to be PostgreSQL-compatible from day one even
    while running on SQLite by default.
    """

    VERDICT_SAFE = "safe"
    VERDICT_SUSPICIOUS = "suspicious"
    VERDICT_MALICIOUS = "malicious"
    VERDICT_UNKNOWN = "unknown"
    VERDICT_ERROR = "error"
    VERDICT_CHOICES = [
        (VERDICT_SAFE, "Safe"),
        (VERDICT_SUSPICIOUS, "Suspicious"),
        (VERDICT_MALICIOUS, "Malicious"),
        (VERDICT_UNKNOWN, "Unknown"),
        (VERDICT_ERROR, "Error"),
    ]

    id = models.BigAutoField(primary_key=True)

    # SHA-256 hex digest is always 64 chars — fixed length, indexed for fast
    # lookups/dedup without ever storing the plaintext URL.
    normalized_url_hash = models.CharField(max_length=64, db_index=True)

    # Domain alone (not full URL) is retained in the clear — needed for
    # future aggregate reputation lookups, far less sensitive than a full
    # URL with path/query.
    domain = models.CharField(max_length=255, db_index=True, blank=True, default="")

    verdict = models.CharField(max_length=16, choices=VERDICT_CHOICES)
    risk_score = models.PositiveSmallIntegerField(default=0)

    # Numeric confidence (0-100), not a low/medium/high enum — lets a future
    # scoring engine express graduated certainty rather than three buckets.
    confidence = models.PositiveSmallIntegerField(default=0)

    # Coarse context only (e.g. "gmail", "browser_navigation") — never
    # message content or any per-user identifier. Optional/blank by design.
    source_context = models.CharField(max_length=40, blank=True, default="")

    # Debugging/analytics correlation only — never used for any decision.
    extension_version = models.CharField(max_length=32, blank=True, default="unknown")

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["normalized_url_hash", "created_at"]),
        ]

    def __str__(self):
        return f"{self.domain} — {self.verdict} ({self.risk_score})"


class UserReport(models.Model):
    """
    A user-submitted report about a URL — e.g. "this was actually phishing"
    or "this was flagged incorrectly."

    Scope note: this phase adds the model only. No API endpoint exposes it
    yet, and no report here feeds back into scoring automatically — that
    wiring, plus abuse-resistance for a public report endpoint (e.g.
    requiring the report to reference a real prior URLCheckRecord, rate
    limiting, spam/troll mitigation), belongs to a later phase and
    shouldn't be assumed solved by this model existing.

    Same privacy posture as URLCheckRecord: hash + domain only, never the
    raw URL, and no free-form field here is treated as safe to render
    without going through the same safe-DOM-rendering rules as everywhere
    else in the extension.
    """

    REPORT_PHISHING = "reported_phishing"
    REPORT_MALICIOUS = "reported_malicious"
    REPORT_FALSE_POSITIVE = "false_positive"
    REPORT_OTHER = "other"
    REPORT_TYPE_CHOICES = [
        (REPORT_PHISHING, "Reported as phishing"),
        (REPORT_MALICIOUS, "Reported as malicious"),
        (REPORT_FALSE_POSITIVE, "False positive"),
        (REPORT_OTHER, "Other"),
    ]

    id = models.BigAutoField(primary_key=True)

    normalized_url_hash = models.CharField(max_length=64, db_index=True)
    domain = models.CharField(max_length=255, db_index=True, blank=True, default="")

    report_type = models.CharField(max_length=20, choices=REPORT_TYPE_CHOICES)

    # Short, optional free-text comment. Length-capped defensively; this is
    # untrusted user input and must always be rendered via safe DOM APIs
    # (never innerHTML) anywhere it's eventually displayed.
    comment = models.CharField(max_length=280, blank=True, default="")

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["normalized_url_hash", "created_at"]),
        ]

    def __str__(self):
        return f"{self.domain} — {self.report_type}"
