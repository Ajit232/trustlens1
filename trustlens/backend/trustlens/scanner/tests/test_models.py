from django.test import TestCase

from trustlens.scanner.models import URLCheckRecord, UserReport


class URLCheckRecordModelTests(TestCase):
    def test_creates_record_with_required_fields(self):
        record = URLCheckRecord.objects.create(
            normalized_url_hash="a" * 64,
            domain="example.com",
            verdict=URLCheckRecord.VERDICT_UNKNOWN,
            risk_score=0,
            confidence=0,
        )
        self.assertIsNotNone(record.id)
        self.assertIsNotNone(record.created_at)

    def test_source_context_defaults_to_blank(self):
        record = URLCheckRecord.objects.create(
            normalized_url_hash="b" * 64,
            domain="example.com",
            verdict=URLCheckRecord.VERDICT_UNKNOWN,
            risk_score=0,
            confidence=0,
        )
        self.assertEqual(record.source_context, "")

    def test_extension_version_defaults_to_unknown(self):
        record = URLCheckRecord.objects.create(
            normalized_url_hash="f" * 64,
            domain="example.com",
            verdict=URLCheckRecord.VERDICT_UNKNOWN,
            risk_score=0,
            confidence=0,
        )
        self.assertEqual(record.extension_version, "unknown")

    def test_str_includes_domain_and_verdict(self):
        record = URLCheckRecord.objects.create(
            normalized_url_hash="c" * 64,
            domain="example.com",
            verdict=URLCheckRecord.VERDICT_SUSPICIOUS,
            risk_score=50,
            confidence=40,
        )
        self.assertIn("example.com", str(record))
        self.assertIn("suspicious", str(record))

    def test_ordering_is_most_recent_first(self):
        older = URLCheckRecord.objects.create(
            normalized_url_hash="d" * 64,
            domain="old.example.com",
            verdict=URLCheckRecord.VERDICT_UNKNOWN,
            risk_score=0,
            confidence=0,
        )
        newer = URLCheckRecord.objects.create(
            normalized_url_hash="e" * 64,
            domain="new.example.com",
            verdict=URLCheckRecord.VERDICT_UNKNOWN,
            risk_score=0,
            confidence=0,
        )
        records = list(URLCheckRecord.objects.all())
        self.assertEqual(records[0].id, newer.id)
        self.assertEqual(records[1].id, older.id)

    def test_error_verdict_is_a_valid_choice(self):
        record = URLCheckRecord.objects.create(
            normalized_url_hash="g" * 64,
            domain="example.com",
            verdict=URLCheckRecord.VERDICT_ERROR,
            risk_score=0,
            confidence=0,
        )
        self.assertEqual(record.verdict, "error")


class UserReportModelTests(TestCase):
    def test_creates_report_with_required_fields(self):
        report = UserReport.objects.create(
            normalized_url_hash="a" * 64,
            domain="example.com",
            report_type=UserReport.REPORT_PHISHING,
        )
        self.assertIsNotNone(report.id)
        self.assertIsNotNone(report.created_at)

    def test_comment_defaults_to_blank(self):
        report = UserReport.objects.create(
            normalized_url_hash="b" * 64,
            domain="example.com",
            report_type=UserReport.REPORT_FALSE_POSITIVE,
        )
        self.assertEqual(report.comment, "")

    def test_str_includes_domain_and_report_type(self):
        report = UserReport.objects.create(
            normalized_url_hash="c" * 64,
            domain="example.com",
            report_type=UserReport.REPORT_MALICIOUS,
        )
        self.assertIn("example.com", str(report))
        self.assertIn("reported_malicious", str(report))
