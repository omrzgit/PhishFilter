import unittest
from analyzer import (
    extract_urls,
    clean_extracted_url,
    undefang_text,
    check_anchor_mismatches,
    analyze_sender,
    parse_email_message,
    generate_report
)


class TestPhishFilter(unittest.TestCase):

    def test_undefang_and_clean_url(self):
        defanged = "hxxps://evil-phish[.]com/login[:]8080"
        normalized = undefang_text(defanged)
        self.assertEqual(normalized, "https://evil-phish.com/login:8080")

        punct_url = clean_extracted_url("https://example.com/test.")
        self.assertEqual(punct_url, "https://example.com/test")

        punct_url2 = clean_extracted_url("https://example.com/page),")
        self.assertEqual(punct_url2, "https://example.com/page")

    def test_extract_urls(self):
        text = """
        Check this link: https://legit.com. And also visit hxxp://bad-domain[.]com/verify!
        Here is another: www.example.org/path?id=123.
        """
        urls = extract_urls(text)
        self.assertIn("https://legit.com", urls)
        self.assertIn("http://bad-domain.com/verify", urls)
        self.assertIn("http://www.example.org/path?id=123", urls)

    def test_anchor_mismatch(self):
        html_text = '<a href="http://malicious-site.com/login">https://paypal.com/signin</a>'
        mismatches = check_anchor_mismatches(html_text)
        self.assertEqual(len(mismatches), 1)
        self.assertEqual(mismatches[0]["target_url"], "http://malicious-site.com/login")

    def test_sender_legitimate_domain(self):
        result = analyze_sender("support@google.com")
        self.assertEqual(result["risk_level"], "SAFE")
        self.assertEqual(len(result["findings"]), 0)

    def test_sender_brand_impersonation(self):
        result = analyze_sender("billing@paypal-account-update.com")
        self.assertEqual(result["risk_level"], "MALICIOUS")
        self.assertTrue(any("impersonation" in f.lower() for f in result["findings"]))

    def test_sender_display_name_spoofing(self):
        result = analyze_sender('"PayPal Security" <alerts@randomdomain123.com>')
        self.assertEqual(result["risk_level"], "MALICIOUS")
        self.assertTrue(any("display name spoofing" in f.lower() for f in result["findings"]))

    def test_sender_suspicious_patterns(self):
        result = analyze_sender("support@secure-bank-verify.com")
        self.assertIn(result["risk_level"], ["SUSPICIOUS", "MALICIOUS"])
        self.assertTrue(len(result["findings"]) > 0)

    def test_parse_email_message(self):
        raw_eml = """From: "Security Team" <security@secure-bank-verify.com>
Subject: Account Suspended
Date: Wed, 07 Oct 2026 12:00:00 +0000
Authentication-Results: mx.google.com; spf=fail; dkim=fail

Please verify your credentials immediately at http://verify-now.com.
"""
        parsed = parse_email_message(raw_eml)
        self.assertIn("security@secure-bank-verify.com", parsed["sender"])
        self.assertEqual(parsed["subject"], "Account Suspended")
        self.assertTrue(any("spf" in f.lower() for f in parsed["auth_findings"]))
        self.assertTrue(any("dkim" in f.lower() for f in parsed["auth_findings"]))

    def test_generate_report_stats(self):
        mock_data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 3,
                        "suspicious": 1,
                        "harmless": 65,
                        "undetected": 5
                    }
                }
            }
        }
        report = generate_report("http://bad.com", mock_data)
        self.assertEqual(report["verdict"], "MALICIOUS")
        self.assertEqual(report["malicious"], 3)


if __name__ == "__main__":
    unittest.main()
