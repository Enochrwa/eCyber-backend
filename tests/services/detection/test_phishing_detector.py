import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

# Assuming dnspython and python-whois are installed, otherwise these imports will fail
# In a real CI environment, these would be part of the test dependencies
try:
    import dns.resolver
    import dns.exception
except ImportError:
    # Mock them if not available, so tests can still be outlined
    dns = MagicMock()
    dns.resolver = MagicMock()
    dns.exception = MagicMock()
    dns.resolver.NXDOMAIN = Exception
    dns.resolver.NoAnswer = Exception
    dns.resolver.Timeout = Exception
    dns.resolver.NoMX = Exception


try:
    import whois
except ImportError:
    whois = MagicMock()

try:
    import Levenshtein
except ImportError:
    Levenshtein = MagicMock()


from app.services.detection.phishing_detector import (
    ClassicalPhishingDetector,
    PhishingResult,
)


class TestClassicalPhishingDetector(unittest.TestCase):

    def setUp(self):
        self.detector = ClassicalPhishingDetector()
        # Lower the threshold for easier testing of lookalikes if needed, or rely on mocking distance
        # self.detector.lookalike_threshold = 1

    # --- URL Analysis Tests ---
    @patch("Levenshtein.distance")
    def test_url_analysis_lookalike_domain_similar(self, mock_levenshtein_distance):
        mock_levenshtein_distance.return_value = 1  # e.g., paypa1.com vs paypal.com
        # One of the common legitimate domains is "paypal.com"
        result = self.detector.analyze_url("http://paypa1.com/login")
        self.assertTrue(
            result.is_phishing
            or result.risk_score >= self.detector.risk_weights["lookalike_domain"]
        )
        self.assertIn(
            "Lookalike domain: 'paypa1.com' is similar to 'paypal.com' (distance: 1)",
            result.reasons,
        )
        mock_levenshtein_distance.assert_called_with("paypa1.com", "paypal.com")

    @patch("Levenshtein.distance")
    def test_url_analysis_lookalike_domain_not_similar_but_brand_keyword(
        self, mock_levenshtein_distance
    ):
        mock_levenshtein_distance.return_value = 5  # Too different for Levenshtein
        # common_legitimate_domains includes "apple.com"
        # brand_impersonation_keywords_html includes "apple"
        result = self.detector.analyze_url("http://apple-security-check.com/login")
        self.assertTrue(
            result.is_phishing
            or result.risk_score >= self.detector.risk_weights["brand_mismatch"]
        )
        self.assertIn(
            "Potential brand impersonation in domain name: 'apple-security-check.com' contains 'apple'",
            result.reasons,
        )

    def test_url_analysis_known_malicious_url(self):
        # Add a domain to blacklist for testing
        test_malicious_domain = "secure-login-confirmation-paypal.com"
        self.detector.blacklisted_domains.add(test_malicious_domain)
        result = self.detector.analyze_url(f"http://{test_malicious_domain}/somepath")
        self.assertTrue(result.is_phishing)
        self.assertIn("Blacklisted domain", result.reasons)

    def test_url_analysis_suspicious_url_pattern_http(self):
        # "http://" is a suspicious pattern (if not followed by s)
        result = self.detector.analyze_url(
            "http://example-phishy.com"
        )  # Already normalized to http://
        self.assertTrue(
            result.risk_score >= self.detector.risk_weights["http_protocol"]
        )
        self.assertIn("Insecure HTTP protocol", result.reasons)

    def test_url_analysis_suspicious_url_pattern_at_symbol(self):
        # "@" in domain is suspicious
        result = self.detector.analyze_url("http://user@phishy-domain.com/login")
        self.assertTrue(result.risk_score >= self.detector.risk_weights["at_symbol"])
        self.assertIn("@ symbol in domain (obfuscation)", result.reasons)

    def test_url_analysis_ip_in_domain(self):
        result = self.detector.analyze_url("http://192.168.1.100/login.php")
        self.assertTrue(result.risk_score >= self.detector.risk_weights["ip_in_url"])
        self.assertIn("IP address in domain", result.reasons)

    def test_url_analysis_suspicious_tld(self):
        result = self.detector.analyze_url(
            "http://account-update.xyz/login"
        )  # .xyz is in phishing_tlds
        self.assertTrue(
            result.risk_score >= self.detector.risk_weights["suspicious_tld"]
        )
        self.assertIn("Suspicious TLD: .xyz", result.reasons)

    def test_url_analysis_shortener_domain(self):
        result = self.detector.analyze_url(
            "http://bit.ly/shorturl"
        )  # bit.ly is in shortener_domains
        self.assertTrue(
            result.risk_score >= self.detector.risk_weights["shortener_domain"]
        )
        self.assertIn("URL shortener domain", result.reasons)

    # --- Placeholder for Domain Reputation Tests ---
    # These will be filled in later

    # --- Placeholder for Content Inspection Tests ---
    # These will be filled in later

    # --- Placeholder for Risk Score Aggregation Tests ---
    # These will be filled in later

    # --- Placeholder Function Tests ---
    def test_placeholder_email_functions(self):
        self.assertEqual(self.detector.analyze_email_headers({}), [])
        self.assertEqual(self.detector.analyze_email_body("some body content"), [])
        self.assertEqual(self.detector.scan_email_attachments([]), [])

    def test_placeholder_ml_model(self):
        self.assertIsNone(self.detector.predict_with_ml_model("http://example.com"))

    # --- Domain Reputation Checking Tests (Mocked) ---
    @patch("dns.resolver.resolve")
    def test_dns_checks_no_a_record(self, mock_dns_resolve):
        mock_dns_resolve.side_effect = dns.resolver.NXDOMAIN
        result = self.detector.analyze_url("http://domainwithnoarecord.com/login")
        self.assertTrue(
            result.risk_score >= self.detector.risk_weights["dns_no_a_record"]
        )
        self.assertIn(
            "DNS: No A record or resolution failed for host domainwithnoarecord.com (NXDOMAIN)",
            result.reasons,
        )

    @patch("dns.resolver.resolve")
    def test_dns_checks_no_mx_record_for_service_domain(self, mock_dns_resolve):
        # First call for A record (let's say it's found)
        # Second call for MX record (NXDOMAIN)
        mock_dns_resolve.side_effect = [
            MagicMock(),  # Mock A record result
            dns.resolver.NoMX,  # Mock NoMX result for MX query
        ]
        # "paypal" is in brand_impersonation_keywords_html, making it look like a service domain
        # The domain also contains "service", another keyword.
        result = self.detector.analyze_url("http://paypal-login-service.com/login")
        self.assertTrue(
            result.risk_score >= self.detector.risk_weights["dns_suspicious_mx"]
        )
        self.assertIn(
            "DNS: MX query failed or no records for paypal-login-service.com (NoMX)",
            result.reasons,
        )
        # ensure A record was checked for domain and MX for main_domain_with_tld
        mock_dns_resolve.assert_any_call("paypal-login-service.com", "A")
        mock_dns_resolve.assert_any_call("paypal-login-service.com", "MX")

    @patch("whois.whois")
    def test_whois_checks_recent_domain(self, mock_whois):
        mock_whois_response = MagicMock()
        # Ensure tzinfo is None for direct comparison if datetime.now() is naive, or make both aware.
        mock_whois_response.creation_date = datetime.now().replace(
            tzinfo=None
        ) - timedelta(
            days=30
        )  # 30 days old
        mock_whois_response.registrar = "Some Registrar"
        mock_whois_response.status = ["clientDeleteProhibited"]
        mock_whois_response.text = (
            "Domain Name: recentdomain.com..."  # Add text for privacy check fallback
        )
        mock_whois.return_value = mock_whois_response

        result = self.detector.analyze_url("http://recentdomain.com/path")
        self.assertTrue(
            result.risk_score >= self.detector.risk_weights["whois_recent_creation"]
        )
        self.assertIn("WHOIS: Domain created recently (30 days ago)", result.reasons)
        mock_whois.assert_called_with("recentdomain.com")

    @patch("whois.whois")
    def test_whois_checks_privacy_protected_by_registrar(self, mock_whois):
        mock_whois_response = MagicMock()
        mock_whois_response.creation_date = datetime.now().replace(
            tzinfo=None
        ) - timedelta(
            days=365
        )  # Old domain
        mock_whois_response.registrar = "Domains By Proxy, LLC"  # Privacy registrar
        mock_whois_response.status = ["clientTransferProhibited"]
        mock_whois_response.text = (
            "Domain Name: privacyprotected.com\nRegistrar: Domains By Proxy, LLC"
        )
        mock_whois.return_value = mock_whois_response

        result = self.detector.analyze_url("http://privacyprotected.com/path")
        self.assertTrue(
            result.risk_score >= self.detector.risk_weights["whois_privacy_protected"]
        )
        self.assertIn("WHOIS: Registrar suggests privacy protection", result.reasons)

    @patch("whois.whois")
    def test_whois_checks_privacy_protected_by_status(self, mock_whois):
        mock_whois_response = MagicMock()
        mock_whois_response.creation_date = datetime.now().replace(
            tzinfo=None
        ) - timedelta(days=365)
        mock_whois_response.registrar = "Normal Registrar Inc."
        mock_whois_response.status = [
            "clientTransferProhibited",
            "REDACTED FOR PRIVACY",
        ]  # Privacy status
        mock_whois_response.text = "Domain Name: privacyprotectedstatus.com..."
        mock_whois.return_value = mock_whois_response

        result = self.detector.analyze_url("http://privacyprotectedstatus.com/path")
        self.assertTrue(
            result.risk_score >= self.detector.risk_weights["whois_privacy_protected"]
        )
        self.assertIn(
            "WHOIS: Domain status suggests privacy protection", result.reasons
        )

    @patch("whois.whois")
    def test_whois_checks_error(self, mock_whois):
        mock_whois.side_effect = Exception(
            "WHOIS lookup failed"
        )  # Simulate a generic error
        result = self.detector.analyze_url("http://domainwithwhoiserror.com/login")
        self.assertIn(
            "WHOIS: Query failed for domainwithwhoiserror.com", result.reasons
        )
        self.assertTrue(
            result.risk_score
            >= self.detector.risk_weights["whois_recent_creation"] * 0.1
        )

    # --- Content Inspection Tests ---
    def test_analyze_html_content_password_foreign_domain(self):
        html_content = """
        <html><body><form action="http://malicious-site.com/submit">
        <input type="password" name="pass">
        <input type="submit">
        </form></body></html>
        """
        url_domain = "legit-site.com"
        reasons, score_impact = self.detector.analyze_html_content(
            html_content, url_domain
        )
        self.assertIn(
            "Password form submits to a different domain: malicious-site.com", reasons
        )
        self.assertEqual(
            score_impact,
            self.detector.risk_weights["html_password_form_foreign_domain"],
        )

    def test_analyze_html_content_password_same_domain_relative_action(self):
        html_content = """
        <html><body><form action="/login_process">
        <input type="password" name="pass">
        </form></body></html>
        """
        url_domain = "legit-site.com"
        reasons, score_impact = self.detector.analyze_html_content(
            html_content, url_domain
        )
        # Relative action URL should not trigger foreign domain password submission
        self.assertNotIn(
            "Password form submits to a different domain", " ".join(reasons)
        )
        self.assertEqual(score_impact, 0.0)  # Assuming no other content triggers score

    def test_analyze_html_content_brand_impersonation_not_matching_domain(self):
        # "paypal" is in brand_impersonation_keywords_html
        html_content = "<p>Please login to your PayPal account to confirm.</p>"
        url_domain = "secure-mysite.com"  # Does not match "paypal"
        reasons, score_impact = self.detector.analyze_html_content(
            html_content, url_domain
        )
        self.assertIn(
            f"HTML content mentions brands (paypal) not matching domain {url_domain}",
            reasons,
        )
        self.assertEqual(
            score_impact, self.detector.risk_weights["html_brand_impersonation"]
        )

    def test_analyze_html_content_brand_impersonation_matching_trusted_domain(self):
        html_content = "<p>Welcome to the official Google login page.</p>"
        url_domain = "login.google.com"  # Main registered domain is "google.com"
        # self.detector.trusted_domains already includes "google.com"
        reasons, score_impact = self.detector.analyze_html_content(
            html_content, "google.com"
        )  # Pass registered domain
        # If "google.com" is the domain of the URL, and "google" is mentioned in content,
        # and "google.com" is in trusted_domains, it should NOT be flagged as impersonation.
        self.assertEqual(reasons, [])  # Expect no impersonation reason
        self.assertEqual(score_impact, 0.0)

    def test_analyze_url_with_html_content_triggering_html_rule(self):
        html_content = """
        <html><body><form action="http://malicious-site.com/submit">
        <input type="password" name="pass"><input type="submit">
        </form></body></html>
        """
        result = self.detector.analyze_url(
            "http://legit-looking-site.com/login", html_content=html_content
        )
        self.assertTrue(
            result.risk_score
            >= self.detector.risk_weights["html_password_form_foreign_domain"]
        )
        self.assertIn(
            "Password form submits to a different domain: malicious-site.com",
            result.reasons,
        )

    # --- Risk Score Aggregation Tests ---
    @patch("Levenshtein.distance")
    @patch("dns.resolver.resolve")
    @patch("whois.whois")
    def test_risk_score_aggregation_multiple_triggers(
        self, mock_whois, mock_dns_resolve, mock_levenshtein_distance
    ):
        # Setup mocks for multiple triggers
        # 1. Lookalike domain
        mock_levenshtein_distance.return_value = 1
        # 2. Suspicious TLD (already part of URL)
        # 3. DNS: No A record
        mock_dns_resolve.side_effect = dns.resolver.NXDOMAIN
        # 4. WHOIS: Recent domain
        mock_whois_response = MagicMock()
        mock_whois_response.creation_date = datetime.now().replace(
            tzinfo=None
        ) - timedelta(days=10)
        mock_whois_response.text = "Recent domain text"  # For privacy check fallback
        mock_whois_response.registrar = "SomeReg"  # For privacy check
        mock_whois_response.status = ["ok"]  # For privacy check
        mock_whois.return_value = mock_whois_response

        url_to_test = "http://paypa1.xyz/login"  # .xyz is suspicious TLD, paypa1 is lookalike for paypal.com

        # Calculate expected score based on weights of triggered rules
        expected_score = (
            self.detector.risk_weights["lookalike_domain"]  # paypa1.xyz vs paypal.com
            + self.detector.risk_weights["suspicious_tld"]  # .xyz
            + self.detector.risk_weights["dns_no_a_record"]  # Mocked NXDOMAIN
            + self.detector.risk_weights["whois_recent_creation"]  # Mocked 10 days old
            + self.detector.risk_weights["http_protocol"]  # URL is http://
        )
        # Additional potential triggers based on the URL structure "paypa1.xyz"
        # High digit ratio in domain? "paypa1" has 1 digit out of 6. 1/6 = 0.16. Default threshold is 0.3. So, no.
        # Suspicious path keywords? "/login". "login" is a suspicious keyword.
        expected_score += self.detector.risk_weights["suspicious_path"]

        result = self.detector.analyze_url(url_to_test)

        self.assertAlmostEqual(
            result.risk_score, min(1.0, round(expected_score, 3)), places=2
        )
        self.assertIn(
            "Lookalike domain: 'paypa1.xyz' is similar to 'paypal.com' (distance: 1)",
            result.reasons,
        )
        self.assertIn("Suspicious TLD: .xyz", result.reasons)
        self.assertIn(
            "DNS: No A record or resolution failed for host paypa1.xyz (NXDOMAIN)",
            result.reasons,
        )
        self.assertIn("WHOIS: Domain created recently (10 days ago)", result.reasons)
        self.assertIn("Insecure HTTP protocol", result.reasons)
        self.assertIn("Suspicious path keywords: login", result.reasons)

    def test_risk_score_low_risk_url_trusted_https(self):
        # A legitimate, known, HTTPS site should have a low score
        with patch("dns.resolver.resolve") as mock_dns, patch(
            "whois.whois"
        ) as mock_whois, patch("Levenshtein.distance") as mock_lev:

            mock_a_record_results = [MagicMock()]  # Simulate successful A record lookup
            mock_a_record_results[0].address = "1.2.3.4"
            mock_mx_record_results = [
                MagicMock()
            ]  # Simulate successful MX record lookup
            mock_mx_record_results[0].exchange = "mail.google.com"

            def dns_side_effect(domain, rdtype):
                if rdtype == "A":
                    return mock_a_record_results
                if rdtype == "MX":
                    return mock_mx_record_results
                raise dns.resolver.NoAnswer

            mock_dns.side_effect = dns_side_effect

            mock_whois_data = MagicMock()
            mock_whois_data.creation_date = datetime.now().replace(
                tzinfo=None
            ) - timedelta(
                days=1000
            )  # Old domain
            mock_whois_data.registrar = "Google LLC"  # Not a privacy service
            mock_whois_data.status = ["ok"]
            mock_whois_data.text = (
                "Domain: google.com Registrant Organization: Google LLC"
            )
            mock_whois.return_value = mock_whois_data

            mock_lev.return_value = 10  # Not a lookalike

            # google.com is in self.detector.trusted_domains by default
            result = self.detector.analyze_url("https://www.google.com/search")

            # Check specific reasons are NOT present
            self.assertNotIn("Insecure HTTP protocol", result.reasons)
            self.assertFalse(any("Lookalike domain" in r for r in result.reasons))
            self.assertFalse(any("Suspicious TLD" in r for r in result.reasons))
            self.assertFalse(
                any("WHOIS: Domain created recently" in r for r in result.reasons)
            )
            self.assertFalse(
                any("WHOIS: Privacy protection" in r for r in result.reasons)
            )

            self.assertLess(
                result.risk_score,
                0.1,
                f"Score for google.com too high: {result.risk_score}, Reasons: {result.reasons}",
            )
            self.assertFalse(result.is_phishing)

    def test_risk_score_capping_at_one(self):
        test_url = "http://user@10.1.2.3.some-very-long-subdomain-that-triggers-length.fakedomain.top/%20login%20verify/account.php"
        # Add the full hostname to blacklisted_domains for one strong hit
        self.detector.blacklisted_domains.add(
            "10.1.2.3.some-very-long-subdomain-that-triggers-length.fakedomain.top"
        )

        html_content = """<form action='http://another-evil.com/s.php'><input type='password'></form>"""

        # Mock external calls to also contribute to risk
        with patch("dns.resolver.resolve") as mock_dns, patch(
            "whois.whois"
        ) as mock_whois, patch("Levenshtein.distance") as mock_lev:

            mock_dns.side_effect = dns.resolver.NXDOMAIN  # DNS no A record

            mock_whois_data = MagicMock()
            mock_whois_data.creation_date = datetime.now().replace(
                tzinfo=None
            ) - timedelta(
                days=1
            )  # WHOIS recent
            mock_whois_data.registrar = "Privacy Service Ltd."  # WHOIS privacy
            mock_whois_data.text = (
                "Domain: fakedomain.top Registrant: Privacy Service Ltd."
            )
            mock_whois_data.status = ["clientHold", "REDACTED FOR PRIVACY"]
            mock_whois.return_value = mock_whois_data

            # Mock Levenshtein to make "fakedomain.top" a lookalike of "example.com" (a common domain)
            # Add example.com to common_legitimate_domains if not already there for this test
            if "example.com" not in self.detector.common_legitimate_domains:
                self.detector.common_legitimate_domains.append("example.com")
            mock_lev.side_effect = lambda d1, d2: (
                1
                if (d1 == "fakedomain.top" and d2 == "example.com")
                or (d2 == "fakedomain.top" and d1 == "example.com")
                else 10
            )

            result = self.detector.analyze_url(test_url, html_content=html_content)

            # Check that multiple rules were hit
            self.assertIn("Blacklisted domain", result.reasons)
            self.assertIn("IP address in domain", result.reasons)  # from 10.1.2.3...
            self.assertIn("Insecure HTTP protocol", result.reasons)
            self.assertIn("@ symbol in domain (obfuscation)", result.reasons)
            self.assertIn("Hex encoding in URL path/query", result.reasons)  # from %20
            self.assertIn(
                "Excessive subdomains", result.reasons
            )  # from some-very-long-subdomain...
            self.assertIn("Suspicious path keywords: login, verify", result.reasons)
            self.assertIn("Suspicious TLD: .top", result.reasons)  # .top is suspicious
            self.assertIn(
                "Password form submits to a different domain: another-evil.com",
                result.reasons,
            )  # from HTML
            self.assertIn(
                "DNS: No A record or resolution failed for host 10.1.2.3.some-very-long-subdomain-that-triggers-length.fakedomain.top (NXDOMAIN)",
                result.reasons,
            )
            self.assertIn("WHOIS: Domain created recently (1 days ago)", result.reasons)
            self.assertIn(
                "WHOIS: Domain status suggests privacy protection", result.reasons
            )
            self.assertIn(
                "Lookalike domain: 'fakedomain.top' is similar to 'example.com' (distance: 1)",
                result.reasons,
            )

            self.assertEqual(
                result.risk_score, 1.0, "Risk score should be capped at 1.0"
            )
            self.assertTrue(result.is_phishing)


if __name__ == "__main__":
    unittest.main()
