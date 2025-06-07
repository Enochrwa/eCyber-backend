import re
import multiprocessing
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Set, Optional
import time
import tldextract
from dataclasses import dataclass
import json
from datetime import datetime
import dns.resolver
import whois
import Levenshtein


# Note: This module relies on external libraries:
# - tldextract: For accurate domain component extraction.
# - dnspython: For DNS record lookups (MX, A records).
# - python-whois: For fetching WHOIS domain registration data.
# - python-Levenshtein: For calculating similarity between domain names.
# Ensure these are installed in your environment.


@dataclass
class PhishingResult:
    """
    Represents the result of a phishing detection analysis for a given URL.

    Attributes:
        url (str): The URL that was analyzed.
        is_phishing (bool): True if the URL is classified as phishing, False otherwise.
        risk_score (float): A numerical score from 0.0 to 1.0 indicating the phishing risk.
        reasons (List[str]): A list of reasons or indicators that contributed to the classification.
        timestamp (str): ISO 8601 timestamp of when the analysis was performed.
    """

    url: str
    is_phishing: bool
    risk_score: float  # 0.0 to 1.0
    reasons: List[str]
    timestamp: str


class ClassicalPhishingDetector:
    """
    A rule-based phishing detector that analyzes URLs and HTML content for various phishing indicators.

    It uses a combination of blacklists, heuristics, pattern matching, DNS lookups,
    WHOIS data, Levenshtein distance for lookalike domains, and basic HTML content analysis
    to determine the likelihood of a URL being a phishing attempt.

    The detector maintains several internal lists (trusted domains, suspicious keywords, etc.)
    and assigns weights to different indicators to calculate a final risk score.
    """

    def __init__(self):
        """
        Initializes the ClassicalPhishingDetector with predefined datasets and configurations.
        This includes lists of trusted domains, suspicious keywords, TLDs commonly used for phishing,
        blacklisted domains, suspicious URL patterns, and risk weights for various indicators.
        """
        # Initialize detection databases
        self.common_legitimate_domains = (
            [  # Used for Levenshtein distance calculation against potential lookalikes
                "paypal.com",
                "google.com",
                "microsoft.com",
                "apple.com",
                "amazon.com",
                "linkedin.com",
                "facebook.com",
                "dropbox.com",
                "github.com",
                "bankofamerica.com",
                "icloud.com",
                "outlook.com",
                "chase.com",
                "twitter.com",
                "instagram.com",
                "yahoo.com",
                "citibank.com",
                "wellsfargo.com",
            ]
        )
        self.trusted_domains = set(
            self.common_legitimate_domains
        )  # For direct exact matching of trusted domains

        # Keywords commonly found in phishing URLs (especially in paths or subdomains)
        # Note: The previous duplicate assignment of self.suspicious_keywords has been removed.
        # The more comprehensive list is retained.
        self.suspicious_keywords = {
            "login",
            "verify",
            "account",
            "secure",
            "banking",
            "update",
            "confirm",
            "signin",
            "submit",
            "reset",
            "payment",
            "security",
            "alert",
            "invoice",
            "suspended",
            "claim",
            "authenticate",
            "reactivate",
            "passcode",
            "urgent",
        }

        self.shortener_domains = {
            "bit.ly",
            "goo.gl",
            "tinyurl.com",
            "t.co",
            "ow.ly",
            "is.gd",
            "buff.ly",
            "rebrand.ly",
            "cutt.ly",
            "shorte.st",
            "t.ly",
            "bl.ink",
            "tiny.cc",
            "rb.gy",
        }

        self.phishing_tlds = {
            ".tk",
            ".ml",
            ".ga",
            ".cf",
            ".gq",
            ".xyz",
            ".top",
            ".club",
            ".live",
            ".online",
            ".shop",
            ".work",
            ".cam",
            ".buzz",
            ".click",
        }

        self.blacklisted_domains = {
            "paypal.secure-login.com",
            "apple.security.com",
            "goog1e.com",
            "rnicrosoft.com",
            "faceb00k.com",
            "secure-microsoft.com",
            "verify-paypal.com",
            "login-update-security.com",
            "amazon-customersupport.net",
            "login-apple-support.com",  # Added
            "microsoft-securelogin.com",  # Added
            "chase-online-banking-verify.com",  # Added
        }

        self.suspicious_url_patterns = {
            r"http://",  # Non-HTTPS
            r"@",  # user@host.com URLs (phishing trick)
            "login.",  # login.paypal.support
            "-secure",  # paypal-secure.com
            "--",  # long confusing subdomains
            "cdn.",  # fake content delivery or disguised links
        }

        # Compiled regex patterns for performance
        self.ip_pattern = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
        self.hex_pattern = re.compile(r"%[0-9a-fA-F]{2}")
        self.digit_ratio_threshold = 0.3  # If >30% of URL is digits

        # Risk score weights
        self.risk_weights = {
            "blacklisted_domain": 0.8,
            "suspicious_tld": 0.6,
            "ip_in_url": 0.7,
            "shortener_domain": 0.5,
            "suspicious_keyword": 0.4,
            "http_protocol": 0.5,
            "at_symbol": 0.7,
            "hex_encoding": 0.6,
            "high_digit_ratio": 0.4,
            "long_subdomain": 0.3,
            "suspicious_path": 0.5,
            "brand_mismatch": 0.9,
            "lookalike_domain": 0.85,
            "dns_suspicious_mx": 0.4,
            "dns_no_a_record": 0.5,
            "whois_recent_creation": 0.3,
            "whois_privacy_protected": 0.2,  # Lower impact, as it's common
            "html_password_form_foreign_domain": 0.7,
            "html_brand_impersonation": 0.6,
            "suspicious_content_keyword": 0.3,
        }

        # Levenshtein distance threshold for lookalike domains
        self.lookalike_threshold = 2  # e.g., "go0gle.com" vs "google.com"

        # WHOIS settings
        self.domain_age_threshold_days = (
            90  # Domains created within 90 days are suspicious
        )

        # HTML Content related
        self.brand_impersonation_keywords_html = {  # Keywords to look for in HTML text
            "paypal",
            "google",
            "microsoft",
            "apple",
            "amazon",
            "linkedin",
            "facebook",
            "bank of america",
            "chase",
            "citibank",
            "wellsfargo",
            "dropbox",
            "icloud",
            "outlook",
            "twitter",
            "instagram",
            "yahoo",
        }

        # Multiprocessing setup for offloading CPU-bound tasks if not handled by caller.
        # Currently, analyze_url is mostly synchronous but uses this pool for some operations if live_monitor is used.
        # For direct calls to analyze_url, this pool is not directly used by analyze_url itself,
        # but by live_monitor -> handle_result if that path is taken.
        self.pool = multiprocessing.Pool(
            processes=multiprocessing.cpu_count()
        )  # Use available CPUs
        self.result_queue = (
            multiprocessing.Queue()
        )  # Queue for results from multiprocessing tasks
        self.running = multiprocessing.Value(
            "b", True
        )  # Flag for controlling background processes

    # --- Placeholder Methods ---
    def analyze_email_headers(self, headers: Dict) -> List[str]:
        """
        Placeholder for analyzing email headers for phishing indicators.

        In a real implementation, this would check SPF, DKIM, DMARC records,
        Return-Path, X-Originating-IP, and other header anomalies.

        Args:
            headers (Dict): A dictionary representing email headers.

        Returns:
            List[str]: A list of reasons if any phishing indicators are found in headers.
        """
        # Example checks (to be implemented):
        # reasons = []
        # if not verify_spf(headers.get('Received-SPF')): reasons.append("SPF check failed")
        # if not verify_dkim(headers.get('DKIM-Signature')): reasons.append("DKIM check failed")
        return []

    def analyze_email_body(self, body: str) -> List[str]:
        """
        Placeholder for analyzing email body content for phishing indicators.

        In a real implementation, this would look for suspicious links, urgent language,
        grammar mistakes, requests for sensitive information, etc.

        Args:
            body (str): The plain text or HTML content of the email body.

        Returns:
            List[str]: A list of reasons if any phishing indicators are found in the body.
        """
        # Example checks (to be implemented):
        # reasons = []
        # if "click here to update your account" in body.lower(): reasons.append("Suspicious call to action")
        # if re.search(r"http://[^\s]*shortenedlink[^\s]*", body): reasons.append("Shortened link in email body")
        return []

    def scan_email_attachments(self, attachments: List[Dict]) -> List[str]:
        """
        Placeholder for scanning email attachments for malware or phishing vectors.

        Attachments are a common vector for malware delivery in phishing campaigns.
        A real implementation would involve checking file types, scanning with AV engines,
        analyzing macros in documents, etc.

        Args:
            attachments (List[Dict]): A list of attachment details.
                Each dict could be: {"filename": "doc.pdf", "content_type": "application/pdf", "data": b"..."}

        Returns:
            List[str]: A list of reasons if any attachments are deemed suspicious.
        """
        # Example checks (to be implemented):
        # reasons = []
        # for att in attachments:
        #     if att['filename'].endswith(".exe") or att['filename'].endswith(".js"):
        #         reasons.append(f"Suspicious attachment file type: {att['filename']}")
        #     # if is_malware(att['data']): reasons.append(f"Malware detected in {att['filename']}")
        return []

    def predict_with_ml_model(
        self, url: str, content: Optional[str] = None
    ) -> Optional[Dict]:
        """
        Placeholder for integrating a machine learning model for phishing prediction.

        This would involve extracting features from the URL (and content, if available),
        feeding them to a trained ML model, and interpreting the model's output.

        Args:
            url (str): The URL to analyze.
            content (Optional[str]): Optional HTML content of the URL.

        Returns:
            Optional[Dict]: A dictionary with ML-based risk assessment (e.g.,
            {"is_phishing_ml": True, "ml_confidence": 0.9}) or None if ML model
            is not applicable or fails.
        """
        # Example structure (to be implemented):
        # features = extract_features_for_ml(url, content)
        # prediction = self.ml_model.predict(features)
        # confidence = self.ml_model.predict_proba(features)
        # if prediction == 1: # Assuming 1 is phishing
        #     return {"is_phishing_ml": True, "ml_confidence": confidence[1]}
        return None

    # --- Content Inspection ---
    def analyze_html_content(
        self, html_content: str, url_domain: str
    ) -> tuple[List[str], float]:
        """
        Analyzes basic HTML content for common phishing indicators.

        Checks for:
        1.  Password input fields in forms that submit to a different domain than the URL's domain.
        2.  Mention of brand keywords (e.g., "PayPal", "Google") in the text content if the
            URL's domain does not legitimately correspond to that brand.
        3.  Presence of other suspicious keywords (reused from URL suspicious keywords list).

        Args:
            html_content (str): The HTML content of the webpage to analyze.
            url_domain (str): The registered domain of the URL from which the HTML content was fetched.
                              Used to compare against form action domains and brand mentions.

        Returns:
            tuple[List[str], float]: A tuple containing:
                - A list of string reasons for any detected HTML-based phishing indicators.
                - A float representing the sum of risk score impacts from these indicators.
        """
        reasons = []
        score_impact = 0.0

        if not html_content:
            return reasons, score_impact

        # 1. Look for password input fields and check form action domain
        # Simplified regex for password fields and form actions
        # This is a basic check and might not cover all cases (e.g., JS-submitted forms)
        password_input_pattern = re.compile(
            r"<input[^>]*type=[\"']password[\"'][^>]*>", re.IGNORECASE
        )
        form_action_pattern = re.compile(
            r"<form[^>]*action=[\"'](.*?)[\"'][^>]*>", re.IGNORECASE
        )

        if password_input_pattern.search(html_content):
            form_actions = form_action_pattern.findall(html_content)
            for action_url in form_actions:
                if not action_url.startswith("#") and not action_url.startswith(
                    "javascript:"
                ):  # Ignore local links
                    try:
                        action_parsed = urlparse(action_url)
                        action_domain = action_parsed.netloc
                        if action_domain and action_domain != url_domain:
                            # Check if action_domain is a subdomain of url_domain
                            if not action_domain.endswith("." + url_domain):
                                reasons.append(
                                    f"Password form submits to a different domain: {action_domain}"
                                )
                                score_impact += self.risk_weights[
                                    "html_password_form_foreign_domain"
                                ]
                                break  # One instance is enough
                    except Exception:
                        # Invalid action URL, could be suspicious or just bad HTML
                        reasons.append(
                            f"Password form with potentially suspicious action URL: {action_url[:50]}"
                        )
                        score_impact += (
                            self.risk_weights["html_password_form_foreign_domain"] * 0.5
                        )  # Lower impact
                        break

        # 2. Look for brand impersonation keywords in text content
        # Basic way to get text: remove tags. This is very crude.
        text_content = re.sub(r"<[^>]+>", "", html_content).lower()
        found_brands = set()
        for brand in self.brand_impersonation_keywords_html:
            if brand in text_content:
                found_brands.add(brand)

        if found_brands:
            # Check if the actual domain matches the brand.
            # This is a simplified check; real brand protection is complex.
            is_legitimate_brand_domain = False
            for trusted_brand_domain_part in found_brands:  # e.g. "paypal"
                if trusted_brand_domain_part.replace(" ", "") in url_domain.replace(
                    "-", ""
                ):  # "bank of america" -> "bankofamerica"
                    # Check if it's a known trusted domain for that brand
                    if any(
                        trusted_brand_domain_part in trusted_domain
                        for trusted_domain in self.trusted_domains
                        if trusted_brand_domain_part in trusted_domain
                    ):
                        is_legitimate_brand_domain = True
                        break
            if not is_legitimate_brand_domain:
                reasons.append(
                    f"HTML content mentions brands ({', '.join(found_brands)}) not matching domain {url_domain}"
                )
                score_impact += self.risk_weights["html_brand_impersonation"]

        # 3. Look for other suspicious keywords in content (can reuse/adapt suspicious_keywords)
        content_keywords_found = set()
        for keyword in self.suspicious_keywords:  # Reusing URL keywords for now
            if keyword in text_content:
                content_keywords_found.add(keyword)
        if content_keywords_found:
            reasons.append(
                f"Suspicious keywords in HTML content: {', '.join(content_keywords_found)}"
            )
            score_impact += self.risk_weights["suspicious_content_keyword"]

        return reasons, score_impact

    def analyze_url(
        self, url: str, html_content: Optional[str] = None
    ) -> PhishingResult:
        """Main analysis function that checks all phishing indicators"""
        reasons = []
        risk_score = 0.0

        # Normalize URL
        url = url.lower().strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        # Parse URL components
        parsed = urlparse(url)
        domain = parsed.netloc  # Full domain e.g., sub.example.co.uk or example.com
        path = parsed.path
        # query = parsed.query # Not used yet, but useful for future query parameter analysis
        # fragment = parsed.fragment # Not used yet, but can be relevant for client-side routing

        # Extract domain parts using tldextract for robustness
        ext = tldextract.extract(
            url
        )  # Use full URL for tldextract to handle schema better if present
        subdomain = ext.subdomain
        main_domain_with_tld = (
            ext.registered_domain
        )  # e.g., "google.com" or "example.co.uk" (domain + TLD)
        # main_domain_name_only = ext.domain # e.g., "google" or "example" (just the domain part)
        tld = "." + ext.suffix if ext.suffix else ""  # Top-level domain, e.g., ".com"

        # --- URL Analysis ---
        # Each check appends a reason and adds to the risk_score if a condition is met.

        # 1. Check against blacklists (both full domain and registered domain for comprehensive coverage)
        if domain in self.blacklisted_domains or (
            main_domain_with_tld and main_domain_with_tld in self.blacklisted_domains
        ):
            reasons.append("Blacklisted domain")
            risk_score += self.risk_weights["blacklisted_domain"]

        # 2. Check TLD against a list of TLDs commonly used for phishing
        if tld and tld in self.phishing_tlds:
            reasons.append(f"Suspicious TLD: {tld}")
            risk_score += self.risk_weights["suspicious_tld"]

        # 3. Check for direct IP address usage in the domain part of the URL
        if self.ip_pattern.search(domain):  # Only check domain, not whole URL path
            reasons.append("IP address in domain")
            risk_score += self.risk_weights["ip_in_url"]

        # 4. Check if the domain is a known URL shortener
        if main_domain_with_tld and main_domain_with_tld in self.shortener_domains:
            reasons.append("URL shortener domain")
            risk_score += self.risk_weights["shortener_domain"]

        # 5. Check for insecure HTTP protocol (already normalized, but kept for explicit scoring)
        if url.startswith("http://"):
            reasons.append("Insecure HTTP protocol")
            risk_score += self.risk_weights["http_protocol"]

        # 6. Check for '@' symbol in the domain part, often used for obfuscation
        if "@" in domain:  # More specific than checking the whole URL
            reasons.append("@ symbol in domain (obfuscation)")
            risk_score += self.risk_weights["at_symbol"]

        # 7. Check for hex encoding in path or query parameters (less common/problematic in domain itself)
        if self.hex_pattern.search(path) or self.hex_pattern.search(parsed.query):
            reasons.append("Hex encoding in URL path/query")
            risk_score += self.risk_weights["hex_encoding"]

        # 8. Check digit ratio in the domain name (high digit ratio can be suspicious)
        # Use main_domain_with_tld to avoid penalizing long paths with digits.
        domain_to_check_digits = (
            main_domain_with_tld if main_domain_with_tld else domain
        )
        if domain_to_check_digits:  # Ensure there's a domain string to check
            digit_count = sum(c.isdigit() for c in domain_to_check_digits)
            length = len(domain_to_check_digits)
            if length > 0:  # Avoid division by zero for empty domain strings
                domain_digit_ratio = digit_count / length
                if domain_digit_ratio > self.digit_ratio_threshold:
                    reasons.append(
                        f"High digit ratio in domain ({domain_digit_ratio:.0%})"
                    )
                    risk_score += self.risk_weights["high_digit_ratio"]

        # 9. Check subdomain length and depth (excessive or very long subdomains can be suspicious)
        if subdomain:
            subdomain_parts = subdomain.split(".")
            if len(subdomain_parts) > 3:  # e.g., sub1.sub2.sub3.sub4.domain.com
                reasons.append(f"Excessive subdomains (depth > 3): {subdomain}")
                risk_score += self.risk_weights["long_subdomain"]
            if len(subdomain) > 50:  # A very long single subdomain string
                reasons.append(
                    f"Very long subdomain string: {subdomain[:50]}..."
                )  # Truncate for reason message
                risk_score += (
                    self.risk_weights["long_subdomain"] * 0.7
                )  # Slightly less weight than depth

        # 10. Check URL path for suspicious keywords
        path_lower = path.lower()
        path_keywords_found = set()
        for keyword in self.suspicious_keywords:
            # Check for keyword as a whole segment or at the end of a segment
            if (
                f"/{keyword}/" in path_lower
                or path_lower.endswith(f"/{keyword}")
                or f"/{keyword}." in path_lower
            ):  # e.g. /login.php
                path_keywords_found.add(keyword)
        if path_keywords_found:
            reasons.append(
                f"Suspicious path keywords: {', '.join(path_keywords_found)}"
            )
            risk_score += self.risk_weights["suspicious_path"]

        # 11. Improved Lookalike Domain Detection & Brand Impersonation
        # Compare main_domain_with_tld against common_legitimate_domains using Levenshtein distance.
        if main_domain_with_tld and not (main_domain_with_tld in self.trusted_domains):
            is_lookalike = False
            closest_match = ""
            min_dist = (
                self.lookalike_threshold + 1
            )  # Initialize min_dist to be higher than threshold

            for legit_domain in self.common_legitimate_domains:
                dist = Levenshtein.distance(main_domain_with_tld, legit_domain)
                # Condition: distance is within threshold AND it's not an exact match to a variant
                # AND the primary domain part (e.g., "google" vs "paypa1") is different to avoid
                # penalizing "mail.google.com" vs "google.com" if "mail.google.com" wasn't explicitly trusted.
                if 0 < dist <= self.lookalike_threshold:
                    # Compare the domain part before TLD (e.g., "paypa1" vs "paypal")
                    current_domain_part = ext.domain
                    legit_domain_part = tldextract.extract(legit_domain).domain
                    if (
                        current_domain_part != legit_domain_part
                    ):  # Ensures we are not comparing apple.com to apple.org if both are legit variants
                        if (
                            Levenshtein.distance(current_domain_part, legit_domain_part)
                            <= self.lookalike_threshold
                        ):
                            is_lookalike = True
                            min_dist = dist
                            closest_match = legit_domain
                            break  # Found a close enough match
            if is_lookalike:
                reasons.append(
                    f"Lookalike domain: '{main_domain_with_tld}' is similar to '{closest_match}' (distance: {min_dist})"
                )
                risk_score += self.risk_weights["lookalike_domain"]
            else:  # If not a direct Levenshtein lookalike, check for brand keywords within the domain name
                # This catches domains like "paypal-secure-login.com"
                cleaned_main_domain = main_domain_with_tld.replace("-", "").replace(
                    ".", ""
                )  # For looser matching
                found_brand_keyword_in_domain = None
                for (
                    brand_keyword
                ) in (
                    self.brand_impersonation_keywords_html
                ):  # Using HTML brand keywords for broader coverage
                    # Remove spaces from multi-word brand keywords (e.g., "bank of america" -> "bankofamerica")
                    processed_brand_keyword = brand_keyword.replace(" ", "")
                    if processed_brand_keyword in cleaned_main_domain:
                        # Ensure it's not the actual trusted domain (e.g., "paypal" in "paypal.com" is fine)
                        # and the brand keyword is not the main part of the domain itself (e.g. "apple" in "apple.com")
                        if (
                            main_domain_with_tld not in self.trusted_domains
                            and processed_brand_keyword != ext.domain
                        ):  # ext.domain is the domain part without TLD
                            found_brand_keyword_in_domain = brand_keyword
                            break
                if found_brand_keyword_in_domain:
                    reasons.append(
                        f"Potential brand impersonation in domain name: '{main_domain_with_tld}' contains '{found_brand_keyword_in_domain}'"
                    )
                    risk_score += self.risk_weights["brand_mismatch"]

        # 12. Check for other suspicious URL patterns (regex based, defined in __init__)
        # Ensure patterns are applied to the full URL for broader checks.
        for pattern_str in self.suspicious_url_patterns:
            try:
                # Using re.search for regex patterns.
                # Consider pre-compiling these patterns in __init__ for slight performance gain if they are static.
                if re.search(pattern_str, url):
                    reasons.append(f"Suspicious URL pattern matched: {pattern_str}")
                    # Use a generic weight or define specific weights per pattern if needed
                    risk_score += self.risk_weights.get(f"pattern_{pattern_str}", 0.3)
            except re.error as e:
                # Log this error, as it indicates an issue with the defined patterns
                # PROD_CLEANUP: print(
                    # PROD_CLEANUP: f"Warning: Invalid regex pattern in self.suspicious_url_patterns: {pattern_str} - {e}"
                # PROD_CLEANUP: )

        # --- Domain Reputation Checking (DNS & WHOIS) ---
        # Only perform these checks if we have a valid, non-IP registered domain,
        # and it's not a known URL shortener (as their DNS/WHOIS might be irrelevant or misleading).
        if (
            main_domain_with_tld
            and not self.ip_pattern.search(domain)
            and main_domain_with_tld not in self.shortener_domains
        ):

            # 13. DNS Checks (A record, MX record)
            try:
                dns.resolver.default_resolver.timeout = (
                    1.5  # Slightly increased timeout for resolver
                )
                dns.resolver.default_resolver.lifetime = 1.5
                try:
                    # Check for A record (use `domain` as it could be a subdomain like "sub.example.com")
                    dns.resolver.resolve(domain, "A")
                except (
                    dns.resolver.NXDOMAIN,
                    dns.resolver.NoAnswer,
                    dns.resolver.Timeout,
                ) as e:
                    reasons.append(
                        f"DNS: No A record or resolution failed for host {domain} ({type(e).__name__})"
                    )
                    risk_score += self.risk_weights["dns_no_a_record"]

                # Check MX records for the registered domain (main_domain_with_tld).
                # This is a heuristic: suspicious if a domain that looks like it should handle email
                # (e.g., not a blog, personal site) has no MX records.
                looks_like_service_domain = any(
                    kw in main_domain_with_tld
                    for kw in self.brand_impersonation_keywords_html
                ) or any(
                    kw in main_domain_with_tld
                    for kw in ["login", "service", "support", "mail", "account"]
                )

                if (
                    looks_like_service_domain
                    and main_domain_with_tld not in self.trusted_domains
                ):
                    try:
                        mx_records = dns.resolver.resolve(main_domain_with_tld, "MX")
                        if not mx_records:  # No MX records returned
                            reasons.append(
                                f"DNS: No MX records found for service-like domain {main_domain_with_tld}"
                            )
                            risk_score += self.risk_weights["dns_suspicious_mx"]
                    except (
                        dns.resolver.NoAnswer,
                        dns.resolver.NXDOMAIN,
                        dns.resolver.NoMX,
                        dns.resolver.Timeout,
                    ) as e:
                        # Specific exceptions for MX lookup failures
                        reasons.append(
                            f"DNS: MX query failed or no records for {main_domain_with_tld} ({type(e).__name__})"
                        )
                        risk_score += self.risk_weights["dns_suspicious_mx"]
            except Exception as e:  # Catch-all for other DNS query library issues
                # PROD_CLEANUP: print(
                    # PROD_CLEANUP: f"General DNS check error for {domain} or {main_domain_with_tld}: {e}"
                # PROD_CLEANUP: )

            # 14. WHOIS Checks (Creation Date, Privacy Protection)
            try:
                w = None  # Initialize whois result
                try:
                    # Use registered_domain for WHOIS lookup as it's more standard
                    w = whois.whois(main_domain_with_tld)
                except (
                    whois.parser.PywhoisError
                ) as e:  # Catch parsing errors from python-whois library
                    # PROD_CLEANUP: print(f"WHOIS parsing error for {main_domain_with_tld}: {e}")
                    reasons.append(
                        f"WHOIS: Data parsing issue for {main_domain_with_tld}"
                    )
                    risk_score += (
                        self.risk_weights["whois_recent_creation"] * 0.2
                    )  # Partial penalty for unparseable data
                except (
                    Exception
                ) as e:  # Catch other errors like network issues, timeouts from the library
                    # PROD_CLEANUP: print(f"WHOIS query error for {main_domain_with_tld}: {e}")
                    reasons.append(f"WHOIS: Query failed for {main_domain_with_tld}")
                    risk_score += (
                        self.risk_weights["whois_recent_creation"] * 0.1
                    )  # Minimal penalty for query failure

                if w and w.creation_date:
                    # WHOIS creation_date can be a single datetime object or a list. Take the first if list.
                    creation_date_val = (
                        w.creation_date[0]
                        if isinstance(w.creation_date, list)
                        else w.creation_date
                    )
                    if isinstance(creation_date_val, datetime):
                        now_utc = datetime.now(
                            datetime.timezone.utc
                        )  # Timezone-aware current time
                        # Make creation_date_val timezone-aware if it's naive, assuming UTC for naive dates from WHOIS
                        if creation_date_val.tzinfo is None:
                            # This assumption might need adjustment based on typical WHOIS library behavior
                            # For robustness, one might try to infer timezone or localize to UTC
                            age_days = (
                                datetime.now() - creation_date_val
                            ).days  # Fallback to naive comparison if tz handling is complex
                        else:  # It's timezone-aware
                            age_days = (now_utc - creation_date_val).days

                        if 0 <= age_days < self.domain_age_threshold_days:
                            reasons.append(
                                f"WHOIS: Domain created recently ({age_days} days ago)"
                            )
                            risk_score += self.risk_weights["whois_recent_creation"]
                        elif age_days < 0:  # Creation date is in the future
                            reasons.append(
                                f"WHOIS: Domain creation date in future ({age_days} days)"
                            )
                            risk_score += (
                                self.risk_weights["whois_recent_creation"] * 1.5
                            )  # Higher penalty

                elif (
                    w and not w.text
                ):  # WHOIS object exists but no creation_date and no raw text (implies query failure)
                    reasons.append(
                        f"WHOIS: Creation date missing for {main_domain_with_tld}"
                    )
                    risk_score += (
                        self.risk_weights["whois_recent_creation"] * 0.4
                    )  # Penalize if creation date is missing

                # Check for WHOIS privacy/redaction services
                if w:
                    privacy_keywords = [
                        "privacy",
                        "redacted",
                        "whoisguard",
                        "domains by proxy",
                        "contact privacy",
                        "private registration",
                        "protection",
                        "registrant info withheld",
                        "identity shielded",
                    ]
                    registrar_privacy = False
                    status_privacy = False
                    text_privacy = False  # Fallback check in raw text

                    # Check registrar field
                    if w.registrar and any(
                        pk in w.registrar.lower() for pk in privacy_keywords
                    ):
                        registrar_privacy = True
                    # Check status field (often contains "REDACTED FOR PRIVACY" or similar)
                    if w.status:
                        # Ensure w.status is a list of strings before lowercasing
                        status_str_list = [
                            s.lower() for s in w.status if isinstance(s, str)
                        ]
                        if any(
                            pk in status_item
                            for status_item in status_str_list
                            for pk in privacy_keywords
                        ):
                            status_privacy = True
                    # Fallback: check raw WHOIS text if available and not found in structured fields
                    if w.text and not (registrar_privacy or status_privacy):
                        if any(pk in w.text.lower() for pk in privacy_keywords):
                            text_privacy = True

                    if registrar_privacy or status_privacy or text_privacy:
                        reasons.append(
                            f"WHOIS: Privacy protection likely used for {main_domain_with_tld}"
                        )
                        risk_score += self.risk_weights["whois_privacy_protected"]

            except Exception as e:
                # Catch-all for any other unexpected errors in WHOIS processing logic
                # PROD_CLEANUP: print(f"Critical WHOIS logic error for {main_domain_with_tld}: {e}")

        # --- HTML Content Inspection (if content is provided) ---
        if html_content:
            # Pass the registered domain for more accurate comparison in content analysis
            # (e.g. form actions relative to the main site vs. full domain from URL bar)
            content_reasons, content_score_impact = self.analyze_html_content(
                html_content,
                main_domain_with_tld
                or domain,  # Fallback to full domain if registered_domain is empty
            )
            if content_reasons:
                reasons.extend(content_reasons)
                risk_score += content_score_impact

        # --- ML Model Prediction (Placeholder Integration) ---
        ml_prediction = self.predict_with_ml_model(url, html_content)
        if ml_prediction:  # If ML model provides a result
            if ml_prediction.get("is_phishing_ml"):
                reasons.append(
                    f"ML Model flagged as potential phishing (Confidence: {ml_prediction.get('ml_confidence', 'N/A')})"
                )
                # Example: Add half of the ML confidence to the risk score, or a fixed weight
                risk_score += ml_prediction.get("ml_confidence", 0.5) * 0.5

        # Final Risk Score Capping & Determination
        risk_score = min(
            1.0, round(risk_score, 3)
        )  # Cap at 1.0 and round to 3 decimal places

        return PhishingResult(
            url=url,
            is_phishing=risk_score
            >= 0.7,  # Threshold for classifying as phishing (can be tuned)
            risk_score=risk_score,
            reasons=list(
                set(reasons)
            ),  # Remove duplicate reasons if any rule triggered multiple ways
            timestamp=datetime.utcnow().isoformat(),  # Standard ISO format timestamp
        )

    def live_monitor(self, packet_data: Dict):
        """
        Processes network packet data for live monitoring, typically used when integrated
        with a packet sniffer that feeds data directly. This method is designed to be
        called as a target for a multiprocessing pool for concurrent analysis.

        Args:
            packet_data (Dict): A dictionary containing packet information, expected to have
                                an "http" key with "host" and "path" for URL construction.
                                Example: {"http": {"host": "example.com", "path": "/login"}}
        """
        if "http" in packet_data:
            url = packet_data["http"].get("host", "") + packet_data["http"].get(
                "path", ""
            )
            if url:
                # Use multiprocessing for parallel analysis
                self.pool.apply_async(
                    self.analyze_url,
                    args=(url,),
                    callback=self.handle_result,  # Offload analysis
                )

    def manual_check(
        self, url: str, html_content: Optional[str] = None
    ) -> PhishingResult:
        """
        Performs a phishing analysis on a given URL, optionally with its HTML content.
        This is typically initiated by a user or an external system for on-demand checks.

        Args:
            url (str): The URL to analyze.
            html_content (Optional[str]): Optional HTML content of the page at the URL.
                                          Providing HTML content enables more in-depth analysis.

        Returns:
            PhishingResult: An object containing the analysis results.
        """
        return self.analyze_url(url, html_content=html_content)

    def handle_result(self, result: PhishingResult):
        """
        Callback method for processing results from asynchronous analysis tasks
        (e.g., those submitted to the multiprocessing pool via `live_monitor`).

        If a URL is determined to be phishing, this method formats an alert message
        and puts it onto the `result_queue` for further processing by the parent system
        (e.g., PhishingBlocker).

        Args:
            result (PhishingResult): The result object from an `analyze_url` call.
        """
        if result.is_phishing:
            alert_msg = {  # Standardized alert message format
                "type": "phishing_alert",
                "url": result.url,
                "risk_score": result.risk_score,
                "reasons": result.reasons,
                "timestamp": result.timestamp,
            }
            # Put result in queue for main process to handle
            self.result_queue.put(alert_msg)

    def start(self):
        """
        Starts the detector's background processing capabilities (if any).
        Currently, this sets the `running` flag to True, which might be used
        by other components that interact with the detector's pool or queue.
        Also prints a message indicating the detector is active.
        """
        self.running.value = True
        # PROD_CLEANUP: print(
            # PROD_CLEANUP: f"ClassicalPhishingDetector started. Multiprocessing pool size: {self.pool._processes}"
        # PROD_CLEANUP: )

    def stop(self):
        """
        Stops the detector's background processes and cleans up resources.
        This includes setting the `running` flag to False, closing the
        multiprocessing pool, and joining its processes to ensure graceful shutdown.
        """
        # PROD_CLEANUP: print("Stopping ClassicalPhishingDetector...")
        self.running.value = False
        if self.pool:
            try:
                self.pool.close()  # Prevents new tasks from being submitted
                self.pool.terminate()  # Terminate running tasks - use with caution if tasks are critical
                self.pool.join()  # Waits for worker processes to exit
                # PROD_CLEANUP: print("Multiprocessing pool stopped.")
            except Exception as e:
                pass
                # PROD_CLEANUP: print(f"Error stopping multiprocessing pool: {e}")
        # PROD_CLEANUP: print("ClassicalPhishingDetector stopped.")
