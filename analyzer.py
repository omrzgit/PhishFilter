import argparse
import base64
import email
from email import policy
from email.utils import parseaddr
import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
import requests

API_KEY = "API key"

KNOWN_LEGITIMATE_DOMAINS = {
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
    "github.com",
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "citi.com",
    "netflix.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "twitter.com",
    "x.com",
    "dropbox.com",
    "dhl.com",
    "fedex.com",
    "ups.com",
}

BRAND_KEYWORDS = [
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "netflix",
    "chase",
    "bankofamerica",
    "wellsfargo",
    "citi",
    "github",
    "facebook",
    "dropbox",
]

SUSPICIOUS_DOMAIN_KEYWORDS = [
    "secure",
    "verify",
    "account",
    "update",
    "login",
    "bank",
    "support",
    "billing",
    "auth",
    "security",
    "confirm",
    "password",
    "wallet",
]

HIGH_RISK_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "cam", "work", "loan", "click", "rest", "fit", "surf"
}

_OPENPHISH_CACHE: Optional[Set[str]] = None


def undefang_text(text: str) -> str:
    """Normalize defanged URLs and domain representations."""
    normalized = re.sub(r'hxxp(s?)://', r'http\1://', text, flags=re.IGNORECASE)
    normalized = re.sub(r'\[\.\]|\(\.\)', '.', normalized)
    normalized = re.sub(r'\[:\]', ':', normalized)
    return normalized


def clean_extracted_url(raw_url: str) -> str:
    """Strip trailing punctuation that belongs to surrounding sentences."""
    cleaned = re.sub(r'[.,;!?)\]}>"\'\\]+$', '', raw_url)
    return cleaned


def extract_html_links(html_content: str) -> List[Tuple[str, str]]:
    """Extract (href, anchor_text) tuples from HTML content."""
    pattern = r'<a\s+(?:[^>]*?\s+)?href=["\']([^"\']+)["\'][^>]*>(.*?)</a>'
    matches = re.findall(pattern, html_content, flags=re.IGNORECASE | re.DOTALL)
    links = []
    for href, text in matches:
        clean_href = clean_extracted_url(undefang_text(href.strip()))
        clean_text = re.sub(r'<[^>]+>', '', text).strip()
        if clean_href.startswith(("http://", "https://", "www.")):
            if clean_href.startswith("www."):
                clean_href = f"http://{clean_href}"
            links.append((clean_href, clean_text))
    return links


def extract_urls(email_text: str) -> List[str]:
    """Extract and normalize all URLs from email text or HTML."""
    normalized_text = undefang_text(email_text)

    url_pattern = r'(?:https?://|www\.)[^\s<>"{}|\\^`\[\]]+'
    found_urls = re.findall(url_pattern, normalized_text, flags=re.IGNORECASE)

    html_links = extract_html_links(normalized_text)
    for href, _ in html_links:
        found_urls.append(href)

    cleaned_urls = []
    for url in found_urls:
        cleaned = clean_extracted_url(url)
        if cleaned.lower().startswith("www."):
            cleaned = f"http://{cleaned}"
        if cleaned and cleaned not in cleaned_urls:
            cleaned_urls.append(cleaned)

    return cleaned_urls


def check_anchor_mismatches(email_text: str) -> List[Dict[str, str]]:
    """Detect deceptive links where the visible anchor text differs from the destination URL."""
    html_links = extract_html_links(undefang_text(email_text))
    mismatches = []
    for href, text in html_links:
        if re.match(r'^https?://', text, flags=re.IGNORECASE) or text.lower().startswith("www."):
            display_target = clean_extracted_url(text.strip())
            if display_target.lower().startswith("www."):
                display_target = f"http://{display_target}"
            if display_target.rstrip("/").lower() != href.rstrip("/").lower():
                mismatches.append({
                    "anchor_text": text,
                    "target_url": href,
                    "warning": "Visible link text displays a different destination than the actual URL."
                })
    return mismatches


def check_url_heuristics(url: str) -> Dict[str, Any]:
    """Offline heuristic inspection of URL structure, hostname, and keywords."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    netloc = parsed.netloc.split(":")[0].lower()
    path = parsed.path.lower()
    query = parsed.query.lower()

    flags: List[str] = []
    risk_level = "SAFE"

    # 1. Raw IPv4 address check
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', netloc):
        flags.append("Hostname is a raw IP address instead of a domain name")
        risk_level = "SUSPICIOUS"

    # 2. High-risk TLD check
    tld = netloc.split(".")[-1] if "." in netloc else ""
    if tld in HIGH_RISK_TLDS:
        flags.append(f"High-abuse top-level domain detected (.{tld})")
        if risk_level != "MALICIOUS":
            risk_level = "SUSPICIOUS"

    # 3. Brand impersonation in domain / subdomain
    is_trusted_host = False
    for legit in KNOWN_LEGITIMATE_DOMAINS:
        if netloc == legit or netloc.endswith(f".{legit}"):
            is_trusted_host = True
            break

    if not is_trusted_host:
        for brand in BRAND_KEYWORDS:
            if brand in netloc and not (netloc == f"{brand}.com" or netloc.endswith(f".{brand}.com")):
                flags.append(f"Brand impersonation attempt in URL hostname ({brand})")
                risk_level = "MALICIOUS"
                break

    # 4. Sensitive credential harvesting keywords in path or query
    path_keywords = [
        kw for kw in SUSPICIOUS_DOMAIN_KEYWORDS
        if kw in path or kw in query
    ]
    if path_keywords and not is_trusted_host:
        flags.append(f"Sensitive authentication/billing keywords in URL path: {path_keywords}")
        if risk_level != "MALICIOUS":
            risk_level = "SUSPICIOUS"

    # 5. Excessive subdomains
    domain_parts = netloc.split(".")
    if len(domain_parts) >= 5:
        flags.append(f"Excessive subdomain depth ({len(domain_parts)} levels)")
        if risk_level == "SAFE":
            risk_level = "SUSPICIOUS"

    return {
        "source": "Heuristic Analysis",
        "url": url,
        "risk_level": risk_level,
        "flags": flags
    }


def fetch_openphish_feed() -> Set[str]:
    """Fetch and cache community threat feed from OpenPhish."""
    global _OPENPHISH_CACHE
    if _OPENPHISH_CACHE is not None:
        return _OPENPHISH_CACHE

    _OPENPHISH_CACHE = set()
    try:
        resp = requests.get("https://openphish.com/feed.txt", timeout=5)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                clean_line = line.strip().rstrip("/")
                if clean_line:
                    _OPENPHISH_CACHE.add(clean_line.lower())
    except Exception:
        pass

    return _OPENPHISH_CACHE


def check_openphish(url: str, custom_feed: Optional[Set[str]] = None) -> Optional[Dict[str, Any]]:
    """Check if URL exists in OpenPhish active phishing feed."""
    feed = custom_feed if custom_feed is not None else fetch_openphish_feed()
    normalized_target = url.strip().rstrip("/").lower()

    if normalized_target in feed:
        return {
            "source": "OpenPhish Threat Intelligence",
            "url": url,
            "risk_level": "MALICIOUS",
            "flags": ["URL listed in active OpenPhish community threat feed"]
        }
    return None


def check_virustotal(url: str, api_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Query VirusTotal API v3 for a given URL."""
    key = api_key or API_KEY
    if not key or key == "API key":
        return None

    headers = {
        "x-apikey": key,
        "Accept": "application/json"
    }

    try:
        url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
        get_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        response = requests.get(get_endpoint, headers=headers, timeout=15)

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            post_endpoint = "https://www.virustotal.com/api/v3/urls"
            post_headers = {
                "x-apikey": key,
                "Content-Type": "application/x-www-form-urlencoded"
            }
            submit_resp = requests.post(post_endpoint, headers=post_headers, data={"url": url}, timeout=15)
            if submit_resp.status_code not in (200, 201):
                return None

            submit_data = submit_resp.json()
            analysis_id = submit_data.get("data", {}).get("id")
            if not analysis_id:
                return None

            analysis_endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            for _ in range(3):
                time.sleep(2)
                analysis_resp = requests.get(analysis_endpoint, headers=headers, timeout=15)
                if analysis_resp.status_code == 200:
                    analysis_json = analysis_resp.json()
                    status = analysis_json.get("data", {}).get("attributes", {}).get("status")
                    if status == "completed":
                        return analysis_json

            return analysis_resp.json() if analysis_resp.status_code == 200 else None
        elif response.status_code in (401, 429):
            return None
        else:
            return None

    except requests.RequestException:
        return None


def check_url(url: str, api_key: Optional[str] = None, enable_fallback: bool = True) -> Optional[Dict[str, Any]]:
    """Check URL against VirusTotal with automatic fallback to OpenPhish and local heuristics."""
    vt_result = check_virustotal(url, api_key=api_key)
    if vt_result is not None:
        return vt_result

    if not enable_fallback:
        return None

    # Fallback threat intelligence layer
    openphish_result = check_openphish(url)
    if openphish_result is not None:
        return openphish_result

    # Offline heuristic fallback layer
    heuristic_result = check_url_heuristics(url)
    return heuristic_result


def generate_report(url: str, result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate and display threat report for a URL."""
    print("\n" + "=" * 50)
    print(f"URL: {url}")

    if result is None:
        print("Status: Threat intelligence unavailable.")
        print("VERDICT: UNKNOWN")
        print("=" * 50)
        return {"url": url, "verdict": "UNKNOWN", "malicious": 0, "suspicious": 0, "harmless": 0}

    # Handle VirusTotal response format
    if "data" in result:
        attributes = result.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats") or attributes.get("stats") or {}

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        print("Threat Source: VirusTotal API")
        print(f"Malicious engines:  {malicious}")
        print(f"Suspicious engines: {suspicious}")
        print(f"Harmless engines:   {harmless}")
        print(f"Undetected engines: {undetected}")

        if malicious > 0:
            verdict = "MALICIOUS"
            print("VERDICT: [MALICIOUS] - Do not click this URL!")
        elif suspicious > 0:
            verdict = "SUSPICIOUS"
            print("VERDICT: [SUSPICIOUS] - Treat with caution!")
        else:
            verdict = "SAFE"
            print("VERDICT: [SAFE]")

        print("=" * 50)
        return {
            "source": "VirusTotal",
            "url": url,
            "verdict": verdict,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected
        }

    # Handle OpenPhish / Heuristics fallback format
    source = result.get("source", "Alternative Threat Intelligence")
    risk_level = result.get("risk_level", "SAFE")
    flags = result.get("flags", [])

    print(f"Threat Source: {source} (Fallback)")
    if flags:
        for flag in flags:
            print(f"Indicator: {flag}")
    else:
        print("Indicator: No threat indicators identified")

    if risk_level == "MALICIOUS":
        verdict = "MALICIOUS"
        print("VERDICT: [MALICIOUS] - Do not click this URL!")
    elif risk_level == "SUSPICIOUS":
        verdict = "SUSPICIOUS"
        print("VERDICT: [SUSPICIOUS] - Treat with caution!")
    else:
        verdict = "SAFE"
        print("VERDICT: [SAFE]")

    print("=" * 50)
    return {
        "source": source,
        "url": url,
        "verdict": verdict,
        "flags": flags
    }


def analyze_sender(email_address: str) -> Dict[str, Any]:
    """Analyze sender email address and display name for spoofing and phishing patterns."""
    print("\n" + "=" * 50)
    print(f"SENDER ANALYSIS: {email_address}")

    display_name, raw_address = parseaddr(email_address.strip())
    if "@" in raw_address:
        user_part, domain = raw_address.rsplit("@", 1)
    elif "@" in email_address:
        user_part, domain = email_address.rsplit("@", 1)
    else:
        user_part, domain = "", email_address.strip()

    domain = domain.lower().strip(">").strip()
    domain_labels = domain.split(".")
    root_domain = ".".join(domain_labels[-2:]) if len(domain_labels) >= 2 else domain

    findings: List[str] = []
    risk_level = "SAFE"

    is_trusted = False
    for legit in KNOWN_LEGITIMATE_DOMAINS:
        if domain == legit or domain.endswith(f".{legit}"):
            is_trusted = True
            break

    if is_trusted:
        print(f"Verified legitimate domain: {domain}")
    else:
        impersonated_brands = []
        for brand in BRAND_KEYWORDS:
            if brand in domain and not (domain == f"{brand}.com" or domain.endswith(f".{brand}.com")):
                impersonated_brands.append(brand)

        if impersonated_brands:
            risk_level = "MALICIOUS"
            findings.append(f"Brand impersonation attempt detected: {', '.join(impersonated_brands)}")

        flagged_keywords = [
            kw for kw in SUSPICIOUS_DOMAIN_KEYWORDS
            if kw in domain
        ]

        if len(flagged_keywords) >= 2 or ("-" in domain and flagged_keywords):
            if risk_level != "MALICIOUS":
                risk_level = "SUSPICIOUS"
            findings.append(f"Suspicious domain naming keywords: {flagged_keywords}")
        elif flagged_keywords:
            findings.append(f"Domain contains sensitive keyword: {flagged_keywords}")

    if display_name:
        display_lower = display_name.lower()
        for brand in BRAND_KEYWORDS:
            if brand in display_lower and not is_trusted:
                risk_level = "MALICIOUS"
                findings.append(
                    f"Display name spoofing: Name claims '{display_name}' but sender domain is '{domain}'"
                )
                break

    if findings:
        for finding in findings:
            print(f"Warning: {finding}")
        print(f"SENDER VERDICT: [{risk_level}]")
    else:
        print(f"Domain appears normal: {domain}")
        print("SENDER VERDICT: [SAFE]")

    print("=" * 50)

    return {
        "display_name": display_name,
        "email": raw_address,
        "domain": domain,
        "risk_level": risk_level,
        "findings": findings
    }


def parse_email_message(content: str) -> Dict[str, Any]:
    """Parse raw email string or .eml content into headers and body."""
    msg = email.message_from_string(content, policy=policy.default)

    sender = msg.get("From", "")
    subject = msg.get("Subject", "")
    date = msg.get("Date", "")
    auth_results = msg.get("Authentication-Results", "")
    spf_header = msg.get("Received-SPF", "")

    body_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get("Content-Disposition", ""))
            if "attachment" not in cdispo and ctype in ("text/plain", "text/html"):
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        body_parts.append(payload.decode(charset, errors="replace"))
                except Exception:
                    pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                body_parts.append(payload.decode(charset, errors="replace"))
            else:
                body_parts.append(msg.get_payload() or "")
        except Exception:
            body_parts.append(content)

    full_body = "\n".join(body_parts) if body_parts else content

    auth_findings = []
    combined_auth = f"{auth_results} {spf_header}".lower()
    if "spf=fail" in combined_auth or "spf=softfail" in combined_auth:
        auth_findings.append("SPF check failed or softfailed")
    if "dkim=fail" in combined_auth:
        auth_findings.append("DKIM verification failed")
    if "dmarc=fail" in combined_auth:
        auth_findings.append("DMARC check failed")

    return {
        "sender": sender,
        "subject": subject,
        "date": date,
        "body": full_body,
        "auth_findings": auth_findings
    }


def analyze_full_email(
    content: str,
    explicit_sender: Optional[str] = None,
    check_vt: bool = True,
    api_key: Optional[str] = None
) -> Dict[str, Any]:
    """Complete analysis workflow for email text or .eml message."""
    parsed = parse_email_message(content)
    sender = explicit_sender or parsed.get("sender")

    sender_result = None
    if sender:
        sender_result = analyze_sender(sender)

    if parsed.get("auth_findings"):
        print("\n" + "=" * 50)
        print("EMAIL AUTHENTICATION CHECKS:")
        for auth_warning in parsed["auth_findings"]:
            print(f"Warning: {auth_warning}")
        print("=" * 50)

    email_body = parsed.get("body", content)
    urls = extract_urls(email_body)

    mismatches = check_anchor_mismatches(email_body)
    if mismatches:
        print("\n" + "=" * 50)
        print("DECEPTIVE LINK DETECTIONS (Anchor / Target Mismatch):")
        for m in mismatches:
            print(f"Warning: Displayed '{m['anchor_text']}' -> Points to '{m['target_url']}'")
        print("=" * 50)

    url_reports = []
    if not urls:
        print("\nNo URLs detected in email body.")
    else:
        print(f"\nExtracted {len(urls)} URL(s):")
        for u in urls:
            print(f" - {u}")

        for u in urls:
            result = check_url(u, api_key=api_key, enable_fallback=True) if check_vt else check_url_heuristics(u)
            rep = generate_report(u, result)
            url_reports.append(rep)

    return {
        "parsed_metadata": {
            "sender": sender,
            "subject": parsed.get("subject"),
            "date": parsed.get("date")
        },
        "sender_analysis": sender_result,
        "auth_findings": parsed.get("auth_findings", []),
        "anchor_mismatches": mismatches,
        "urls": urls,
        "url_reports": url_reports
    }


def main():
    parser = argparse.ArgumentParser(
        description="Phishing Email Analyzer - Inspect suspicious emails, sender headers, and URLs."
    )
    parser.add_argument("-f", "--file", help="Path to email file (.eml or text file)")
    parser.add_argument("-t", "--text", help="Raw email text string to analyze")
    parser.add_argument("-s", "--sender", help="Sender email address to inspect")
    parser.add_argument("-u", "--url", help="Single URL to inspect with threat intelligence")
    parser.add_argument("--skip-vt", action="store_true", help="Skip VirusTotal and use fallback intelligence")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()

    print("=" * 50)
    print("   PHISHING EMAIL ANALYZER")
    print("=" * 50)

    if args.url:
        result = check_url(args.url, enable_fallback=True) if not args.skip_vt else check_url_heuristics(args.url)
        report = generate_report(args.url, result)
        if args.json:
            print(json.dumps(report, indent=2))
        return

    if args.sender and not args.file and not args.text:
        sender_report = analyze_sender(args.sender)
        if args.json:
            print(json.dumps(sender_report, indent=2))
        return

    email_content = None
    sender = args.sender

    if args.file:
        if not os.path.exists(args.file):
            print(f"Error: File not found: {args.file}")
            sys.exit(1)
        with open(args.file, "r", encoding="utf-8", errors="replace") as f:
            email_content = f.read()
    elif args.text:
        email_content = args.text
    else:
        if sys.stdin.isatty():
            print("\nSelect an option:")
            print("1. Run sample phishing analysis (default)")
            print("2. Enter email text manually")
            print("3. Analyze single sender address")
            print("4. Analyze single URL")
            choice = input("\nEnter choice [1-4] (default: 1): ").strip()

            if choice == "2":
                print("\nEnter email text (end with an empty line or Ctrl+Z/Ctrl+D):")
                lines = []
                try:
                    while True:
                        line = input()
                        if not line and lines:
                            break
                        lines.append(line)
                except EOFError:
                    pass
                email_content = "\n".join(lines)
            elif choice == "3":
                s = input("Enter sender address: ").strip()
                if s:
                    analyze_sender(s)
                return
            elif choice == "4":
                u = input("Enter URL: ").strip()
                if u:
                    res = check_url(u, enable_fallback=True) if not args.skip_vt else check_url_heuristics(u)
                    generate_report(u, res)
                return

        if not email_content:
            sender = "support@secure-bank-verify.com"
            email_content = """From: "Bank Security Support" <support@secure-bank-verify.com>
Subject: Urgent: Your account has been compromised
Date: Wed, 07 Oct 2026 10:00:00 +0000

Dear user, your account has been compromised.
Please verify your identity here: http://suspicious-link.com
Or review account settings: hxxp://bank-update[.]com/login.
Or visit our support page: http://google.com
"""

    report = analyze_full_email(
        email_content,
        explicit_sender=sender,
        check_vt=not args.skip_vt
    )

    if args.json:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
