# Phishing Email Analyzer

## Overview
A Python-based tool that analyzes suspicious emails to detect phishing attempts by extracting URLs, evaluating sender domains, and querying VirusTotal threat intelligence.

## Tools & Technologies
- Python 3
- VirusTotal API (v3)
- OpenPhish threat intelligence feed
- Requests
- Standard libraries: re, email, argparse

## Features
- Extracts and un-defangs URLs from plain text and HTML emails
- Strips trailing punctuation from extracted URLs
- Detects deceptive links (anchor text vs target URL mismatch)
- Checks URLs against antivirus engines via VirusTotal API
- Automatic fallback to OpenPhish feed and local heuristics if VirusTotal is unavailable
- Analyzes sender domains for brand impersonation and display name spoofing
- Parses .eml files, raw text, or single URLs via CLI flags
- Generates structured threat reports with SAFE, SUSPICIOUS, or MALICIOUS verdicts

## How It Works
1. Provide email text, a .eml file, or a specific URL to the tool
2. Tool extracts and normalizes all URLs using regex and HTML parsing
3. Each URL is checked against VirusTotal or secondary threat intelligence feeds
4. Sender identity is verified for spoofing and brand impersonation
5. A full threat report is generated with clear verdicts

## Usage
Install dependencies:
```bash
pip install -r requirements.txt
```

Run interactive mode or sample analysis:
```bash
python analyzer.py
```

Command line options:
```bash
python analyzer.py --file email.eml
python analyzer.py --url "http://suspicious-link.com"
python analyzer.py --sender "support@secure-bank-verify.com"
```

## Skills Demonstrated
- Python scripting and API integration
- Threat intelligence and phishing detection
- Email header analysis
- Security tool development

## Screenshots
<img width="500" height="458" alt="Untitled" src="https://github.com/user-attachments/assets/53b1b664-ca4f-4b5b-ad67-e183217711d7" />
