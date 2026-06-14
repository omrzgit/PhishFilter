# Phishing Email Analyzer

## Overview
A Python-based tool that analyzes suspicious emails to detect phishing attempts by extracting URLs and checking them against VirusTotal's threat intelligence database.

## Tools & Technologies
- Python 3
- VirusTotal API (free tier)
- Regex (URL extraction)

## Features
- Extracts all URLs from email text automatically
- Checks each URL against 70+ antivirus engines via VirusTotal API
- Analyzes sender email domain for suspicious keywords
- Generates a clear threat report with SAFE/SUSPICIOUS/MALICIOUS verdict

## How It Works
1. Paste suspicious email text into the tool
2. Tool extracts all URLs using regex pattern matching
3. Each URL is submitted to VirusTotal for analysis
4. Sender domain is checked against known phishing keywords
5. A full threat report is generated with verdicts

## Skills Demonstrated
- Python scripting and API integration
- Threat intelligence and phishing detection
- Email header analysis
- Security tool development

## Screenshots
