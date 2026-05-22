# ViperScan

ViperScan is a simple Python-based web application vulnerability scanner. It focuses on web form-based security issues and tests target pages for basic vulnerabilities such as SQL Injection, SSTI, SSRF, and XXE.

## Features

- Crawls a target URL
- Extracts HTML forms and form inputs
- Tests forms against:
  - SQL Injection (SQLi)
  - Server-Side Template Injection (SSTI)
  - Server-Side Request Forgery (SSRF)
  - XML External Entity (XXE)
- Saves findings to `reports/report.json`

## Requirements

- Python 3.8+
- `requests`
- `beautifulsoup4`
- `lxml`

