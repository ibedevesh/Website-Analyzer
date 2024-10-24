# Enhanced Website Analyzer

This Python tool performs a **comprehensive analysis of a domain** by gathering information such as DNS records, open ports, SSL certificate details, HTTP headers, WHOIS data, and more. It helps users identify the technologies used by a website and checks for critical files like `robots.txt` and `sitemap.xml`.

---

## Features

- **DNS Record Lookup**: Retrieves A, AAAA, MX, NS, and TXT records.
- **IP Resolution**: Resolves the domain to its corresponding IP address.
- **Port Scanning**: Scans common open ports.
- **HTTP Header Analysis**: Fetches the HTTP headers.
- **SSL Certificate Check**: Extracts certificate details (subject, issuer, validity).
- **WHOIS Information**: Retrieves registrar and domain ownership details.
- **robots.txt and sitemap.xml Check**: Looks for these important site files.
- **Technology Detection**: Identifies common CMS or frameworks (e.g., WordPress, React).
- **Concurrent Port Scanning**: Uses multi-threading for faster results.

---

## Prerequisites

1. **Python 3.x** installed on your machine.
2. Install the required dependencies:
   ```bash
   pip install requests beautifulsoup4 dnspython python-whois
