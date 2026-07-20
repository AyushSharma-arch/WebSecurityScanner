# 🛡️ WebSecurityScanner

Advanced Web Security Assessment Tool developed in Python for security learning and authorized security assessments.

---

## Features

- ✅ Technology Fingerprinting
- ✅ Subdomain Enumeration
- ✅ WAF Detection
- ✅ SSL/TLS Configuration Analysis
- ✅ Security Headers Analysis
- ✅ Cookie Security Analysis
- ✅ API Endpoint Discovery
- ✅ CVE Information Lookup
- ✅ Directory Discovery
- ✅ Port Scanning (Optional)
- ✅ HTML Report Generation
- ✅ JSON Report Generation
- ✅ Multi-threaded Scanning
- ✅ Proxy Support (Burp Suite)
- ✅ Colorized Terminal Output
- ✅ Professional CLI Interface

---

## Requirements

- Python 3.10+
- Kali Linux / Ubuntu / Debian
- Internet Connection

---

## Installation

Clone the repository:

```bash
git clone https://github.com/AyushSharma-arch/WebSecurityScanner.git
cd WebSecurityScanner
```

Install dependencies:

```bash
pip3 install -r requirements.txt
```

---

## Usage

Basic Scan

```bash
python3 recon.py -u https://example.com
```

Generate HTML Report

```bash
python3 recon.py -u https://example.com --html report.html
```

Generate JSON Report

```bash
python3 recon.py -u https://example.com --json report.json
```

Enable Subdomain Enumeration

```bash
python3 recon.py -u https://example.com --subdomain
```

Port Scan

```bash
python3 recon.py -u https://example.com --ports
```

Proxy Support

```bash
python3 recon.py -u https://example.com -p http://127.0.0.1:8080
```

---

## Project Structure

```
WebSecurityScanner/
│── recon.py
│── README.md
│── requirements.txt
│── LICENSE
│── screenshots/
│── reports/
```

---

## Screenshots

Add your terminal screenshots inside the **screenshots** folder.

---

## License

This project is licensed under the MIT License.

---

## Author

Ayush Sharma

GitHub:
https://github.com/AyushSharma-arch

---

## Disclaimer

This project is intended for security education and authorized security assessments only. Always obtain permission before assessing systems you do not own or administer.