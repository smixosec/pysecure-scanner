# PySecure Scanner

[![Version](https://img.shields.io/badge/version-2.0-blue.svg)](https://github.com/smixosec/pysecure-scanner/releases)
[![Python](https://img.shields.io/badge/python-3.8%2B-green.svg)](https://www.python.org)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/smixosec/pysecure-scanner)

**PySecure Scanner** is a professional network security scanner for penetration testing, port scanning, service detection, and vulnerability assessment. It features both a modern GUI and powerful CLI interface.

---

## Screenshot

![PySecure Scanner GUI](screenshots/main-gui.png)

*Professional interface with real-time scan results and color-coded risk assessment*

---

## Features

### 🎯 Scanning Capabilities
- **Port Scanning** - TCP port scanning with configurable ranges
- **Service Detection** - Automatic service identification
- **Banner Grabbing** - Capture service banners for analysis
- **Host Discovery** - Network host discovery tools
- **Multi-threading** - Fast scanning with configurable threads (default: 30)

### 🔍 Vulnerability Assessment
- **Version Detection** - Identify outdated software versions
- **Weak Credential Checks** - Detect common default credentials
- **SSL/TLS Analysis** - Check for weak encryption
- **HTTP Security** - Analyze web server security headers
- **Risk Assessment** - Automatic risk level classification (High/Medium/Low)

### 📊 Reporting
- **Multiple Formats** - CSV, HTML, JSON, and text reports
- **Professional HTML** - Beautiful, interactive HTML reports
- **Statistics** - Detailed scan statistics and summaries
- **Export Tools** - Easy export and sharing capabilities

### 🖥️ User Interface
- **Modern GUI** - Professional Tkinter-based interface
- **CLI Support** - Full command-line interface
- **Real-time Updates** - Live results during scanning
- **Progress Tracking** - Visual progress indicators

---

## Installation

### Quick Start

```bash
# Clone the repository
git clone https://github.com/smixosec/pysecure-scanner.git
cd pysecure-scanner

# Run (no installation needed!)
python main.py --gui
```

### Requirements
- Python 3.8 or higher
- No external dependencies required
- Works on Windows, Linux, and macOS

---

## Usage

### GUI Mode
```bash
python main.py --gui
```

### CLI Mode

**Basic Scanning:**
```bash
# Scan single host
python main.py --target 192.168.1.1

# Scan network range
python main.py --target 192.168.1.0/24

# Scan specific ports
python main.py --target example.com --ports 80,443,8080
```

**Advanced Scanning:**
```bash
# Vulnerability scan with banners
python main.py --target 192.168.1.1 --vuln --banner

# Fast scan with high threads
python main.py --target 10.0.0.0/24 --threads 100

# Full security audit with HTML report
python main.py --target company.com --vuln --banner --report html --output audit.html
```

**Reporting:**
```bash
# HTML report
python main.py --target 192.168.1.1 --report html --output report.html

# JSON export
python main.py --target 192.168.1.1 --report json --output scan.json

# CSV format
python main.py --target 192.168.1.1 --report csv
```

---

## Command Options

| Option | Description | Example |
|--------|-------------|---------|
| `--target` | Target IP, hostname, or network (CIDR) | `192.168.1.1` or `10.0.0.0/24` |
| `--ports` | Ports to scan (comma-separated or range) | `80,443` or `1-1000` |
| `--threads` | Number of scanning threads | `--threads 50` |
| `--timeout` | Connection timeout in seconds | `--timeout 2.0` |
| `--vuln` | Enable vulnerability scanning | `--vuln` |
| `--banner` | Enable banner grabbing | `--banner` |
| `--report` | Report format (csv, html, json, txt) | `--report html` |
| `--output` | Output file path | `--output scan.html` |
| `--gui` | Launch GUI mode | `--gui` |

---

## Port Specification

PySecure Scanner supports flexible port targeting:

```bash
# Single port
python main.py --target 192.168.1.1 --ports 80

# Multiple ports
python main.py --target 192.168.1.1 --ports 80,443,8080

# Port ranges
python main.py --target 192.168.1.1 --ports 1-1024

# Combined
python main.py --target 192.168.1.1 --ports 21,22,80,443,8000-9000
```

---

## Target Formats

Supports various target specifications:

- **Single IP:** `192.168.1.1`
- **Network (CIDR):** `192.168.1.0/24`
- **Hostname:** `example.com`
- **Localhost:** `127.0.0.1`

---

## Examples

### Basic Network Audit
```bash
python main.py --target 192.168.1.0/24 --ports 21,22,80,443,3389 --report html
```

### Web Server Security Check
```bash
python main.py --target example.com --ports 80,443,8080,8443 --vuln --banner
```

### Fast Port Sweep
```bash
python main.py --target 10.0.0.0/8 --threads 100 --ports 80,443
```

### Comprehensive Security Scan
```bash
python main.py --target 192.168.1.1 --ports 1-65535 --vuln --banner --report json --output full_scan.json
```

---

## Project Structure

```
pysecure-scanner/
├── main.py              # Main entry point (CLI & GUI launcher)
├── gui.py               # Modern GUI interface
├── scanner.py           # Core scanning engine
├── vulnerabilities.py   # Vulnerability detection
├── report.py            # Reporting system
├── utils.py             # Helper functions
├── config.json          # User configuration
├── requirements.txt     # Dependencies
└── README.md           # This file
```

---

## Legal Notice

```
⚠️ FOR AUTHORIZED SECURITY TESTING ONLY

This tool is designed for authorized security testing and network auditing.

✅ ACCEPTABLE USE:
  • Testing systems you own
  • Testing with explicit written permission
  • Educational purposes in controlled environments
  • Professional penetration testing engagements

❌ PROHIBITED USE:
  • Scanning networks without authorization
  • Unauthorized penetration testing
  • Malicious hacking or exploitation
  • Violating computer fraud and abuse laws

By using PySecure Scanner, you agree to use it responsibly and ethically.
The developers assume NO LIABILITY for misuse of this tool.
```

**Applicable Laws:**
- 🇺🇸 Computer Fraud and Abuse Act (CFAA)
- 🇬🇧 Computer Misuse Act 1990
- 🇪🇺 GDPR & Cybersecurity Act
- 🌍 Your local jurisdiction's laws

---

## Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## Support

- **Documentation:** [Wiki](https://github.com/smixosec/pysecure-scanner/wiki)
- **Bug Reports:** [Issue Tracker](https://github.com/smixosec/pysecure-scanner/issues)
- **Discussions:** [GitHub Discussions](https://github.com/smixosec/pysecure-scanner/discussions)

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

Special thanks to:
- **Python Security Community** - For inspiration and best practices
- **Nmap Project** - For pioneering network scanning techniques
- **OWASP** - For vulnerability classification standards
- **Contributors** - Everyone who has helped improve this tool

---

## Download

Latest release: [v2.0](https://github.com/smixosec/pysecure-scanner/releases)

---

**Made with 🔒 for Security Professionals**

Copyright © 2026 PySecure Scanner Team
