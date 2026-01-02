<div align="center">

# 🔒 PySecure Scanner

### **The Modern Network Security Scanner**

[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0-blue)](https://github.com/smixosec/pysecure-scanner/releases)
[![Stars](https://img.shields.io/github/stars/smixosec/pysecure-scanner?style=social)](https://github.com/smixosec/pysecure-scanner/stargazers)

**Fast · Lightweight · Professional**

[📥 Installation](#-installation) •
[🚀 Quick Start](#-quick-start) •
[📖 Documentation](https://github.com/smixosec/pysecure-scanner/wiki) •
[🐛 Report Bug](https://github.com/smixosec/pysecure-scanner/issues)

</div>

---

## 📸 Screenshot

![PySecure Scanner GUI](screenshots/main-gui.png)

*Modern GUI interface with real-time scanning and color-coded risk assessment*

---

## ⚡ Why PySecure Scanner?

PySecure Scanner is a **professional network security tool** designed for penetration testers and security professionals. Built with Python for **speed, simplicity, and power**.

```bash
# Traditional scanners take 17 minutes
# PySecure Scanner does it in seconds ⚡

python main.py --gui    # Launch GUI
python main.py --target 192.168.1.0/24 --vuln    # CLI scan
```

**Key Advantages:**

| Feature | PySecure Scanner | Traditional Tools |
|---------|------------------|-------------------|
| **Setup Time** | < 1 minute ⚡ | 5-10 minutes |
| **GUI Interface** | ✅ Modern & Built-in | ❌ Third-party only |
| **Dependencies** | ✅ Pure Python | ⚠️ Complex setup |
| **Learning Curve** | ✅ Beginner-friendly | ⚠️ Steep |
| **Report Formats** | ✅ 4 formats | ⚠️ Limited |
| **Speed** | ✅ Multi-threaded | ⚠️ Varies |

---

## ✨ Features

### 🎯 **Core Capabilities**

- **⚡ Lightning Fast Scanning** - Multi-threaded engine with 30+ concurrent threads
- **🔍 Service Detection** - Automatic service identification and banner grabbing
- **🛡️ Vulnerability Assessment** - Built-in checks for common vulnerabilities
- **📊 Professional Reporting** - Export to CSV, HTML, JSON, and TXT
- **🎨 Modern GUI** - User-friendly interface with real-time updates
- **💻 Full CLI Support** - Complete command-line interface for automation
- **🎯 Flexible Targeting** - Support for single IPs, CIDR ranges, and hostnames
- **🌈 Risk Assessment** - Color-coded risk levels (High/Medium/Low)

### 🚀 **Advanced Features**

- Multi-threading with configurable thread count
- Real-time progress tracking and live results
- Banner grabbing for detailed service info
- Weak credential detection
- Network range scanning (CIDR notation)
- Custom port specifications (ranges and lists)
- Automatic service version detection
- Zero external dependencies for basic scanning

---

## 📥 Installation

### **Option 1: Quick Install (Recommended)**

```bash
# Clone the repository
git clone https://github.com/smixosec/pysecure-scanner.git
cd pysecure-scanner

# Run directly - no installation needed!
python main.py --gui
```

### **Option 2: From Release**

1. Download from [Releases](https://github.com/smixosec/pysecure-scanner/releases)
2. Extract and run `python main.py --gui`

### **Requirements**

- Python 3.8 or higher
- No external dependencies required
- Works on Windows, Linux, and macOS

---

## 🚀 Quick Start

### **GUI Mode** (Recommended for Beginners)

```bash
python main.py --gui
```

### **CLI Mode** (For Automation & Advanced Users)

```bash
# Quick scan
python main.py --target 192.168.1.1

# Network scan with report
python main.py --target 192.168.1.0/24 --report html

# Full security audit
python main.py --target example.com --ports 1-1000 --vuln --banner

# Custom ports
python main.py --target 192.168.1.1 --ports 21,22,80,443,3389,8080

# Fast scan with high threads
python main.py --target 10.0.0.1 --threads 50

# Export to JSON
python main.py --target scanme.nmap.org --report json --output results.json
```

---

## 📚 Usage Examples

### **Basic Scanning**

```bash
# Scan single host
python main.py --target 192.168.1.1

# Scan network range
python main.py --target 192.168.1.0/24

# Scan specific ports
python main.py --target example.com --ports 80,443,8080
```

### **Advanced Scanning**

```bash
# Vulnerability scan with banner grabbing
python main.py --target 192.168.1.1 --vuln --banner

# Fast scan with 100 threads
python main.py --target 10.0.0.0/24 --threads 100

# Comprehensive audit with HTML report
python main.py --target company.com --vuln --banner --report html --output audit.html
```

### **Reporting**

```bash
# CSV format
python main.py --target 192.168.1.1 --report csv

# HTML report (professional format)
python main.py --target 192.168.1.1 --report html --output report.html

# JSON for automation
python main.py --target 192.168.1.1 --report json --output scan.json

# Text format
python main.py --target 192.168.1.1 --report txt
```

---

## ⚙️ Command Options

| Option | Description | Example |
|--------|-------------|---------|
| `--target` | Target IP, hostname, or network | `192.168.1.1` or `192.168.1.0/24` |
| `--ports` | Ports to scan (comma-separated or range) | `80,443` or `1-1000` |
| `--threads` | Number of scanning threads | `--threads 50` |
| `--timeout` | Connection timeout in seconds | `--timeout 2.0` |
| `--vuln` | Enable vulnerability scanning | `--vuln` |
| `--banner` | Enable banner grabbing | `--banner` |
| `--report` | Report format (csv, html, json, txt) | `--report html` |
| `--output` | Output file path | `--output scan_results.html` |
| `--gui` | Launch GUI mode | `--gui` |

---

## ✅ Pros

- ✔️ **Easy Setup** - No complex dependencies or configuration
- ✔️ **Fast Scanning** - Multi-threaded engine for rapid results
- ✔️ **Modern GUI** - Intuitive interface with real-time feedback
- ✔️ **Multiple Reports** - 4 export formats for different needs
- ✔️ **Cross-Platform** - Works on Windows, Linux, and macOS
- ✔️ **Pure Python** - Easy to modify and extend
- ✔️ **Beginner Friendly** - Simple commands, clear output
- ✔️ **Professional Grade** - Built-in vulnerability detection
- ✔️ **Active Development** - Regular updates and improvements

---

## ❌ Cons

- ✖️ **TCP Only** - Currently no UDP scanning support
- ✖️ **No IPv6** - IPv6 support planned for future release
- ✖️ **Basic Vuln Detection** - Not as comprehensive as dedicated vulnerability scanners
- ✖️ **Admin Rights** - May require elevated privileges for low port scanning (< 1024)
- ✖️ **Python Required** - Needs Python 3.8+ installed (no standalone binary yet)

---

## 📁 Project Structure

```
pysecure-scanner/
├── main.py              # Main entry point & CLI launcher
├── gui.py               # Tkinter GUI interface
├── scanner.py           # Core scanning engine
├── vulnerabilities.py   # Vulnerability detection module
├── report.py            # Multi-format report generator
├── utils.py             # Helper functions
├── config.json          # User configuration
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

---

## 🛡️ Legal & Ethical Use

```diff
⚠️ IMPORTANT: FOR AUTHORIZED TESTING ONLY

+ ✅ DO: Use on systems you own or have written permission to test
+ ✅ DO: Follow responsible disclosure practices
+ ✅ DO: Comply with all applicable laws and regulations

- ❌ DON'T: Scan networks without authorization
- ❌ DON'T: Use for malicious purposes or illegal activities
- ❌ DON'T: Violate computer fraud and abuse laws
```

**By using PySecure Scanner, you agree to:**
- Only scan systems you own or have explicit permission to test
- Comply with all local, state, and federal laws
- Use the tool responsibly and ethically
- Accept full responsibility for your actions

**Applicable Laws:**
- 🇺🇸 Computer Fraud and Abuse Act (CFAA)
- 🇬🇧 Computer Misuse Act 1990
- 🇪🇺 GDPR & Cybersecurity Act
- 🌍 Your local jurisdiction's laws

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

- 🌟 **Star this repo** - Show your support!
- 🐛 **Report bugs** - [Open an issue](https://github.com/smixosec/pysecure-scanner/issues)
- 💡 **Suggest features** - We're always looking for ideas
- 🔧 **Submit PRs** - Code contributions welcome
- 📖 **Improve docs** - Help others get started

```bash
# Fork and clone
git clone https://github.com/smixosec/pysecure-scanner.git

# Create branch
git checkout -b feature/amazing-feature

# Make changes and commit
git commit -m "Add amazing feature"

# Push and create PR
git push origin feature/amazing-feature
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

Built with ❤️ by the security community.

Special thanks to:
- **Python Security Community** - For inspiration and best practices
- **Contributors** - Everyone who has helped improve this tool
- **You** - For choosing PySecure Scanner!

---

<div align="center">

**Made with 🔒 for Security Professionals**

[⬇️ Download](https://github.com/smixosec/pysecure-scanner/releases) • [📖 Docs](https://github.com/smixosec/pysecure-scanner/wiki) • [💬 Discussions](https://github.com/smixosec/pysecure-scanner/discussions)

**⭐ If you find this useful, please star the repo! ⭐**

---

**Topics:** `python` `security` `scanner` `port-scanner` `network-scanner` `penetration-testing` `vulnerability-scanner` `cybersecurity` `infosec` `hacking-tool`

</div>
