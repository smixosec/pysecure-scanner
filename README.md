# 🔒 PySecure Scanner

A professional network security scanner for penetration testing and network auditing.

![Version](https://img.shields.io/badge/version-2.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

## ✨ Features

### 🎯 Scanning Capabilities
- **Port Scanning**: TCP port scanning with configurable ranges
- **Service Detection**: Automatic service identification
- **Banner Grabbing**: Capture service banners for analysis
- **Host Discovery**: Network host discovery tools
- **Multi-threading**: Fast scanning with configurable threads

### 🔍 Vulnerability Assessment
- **Version Detection**: Identify outdated software versions
- **Weak Credential Checks**: Detect common default credentials
- **SSL/TLS Analysis**: Check for weak encryption
- **HTTP Security**: Analyze web server security headers
- **Risk Assessment**: Automatic risk level classification

### 📊 Reporting
- **Multiple Formats**: CSV, HTML, JSON, and text reports
- **Professional HTML**: Beautiful, interactive HTML reports
- **Statistics**: Detailed scan statistics and summaries
- **Export Tools**: Easy export and sharing capabilities

### 🖥️ User Interface
- **Modern GUI**: Professional Tkinter-based interface
- **CLI Support**: Full command-line interface
- **Real-time Updates**: Live results during scanning
- **Progress Tracking**: Visual progress indicators
- **Dark/Light Theme**: Customizable interface themes

## 🚀 Quick Start

### Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/pysecure-scanner.git
cd pysecure-scanner

# Install (no external dependencies required)
python -m pip install .
```
### Basic Usage
# GUI Mode:

```bash
python main.py --gui
```
### CLI Mode:

```bash
# Scan single host
python main.py --target 192.168.1.1

# Scan network with custom ports
python main.py --target 192.168.1.0/24 --ports 1-1000

# Enable vulnerability scanning
python main.py --target example.com --vuln --report html

# Full featured scan
python main.py --target 192.168.1.1 --ports 21,22,80,443,3389 --vuln --banner --report html --output scan_report.html
```
### 🛠️ Advanced Features

## Port Specification
Single port: 80

Multiple ports: 80,443,8080

Port ranges: 1-1024

Combination: 21,22,80,443,8000-9000

## Target Formats
Single IP: 192.168.1.1

Network (CIDR): 192.168.1.0/24

Hostname: example.com

Localhost: 127.0.0.1

## Scan Options
Threads: Control scanning speed (default: 30)

Timeout: Connection timeout in seconds (default: 2.0)

Banner grabbing: Enable/disable service banner collection

Vulnerability scan: Enable security checks
### 📁 Project Structure
```text
pysecure-scanner/
├── main.py              # Main entry point (CLI & GUI launcher)
├── gui.py               # Modern GUI interface
├── scanner.py           # Core scanning engine
├── vulnerabilities.py   # Vulnerability detection
├── report.py            # Reporting system
├── requirements.txt     # Dependencies
├── config.json          # User configuration
├── README.md           # This file
└── examples/           # Example scripts and configurations
```
"# pysecure-scanner" 
