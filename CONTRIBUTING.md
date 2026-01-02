# Contributing to PySecure Scanner

Thank you for considering contributing to PySecure Scanner! This document provides guidelines and instructions for contributing.

## 📋 Table of Contents
- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Reporting Bugs](#reporting-bugs)
- [Feature Requests](#feature-requests)
- [Security Issues](#security-issues)
- [Questions and Help](#questions-and-help)

## 📜 Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before contributing.

## 🚀 Getting Started

### Ways to Contribute
- 🐛 **Report bugs** - Use the bug report template
- 💡 **Suggest features** - Use the feature request template
- 📝 **Improve documentation** - Fix typos, clarify instructions
- 🔧 **Fix issues** - Check the Issues tab for "good first issue" labels
- 🧪 **Write tests** - Help improve test coverage
- 🌐 **Translation** - Help translate the interface
- 📦 **Packaging** - Improve build scripts for different platforms

### First Time Contributors
Look for issues labeled:
- `good-first-issue`
- `help-wanted`
- `documentation`

## 💻 Development Setup

### Prerequisites
- Python 3.8 or higher
- Git
- (Optional) Virtual environment (recommended)

### Installation
```bash
# 1. Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/pysecure-scanner.git
cd pysecure-scanner

# 2. Create virtual environment (recommended)
python -m venv venv

# On Windows:
venv\Scripts\activate

# On Linux/macOS:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
python main.py --gui
