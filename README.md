# 🔐 VAST - Vulnerability Analysis Security Tool

A comprehensive web-based vulnerability analysis platform that combines **static analysis**, **symbolic execution**, and **fuzz testing** to detect security vulnerabilities in C/C++, Python, and Java code.

[![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![Flask Version](https://img.shields.io/badge/flask-2.3.3-green.svg)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/license-MIT-red.svg)](LICENSE)
[![Deploy on Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy)

---

## 🚀 Features

### 🔍 Analysis Techniques

| Analysis Type | Tools | Languages | Vulnerabilities Detected |
|--------------|-------|-----------|-------------------------|
| **Static Analysis** | Semgrep | C, Python, Java | SQL injection, command injection, hardcoded secrets, buffer overflow |
| **Symbolic Analysis** | KLEE (C), Angr (Python) | C, Python | Double free, use-after-free, memory leaks |
| **Fuzz Testing** | libFuzzer (C), Atheris (Python) | C, Python | Integer overflow, division by zero, array bounds |

### 👤 Authentication & Security
- ✅ Secure User Registration with password strength validation
- ✅ Email Verification via OTP (2FA)
- ✅ Role-based Dashboard (User/Admin)
- ✅ Profile Management (Edit profile, change password)

### 🤖 AI-Powered Analysis
- ✅ AI-assisted vulnerability prioritization
- ✅ CVSS score estimation
- ✅ Remediation recommendations
- ✅ Exploitability analysis

---

## 📦 Installation

### Prerequisites
- Python 3.11+
- Docker (for KLEE symbolic execution)
- Git

### Step-by-Step Setup

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/VAST_project.git
cd VAST_project

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install analysis tools
pip install semgrep angr atheris

# 5. Pull KLEE Docker image (for C symbolic execution)
docker pull klee/klee:latest

# 6. Configure environment
cp .env.example .env
# Edit .env with your credentials

# 7. Initialize database
python run.py
# Database will be created automatically

# 8. Run the application
python run.py
