# Navigate to your project
cd ~/vast-vulnerability-scanner

# Backup old README
cp README.md README.md.backup

# Create new README
cat > README.md << 'EOF'
# 🔐 VAST - Vulnerability Analysis Security Tool

A comprehensive web-based vulnerability analysis platform that combines **static analysis**, **symbolic execution**, and **fuzz testing** to detect security vulnerabilities in C/C++, Python, and Java code.

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![Flask Version](https://img.shields.io/badge/flask-2.3.3-green.svg)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/license-MIT-red.svg)](LICENSE)

---

## 📊 Project Status

| Component | Status | Details |
|-----------|--------|---------|
| **Static Analysis** | ✅ Complete | Semgrep integration |
| **Symbolic Analysis** | ✅ Complete | KLEE (C/C++), Angr (Python), JPF (Java) |
| **Fuzz Testing** | ✅ Complete | libFuzzer (C/C++), Atheris (Python) |
| **Hybrid Analysis** | ✅ Complete | All three techniques combined |
| **Web Interface** | ✅ Complete | Flask + Bootstrap 5 |
| **PDF Reports** | ✅ Complete | Professional reporting |

---

## 🚀 Features

### Authentication & Security
- ✅ Secure User Registration with password strength validation
- ✅ Email Verification via OTP (2FA)
- ✅ Role-based Dashboard with user-specific projects
- ✅ Session Management with Flask-Login
- ✅ Profile Management (Edit profile, change password, profile picture)

### Analysis Techniques

| Analysis Type | Tools | Languages | Vulnerabilities Detected |
|--------------|-------|-----------|-------------------------|
| **Static Analysis** | Semgrep | C, Python, Java | SQL injection, command injection, hardcoded secrets, buffer overflow |
| **Symbolic Analysis** | KLEE (C), Angr (Python), JPF (Java) | C, Python, Java | Double free, use-after-free, memory leaks, deadlocks |
| **Fuzz Testing** | libFuzzer (C), Atheris (Python) | C, Python | Integer overflow, division by zero, array bounds, crashes |

### Project Management
- ✅ Create new projects with code paste or file upload
- ✅ Manage existing projects (view, edit, delete)
- ✅ Scan history with detailed reports
- ✅ PDF report generation with professional formatting

### Web Interface
- ✅ Modern dashboard with sidebar navigation
- ✅ Real-time scan results with severity categorization (Critical/High/Medium/Low/Info)
- ✅ Responsive design for all devices
- ✅ Interactive code editor

---

## 🛠️ Technology Stack

### Backend
| Technology | Version | Purpose |
|------------|---------|---------|
| Flask | 2.3.3 | Web framework |
| Flask-SQLAlchemy | 3.0.5 | Database ORM |
| Flask-Login | 0.6.2 | Authentication |
| Flask-Mail | 0.9.1 | Email (OTP) |
| PostgreSQL/SQLite | - | Database |
| bcrypt | 4.0.1 | Password hashing |

### Analysis Tools
| Tool | Language | Purpose |
|------|----------|---------|
| Semgrep | All | Static analysis |
| KLEE (Docker) | C/C++ | Symbolic execution |
| Angr | Python | Symbolic execution |
| JPF (Pattern) | Java | Symbolic analysis |
| libFuzzer | C/C++ | Fuzz testing |
| Atheris | Python | Fuzz testing |

### Frontend
| Technology | Purpose |
|------------|---------|
| Bootstrap 5 | UI framework |
| Font Awesome | Icons |
| JavaScript | Interactive features |
| HTML5/CSS3 | Structure & styling |

---

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- Git
- Docker (for KLEE symbolic execution)
- Virtual environment (recommended)

### Step-by-Step Setup

```bash
# 1. Clone the repository
git clone https://github.com/Naqash14/VAST_project.git
cd VAST_project

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Install analysis tools
pip install semgrep          # Static analysis
pip install angr             # Python symbolic execution
pip install atheris          # Python fuzzing

# 5. Pull KLEE Docker image (for C/C++ symbolic execution)
docker pull klee/klee:latest

# 6. Configure environment
cp .env.example .env
# Edit .env file with your email settings (for OTP)

# 7. Initialize database
python run.py
# Database will be created automatically on first run

# 8. Run the application
python run.py
