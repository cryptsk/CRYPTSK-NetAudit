CRYPTSK NetAudit
 
The CRYPTSK NetAudit tool

📁 Project Structure

netaudit/
├── core/
│   ├── __init__.py
│   ├── collectors.py      # Safe system data collection
│   ├── sysctl_checks.py   # Kernel parameter checks
│   ├── firewall_checks.py # Firewall configuration checks
│   ├── network_checks.py  # Network interface checks
│   ├── security_checks.py # Security configuration checks
│   └── scoring_engine.py  # Score calculation & reporting
├── cli/
│   └── main.py            # CLI with Typer
├── api/
│   └── main.py            # FastAPI server
├── requirements.txt
├── setup.py
├── README.md
└── __main__.py

🎯 Features

CLI Commands:

netaudit scan - Run full audit
netaudit scan --json - JSON output
netaudit score - Quick score check
netaudit check <category> - Check specific category

Web Dashboard:

Score Display - Large visual indicator (0-100)
Risk Breakdown - Critical/Warning/Info/Passed counts
Category Scores - Sysctl, Firewall, Network, Security
Detailed Findings - Expandable per-category view
Export JSON - Download full report

🔒 Security

Read-only operations (no modifications)
Safe subprocess execution (no shell=True)
Localhost binding only
Input sanitization throughout

The **CRYPTSK NetAudit** project is complete! Let me explain how to use it and what's required:

All components are working:
- **Python Core Modules** - All check modules implemented
- **CLI Tool** - Typer-based command-line interface  
- **FastAPI Backend** - Running on port 3031
- **Next.js Web Dashboard** - Running and displaying real audit data

---

## 🖥️ How to Use

### Web Dashboard (Currently Running)
The dashboard is already accessible in the **Preview Panel** on the right. You can:
- Click **"Scan"** to run a new audit
- Click **"Fresh Scan"** to clear cache and re-scan
- Click **"Export JSON"** to download the report
- Browse findings by category tabs (Critical, Warnings, All Findings, Recommendations)

### CLI Usage

```bash
# Navigate to the netaudit directory
cd /home/z/my-project/netaudit

# Run a full scan
./venv/bin/python -m cli.main scan

# Output as JSON
./venv/bin/python -m cli.main scan --json

# Save to file
./venv/bin/python -m cli.main scan -o report.json

# Quick score check
./venv/bin/python -m cli.main score

# Check specific category
./venv/bin/python -m cli.main check firewall
./venv/bin/python -m cli.main check security
```

---

## 📦 Installation Requirements

### For This Environment (Already Installed)
Everything is already set up:
- ✅ Python 3.12 with virtual environment
- ✅ All dependencies installed in `netaudit/venv`
- ✅ FastAPI server running on port 3031
- ✅ Next.js dashboard running on port 3000

### For a Fresh Linux System

```bash
# 1. Ensure Python 3.11+ is installed
python3 --version

# 2. Clone/copy the netaudit folder
cd netaudit

# 3. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Run CLI
python -m cli.main scan

# 6. Run API server (optional)
python -m api.main
```

### Dependencies (in requirements.txt)
```
fastapi>=0.109.0
uvicorn>=0.27.0
typer>=0.9.0
rich>=13.7.0
pydantic>=2.5.0
```

---

## ⚠️ Important Notes

1. **Linux Only** - This tool is designed for Linux systems only
2. **Root Access** - Some checks require `sudo` for complete results
3. **Read-Only** - The tool never modifies system configuration
4. **Localhost Binding** - API server binds to 127.0.0.1 only (secure by default)

---

## 📊 Current Scan Results

The system is actively scanning and showing:
- **Score: 85/100** (Grade B)
- **Critical Issues: 1** (No active firewall)
- **Warnings: 2** (fail2ban, nftables not installed)
- **Total Checks: 44**

The web dashboard in the Preview Panel shows all this data in real-time!
