# CRYPTSK NetAudit

**Linux Network Infrastructure Audit Tool**

A production-ready security audit tool for Linux systems that scans system configuration and produces structured risk analysis reports.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Overview

CRYPTSK NetAudit performs comprehensive security audits of Linux systems, analyzing kernel parameters, firewall configuration, network settings, and security configurations. The tool generates detailed reports with actionable recommendations.

**Key Features:**
- Read-only scanning (no system modifications)
- Safe subprocess execution
- Localhost-only API binding
- Modular, extensible architecture

---

## System Requirements

- **Operating System:** Linux only
- **Python:** 3.11 or higher
- **Privileges:** Root/sudo recommended for complete audit

---

## Installation

```bash
# Clone or download the repository
cd netaudit

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Command Line Interface

```bash
# Run full security audit
python -m cli.main scan

# Output as JSON
python -m cli.main scan --json

# Save report to file
python -m cli.main scan -o report.json

# Quick score check
python -m cli.main score

# Check specific category
python -m cli.main check firewall
python -m cli.main check security
python -m cli.main check network
python -m cli.main check sysctl
```

### Web Dashboard

```bash
# Start the API server
python -m api.main

# Server runs at: http://localhost:3031
# API documentation: http://localhost:3031/docs
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scan` | GET | Run full audit scan |
| `/api/score` | GET | Quick security score |
| `/api/categories` | GET | Category breakdown |
| `/api/findings` | GET | Detailed findings |
| `/api/recommendations` | GET | Prioritized recommendations |
| `/api/export/json` | GET | Download JSON report |
| `/api/scan/clear-cache` | POST | Clear scan cache |

---

## Audit Categories

### 1. Kernel / Sysctl
- IP forwarding status
- Connection tracking limits
- TCP buffer configurations
- SYN flood protection
- Source routing settings

### 2. Firewall
- nftables/iptables installation
- Default policy analysis
- INPUT chain permissiveness
- UFW status

### 3. Networking
- MTU consistency
- NIC offloading status
- IRQ balance service
- Promiscuous mode detection
- Listening ports analysis

### 4. Security
- SSH root login configuration
- Password authentication
- Fail2ban status
- Password policy enforcement
- World-writable files

---

## Scoring System

### Score Calculation

- **Base Score:** 100 points
- **Critical Issue:** -25 points
- **Failed Check:** -10 points
- **Warning:** -5 points

### Category Weights

| Category | Weight |
|----------|--------|
| Firewall | 30% |
| Security | 30% |
| Sysctl | 25% |
| Network | 15% |

### Grade Scale

| Score | Grade | Status |
|-------|-------|--------|
| 90-100 | A | Excellent |
| 80-89 | B | Good |
| 70-79 | C | Fair |
| 60-69 | D | Poor |
| 0-59 | F | Critical |

---

## Project Structure

```
netaudit/
├── core/
│   ├── collectors.py      # System data collection
│   ├── sysctl_checks.py   # Kernel parameter checks
│   ├── firewall_checks.py # Firewall checks
│   ├── network_checks.py  # Network checks
│   ├── security_checks.py # Security checks
│   └── scoring_engine.py  # Score calculation
├── cli/
│   └── main.py            # CLI entry point
├── api/
│   └── main.py            # FastAPI server
├── requirements.txt
├── setup.py
└── README.md
```

---

## Security Features

- **Read-only operations** - No configuration modifications
- **Safe subprocess execution** - No `shell=True` usage
- **Input sanitization** - All inputs validated
- **Localhost binding** - API only accessible locally
- **No privilege escalation** - Runs with current user permissions

---

## Example Output

### CLI Output

```
============================================================
  CRYPTSK NetAudit - Security Audit Report
============================================================

Timestamp: 2024-01-15T10:30:00Z
Hostname:  server01

----------------------------------------
  OVERALL SECURITY SCORE
----------------------------------------
  Score: 85/100
  Grade: B

----------------------------------------
  RISK BREAKDOWN
----------------------------------------
  Critical Issues: 1
  Warnings:        2
  Info:            34
  Passed:          4

----------------------------------------
  CRITICAL ISSUES
----------------------------------------
  [!] firewall_active
      No active firewall detected

----------------------------------------
  TOP RECOMMENDATIONS
----------------------------------------
  1. [WARNING] Install fail2ban for brute-force protection

============================================================
  Audit completed successfully
============================================================
```

### JSON Output

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "hostname": "server01",
  "overall_score": 85,
  "grade": "B",
  "categories": {
    "sysctl": {"score": 100, "critical_issues": 0},
    "firewall": {"score": 60, "critical_issues": 1},
    "network": {"score": 90, "critical_issues": 0},
    "security": {"score": 95, "critical_issues": 0}
  },
  "summary": {
    "total_checks": 44,
    "passed": 4,
    "failed": 2,
    "warnings": 4
  }
}
```

---

## Development

```bash
# Run linting
ruff check netaudit/

# Format code
black netaudit/

# Run tests
python -m pytest tests/
```

---

## License

MIT License

---

## Disclaimer

This tool is provided for security auditing purposes only. Always review recommendations before applying changes to production systems.

**CRYPTSK NetAudit** - Professional Linux Security Auditing
