# NMD — Network Monitoring Dashboard

A desktop network monitoring and authorized vulnerability assessment application built with Python, CustomTkinter, Nmap, SQLite/SQLAlchemy, and ReportLab.

---

## 🛡️ Vulnerability Scan Feature

NMD includes a dedicated **Vulnerability Scan** mode that performs authorized security assessments against hosts or subnets using Nmap NSE vulnerability scripts (`--script vuln`).

### Key Capabilities

- **Safe Detection**: Executes non-exploitative Nmap NSE vulnerability detection (`-sV --script vuln`).
- **Structured XML Parsing**: Parses structured Nmap XML output to extract hosts, open ports, services, CVE identifiers, titles, and evidence.
- **Normalized Severities**: Normalizes findings into `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, or `UNKNOWN` based strictly on CVSS scores or explicit script output (never guessing or inventing scores/CVEs).
- **SQLite Database Persistence**: Stores vulnerability findings in the `vulnerabilities` table without breaking existing device or scan history data.
- **Multi-Format Reporting**: Generates clean ASCII TXT reports and professional ReportLab PDF assessment reports.
- **Scheduler & Alert Engine Integration**: Supports automated background vulnerability scans and triggers `NEW_VULNERABILITY_DETECTED` alerts.

---

## 📋 Requirements & Installation

1. **Python 3.10+** (Python 3.13 / 3.14 compatible)
2. **Nmap Binary**: Ensure Nmap is installed on the host operating system:
   - **Windows**: Download from [nmap.org](https://nmap.org/download.html) or install via `winget install Nmap.Nmap`.
   - **Linux**: `sudo apt-get install nmap`

### Setup Virtual Environment

```bash
# 1. Create virtual environment
python -m venv .venv

# 2. Activate virtual environment
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# Linux/macOS:
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Running NMD & Launching Scans

### Launch Application GUI

```bash
python main.py
```

### Running Vulnerability Scans via GUI

1. Open NMD GUI and navigate to **Vulnerability scan** in the sidebar.
2. Enter the target IP or subnet CIDR (e.g. `192.168.1.10` or `192.168.1.0/24`).
3. Click **Start Vulnerability Scan**.
4. View real-time results, severity breakdown, and findings table.
5. Click **Export TXT Report** or **Export PDF Report** to generate assessment reports.

---

## 📊 Severity Classification Matrix

| Severity Level | CVSS Score Range | Description |
|---|---|---|
| **CRITICAL** | `9.0 - 10.0` | Severe vulnerabilities allowing unauthenticated RCE or total host compromise. |
| **HIGH** | `7.0 - 8.9` | High impact vulnerabilities affecting confidentiality, integrity, or availability. |
| **MEDIUM** | `4.0 - 6.9` | Moderate security issues requiring specific conditions or configuration flaws. |
| **LOW** | `0.1 - 3.9` | Minor security risks or informational exposure. |
| **INFO** | `0.0` | Informational security checks or service disclosures. |
| **UNKNOWN** | `None` | Findings where CVSS or explicit risk rating is omitted by Nmap. |

---

## ⚠️ Safety, Limitations, & Disclaimer

> [!IMPORTANT]
> **Authorization Disclaimer**: Only scan systems and networks that you own or are explicitly authorized to assess. Unauthorized scanning may violate computer misuse laws.

- **Non-Exploitative**: This scanner performs **detection and reporting only**. It does NOT execute exploits, deliver payloads, perform brute force, or establish persistence.
- **Nmap NSE Scope**: Nmap vulnerability scripts provide targeted service checks. Absence of findings does NOT guarantee that a system is 100% secure.
