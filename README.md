# 🔒 Operational Technology (OT) Layer 7 DPI Firewall & Automated Telemetry Pipeline
## 📌 Project Overview
This repository contains a production-ready, localized **Deep Packet Inspection (DPI) Firewall** and an automated **Log Management/Analytics Pipeline** designed explicitly for critical infrastructure environments utilizing the **Modbus/TCP** industrial protocol. 
Unlike standard IT firewalls that operate exclusively at Layers 3 and 4, this solution operates at **Layer 7 (Application Layer)** using Python and Scapy. It dissects raw network payloads heading to Programmable Logic Controllers (PLCs) on port `502`, enforcing a Zero-Trust data policy by blocking unauthorized industrial control actions (Write commands) from modifying physical machinery states.
### Key Architecture Components
1. **`dpi_firewall.py`**: The real-time passive inline packet inspection engine.
2. **`parse_metrics.py`**: A chronological analytics analyzer grouping system blocks into hourly trends.
3. **`log_cleanup.sh`**: A defensive Bash management utility automating log file thresholds, compression, and persistent storage allocation.
---
## 📐 Pipeline Blueprint
     [ Network Traffic ]
             │
             ▼
     [ Scapy Sniffing Engine ] ──► (Port 502 Verification)
             │
             ▼
    [ Layer 7 Payload Decode ] ──► Extracts Modbus Function Codes
             │
     ┌───────┴────────────────────────┐
     ▼                                ▼
[ Policy Check 1 ]               [ Policy Check 2 ]
Is Source IP Trusted?            Is Command Read-Only?
 (e.g., 192.168.1.100)            (Blocks Write Codes 5, 6, 15, 16)
     │                                │
     ├────────────────────────────────┴───► [ ❌ POLICY CRITICAL VIOLATION ]
     ▼                                                │
[ ✅ ALLOWED PASSIVE TRAFFIC ]                        ▼
                                      Writes to /logs/dpi_firewall_violations.log
                                                      │
                                   ┌──────────────────┴──────────────────┐
                                   ▼                                     ▼
                      [ parse_metrics.py Engine ]            [ log_cleanup.sh Cron ]
                      Aggregates Blocks hourly              Rotates/Compresses if >10MB

---
## 🛠️ Technical Features & Stack
* **Language:** Python 3.13+
* **Libraries:** Scapy, Logging, Datetime, Collections
* **Automation:** Bash scripting, Linux/macOS `crontab` utilities
* **Protocols Decoded:** TCP/IP (IPv4), Modbus/TCP (Industrial ICS)
---
## 💻 Script Reference & Usage
### 1. The Core Firewall (`dpi_firewall.py`)
This script tracks the network interfaces, targets industrial network traffic bound for port `502`, and evaluates both the sender identity and payload safety definitions. It dynamically provisions directory storage upon initiation.
```bash
# Execute with administrative privileges to enable raw interface sniffing
sudo python3 dpi_firewall.py
```
### 2. The Analytical Engine (`parse_metrics.py`)
Reads the system log stream in a thread-safe, read-only mode, extracts security blocks using targeted string markers, strips out microsecond differentials, and charts chronological hourly block counters.
```bash
python3 parse_metrics.py
```
**Sample Output:**
```text
[*] Parsing log file: /Users/rodolfoaguilar/Documents/Projects/otcybersecurity/logs/dpi_firewall_violations.log
===========================================================
[📊 METRICS SUMMARY] Total Incidents Deflected: 47
-----------------------------------------------------------
Hour Window          | Total Blocks Checked
-----------------------------------------------------------
2026-08-31 19:00     | 12 blocks
2026-08-31 20:00     | 35 blocks
```
### 3. Automated Archiving (`log_cleanup.sh`)
An automated safety baseline utility. It monitors log growth via `du` metrics. If the log breaches a strict **10MB (10240KB) threshold**, it compresses the raw log into a timestamped `.gz` file inside the archive path, then flushes the active log using the safe descriptor reset syntax (`cat /dev/null > log_file`) to keep the primary Python daemon stream uninterrupted.
```bash
# Set file authorization flags
chmod +x log_cleanup.sh
# Execute a trial loop run
./log_cleanup.sh
```
---
## ⏰ Cron Automation Configuration
To implement autonomous operations, embed both scripts directly inside your user `crontab` file:
```bash
crontab -e
```
Add these production directives at the bottom of the table file:
```cron
# Run the analytical report daily at 11:30 PM
30 23 * * * /opt/homebrew/bin/python3 /Users/rodolfoaguilar/Documents/Projects/otcybersecurity/parse_metrics.py >> /Users/rodolfoaguilar/Documents/Projects/otcybersecurity/logs/daily_report_generation.log 2>&1
# Run the size checking and archiving script every night at midnight
0 0 * * * /bin/bash /Users/rodolfoaguilar/Documents/Projects/otcybersecurity/log_cleanup.sh >> /Users/rodolfoaguilar/Documents/Projects/otcybersecurity/logs/cleanup_execution.log 2>&1
```
---
## 🚀 Simulated Forensic Testing
To evaluate your setup without setting up a live physical industrial network environment, execute these terminal injection test commands:
1. **Simulate a Malicious Override Packet Attempt (Write Command):**
   ```python
   from scapy.all import IP, TCP, send
   # Crafts an explicit TCP payload embedding Modbus Function Code 6 (Write Single Register)
   attack_pkt = IP(src="192.168.1.100", dst="192.168.1.50")/TCP(dport=502)/b'\x00\x00\x00\x00\x00\x00\x01\x06'
   send(attack_pkt)
   ```
2. **Artificially Force a Log Rotate & Compression Threshold:**
   ```bash
   dd if=/dev/zero bs=1024 count=15000 >> ~/Documents/Projects/otcybersecurity/logs/dpi_firewall_violations.log
   ./log_cleanup.sh
   ```
