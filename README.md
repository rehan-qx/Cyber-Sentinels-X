# 🚀 Sentinel-X | Elite Network Security Framework

**Sentinel-X** is a Command & Control C2 with high-performance, automated network exploitation and OSINT framework. It seamlessly orchestrates professional-grade tools like **Bettercap**, **Mitmproxy**, and **Scapy** to perform stealthy interception, SSL stripping, and deep packet analysis through a single, unified Command-Line Interface (CLI).

---

## 🛡️ Key Modules

| Module | Functionality | Core Engine |
| --- | --- | --- |
| **OSINT Tracker** | Global username search across 60+ platforms. | Requests / Threading |
| **MITM Elite** | Automated ARP Spoofing & Transparent Proxying. | Bettercap + Mitmproxy |
| **Network Discovery** | Real-time ARP mapping & Target Identification. | Scapy |
| **Web Recon** | Fingerprinting, SSL Check, & AI-driven Analysis. | Gemini AI + Requests |
| **Port Scanner** | High-speed multi-threaded TCP port discovery (1-65535). | Socket / ThreadPool |
| **System Monitor** | Host Integrity Audit & Forensic Sanitization. | Windows Kernel API |

---

## 📸 MITM Workflow

Sentinel-X simplifies complex network attacks into an automated 4-step sequence:

1. **Intelligence**: Auto-scans the LAN to identify active hosts and their MAC addresses.
2. **Diversion**: Manipulates ARP tables and sets up cross-platform NAT rules (iptables/netsh) for transparent routing.
3. **Capture**: Initiates the Mitmproxy engine to intercept and modify high-level HTTP/S traffic.
4. **Exfiltration**: Automatically archives logs and raw flows into the `sentinel_vault/`.

---

## ✨ Advanced Features

* **AI-Powered Recon**: Integrated with **Google Gemini** to provide real-time security verdicts on target headers and configurations.
* **Safe-Audio Engine**: Intelligent audio detection that automatically bridges WSL2/Linux audio or silences itself if no hardware is found, preventing system crashes.
* **SSLStrip Integration**: Automatically attempts to downgrade HTTPS connections to intercept plaintext data.
* **Cross-Platform Defense**: A dedicated **System Monitor** module for Windows that audits kernel integrity and wipes forensic tracks.
* **Self-Healing Cleanup**: Automatically flushes networking tables and restores IP forwarding on exit to prevent network downtime.

---

## ⚙️ Quick Start

### 1. Prerequisites

Sentinel-X is optimized for **Kali Linux**, **WSL2**, and **Windows**. Ensure you have the following engines installed:

```bash
# For Kali Linux / Ubuntu
sudo apt update && sudo apt install bettercap mitmproxy iptables libasound2-plugins -y

```

### 2. Installation

Clone the repository and install the dependencies. The framework includes a specialized fix for Windows-to-Linux line endings:

```bash
git clone [https://github.com/rehan-qx/Cyber-Sentinels-X](https://github.com/rehan-qx/Cyber-Sentinels-X)
cd sentinel-x
pip install -r requirements.txt
bash install.sh
sed -i 's/\r$//' main.py 

```

### 3. Execution

Launch the framework with root privileges (required for network socket manipulation and ARP spoofing):

```bash
sudo python3 main.py

```

---

## 📂 Project Structure

```text
Sentinel-X/
├── main.py            # Framework Kernel & Menu System
├── recon.py           # AI-Enhanced Web Intelligence Module
├── moniter.py         # Windows Integrity & Defense Module
├── sentinel_vault/    # Captured Data & Session Logs
├── System_Check/      # System Audit Reports
└── requirements.txt   # Python Dependencies

```

---

## ⚠️ Legal Disclaimer

**For Educational Use Only.** Sentinel-X is designed for authorized penetration testing and security auditing. The developer is not responsible for any unauthorized use, illegal activities, or damage caused by this tool. Use this framework ethically and always obtain written permission before testing any network or system.
