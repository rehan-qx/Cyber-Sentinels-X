# 🚀 Sentinel-X | Elite Network Security Framework

Sentinel-X is a high-performance, automated network exploitation and OSINT framework. It seamlessly orchestrates Bettercap and Mitmproxy to perform stealthy interception, SSL stripping, and deep packet analysis through a single command-line interface.

## 🛡️ Key Modules
Module	Functionality	Core Engine
OSINT Tracker	Global username search across 60+ platforms.	Requests / Threading
MITM Elite	Automated ARP Spoofing & Transparent Proxying.	Bettercap + Mitmproxy
Network Discovery	Real-time ARP mapping & Target Identification.	Scapy
Web Recon	Fingerprinting, SSL Check, & Directory Brute-forcing.	HTTP Probes
Port Scanner	High-speed multi-threaded TCP port discovery.	Socket
📸 MITM Workflow

Sentinel-X simplifies complex network attacks into an automated 4-step sequence:

    Intelligence: Auto-scans the LAN to identify active hosts and their MAC addresses.

    Diversion: Manipulates ARP tables and sets up iptables NAT rules for transparent routing.

    Capture: Initiates the Mitmproxy engine to intercept high-level HTTP/S traffic.

    Exfiltration: Automatically archives logs and raw flows into the sentinel_vault/.

# ✨ Advanced Features

    SSLStrip Integration: Automatically attempts to downgrade HTTPS connections to intercept plaintext data.

    OS Fingerprinting: Analyzes TTL values to identify if the target is running Windows, Linux, or Android.

    Self-Healing Cleanup: Automatically flushes iptables and restores IP forwarding on exit to prevent target network downtime.

    Visual Dashboard: Real-time attack monitoring with custom color-coded status indicators.

# ⚙️ Quick Start
### 1. Prerequisites

Ensure you are using Kali Linux, Parrot OS, or any Debian-based system.

```sudo apt update && sudo apt install bettercap mitmproxy iptables python3-pip -y```

### 2. Installation

Clone the repository and install the Python dependencies:

`git clone https://github.com/yourusername/sentinel-x.git && cd sentinel-x && pip install -r requirements.txt`

### 3. Execution

Launch the framework with root privileges (required for network socket manipulation):

```sudo python3 main.py```

## 📂 Project Structure

Sentinel-X/
├── main.py             
├── sentinel_vault/     
├── requirements.txt   
└── README.md    

# ⚠️ Legal Disclaimer

For Educational Use Only. Sentinel-X is designed for authorized penetration testing and security auditing. The developer is not responsible for any unauthorized use or damage. Use this tool ethically and always obtain permission before testing.
