# NetCheck-Py-Multi-threaded-Network-Port-Auditor


**NetCheck-Py** is a powerful, lightweight Python tool designed for local network discovery and security auditing. It combines **ARP scanning** (Layer 2) with **TCP port scanning** (Layer 4) to provide a comprehensive map of active devices and their exposed services.

Built with performance in mind, it utilizes Python's `ThreadPoolExecutor` for high-speed concurrent execution.

---

## Features

* **Active Host Discovery:** Uses ARP requests to identify devices in the local network (more reliable than ICMP/Ping).
* **Concurrent Scanning:** Multi-threaded architecture for both host discovery and port auditing.
* **Service Mapping:** Scans for common critical ports (SSH, HTTP, HTTPS, SMB, etc.).
* **OSI Layer Integration:** Demonstrates deep interaction between Data Link and Transport layers.
* **Clean CLI Interface:** Professional output formatting with real-time status updates.

---

## Technical Deep Dive

The tool operates in two distinct phases:

1. **ARP Discovery (Layer 2):** It crafts custom Ethernet frames and ARP requests using **Scapy**. By broadcasting these frames, it identifies MAC and IP addresses of active hosts without relying on ICMP, which is often blocked by firewalls.
2. **TCP Port Audit (Layer 4):** For every discovered host, it initiates a series of TCP connection attempts using `socket.connect_ex()`. This method is highly efficient as it returns an error code directly from the OS stack instead of raising exceptions.

---

## Installation & Requirements

### Prerequisites

* **Kali Linux** or any Linux distribution.
* **Python 3.x**
* **Scapy** library.

### Setup

```bash
# Clone the repository
git clone https://github.com/YourUsername/NetCheck-Py.git
cd NetCheck-Py

# Install dependencies
pip install scapy

```

---

## Usage

**Note:** Root privileges are required to craft raw network packets (ARP).

```bash
# Basic scan
sudo python3 net_auditor.py -t 192.168.1.0/24

# Aggressive scan with increased threads
sudo python3 net_auditor.py -t 10.0.0.0/24 -w 50

```

### Argument Flags:

* `-t`, `--target`: Target IP range (e.g., `192.168.1.0/24`).
* `-w`, `--workers`: Number of threads for the scanner (Default: 10).

---

## 📋 Sample Output

```text
[*] Audit avviato su: 192.168.1.0/24
[*] Scansione host e porte comuni in corso...
-----------------------------------------------------------------
IP Address      | MAC Address        | Open Ports
-----------------------------------------------------------------
192.168.1.1     | 00:aa:11:bb:22:cc  | 53, 80, 443
192.168.1.15    | 00:50:56:c0:00:08  | 22, 8080
-----------------------------------------------------------------

```

---

## ⚖️ Legal Disclaimer

This tool is for **educational and ethical security testing purposes only**. Unauthorized scanning of networks you do not own or have explicit permission to test is illegal and unethical. The author is not responsible for any misuse of this software.

---

## 👨‍💻 Author

**Francesco De Filippis**

* M.Sc. Student in Computer Engineering - Cybersecurity @ University of Calabria (UNICAL).
* Focus: Software Security, Network Defense, and Ethical Hacking.
