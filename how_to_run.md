# How to Run the Network Packet Analyzer

This guide explains how to set up and run the Network Packet Analyzer on Windows, Linux, and macOS, including installing dependencies and required drivers.

---

## 1. Prerequisites
- **Python 3.7+** (recommended: latest 3.x)
- **pip** (Python package manager)
- **Npcap** (Windows) or **libpcap** (Linux/macOS)
- **Administrator/root privileges** (required for packet capture)

---

## 2. Clone the Repository
```bash
git clone <repo-url>
cd <repo-directory>
```

---

## 3. Install Python Dependencies
```bash
pip install -r requirements.txt
```

---

## 4. Install Packet Capture Driver

### Windows
- Download and install **Npcap** from: [https://nmap.org/npcap/](https://nmap.org/npcap/)
- During installation, check "Install Npcap in WinPcap API-compatible Mode"
- Restart your terminal after installation

### Linux (Debian/Ubuntu)
```bash
sudo apt update
sudo apt install libpcap-dev
```

### macOS
- Install Xcode Command Line Tools (if not already):
```bash
xcode-select --install
```
- Install libpcap (if needed):
```bash
brew install libpcap
```

---

## 5. List Available Network Interfaces
To see available interfaces (required for the `-i` option):
```bash
python -c "from scapy.all import get_if_list; print('\n'.join(get_if_list()))"
```

---

## 6. Run the Packet Analyzer

### Basic Usage
```bash
python packet_analyzer.py -i <interface>
```

### Example (Windows Loopback)
```bash
python packet_analyzer.py -i "\\Device\\NPF_Loopback"
```

### Example (Linux)
```bash
sudo python3 packet_analyzer.py -i eth0
```

### Example (macOS)
```bash
sudo python3 packet_analyzer.py -i en0
```

---

## 7. Common Options
- `--protocol TCP` : Filter by protocol (TCP, UDP, ICMP)
- `--show-payload` : Display packet payloads
- `--log-file mylog.csv` : Specify custom log file
- `--ip-range 192.168.1.0/24` : Filter by IP range
- `--port-range 80-443` : Filter by port range
- `--bpf "tcp port 80"` : Custom BPF filter
- `--save-pcap mycapture.pcap` : Save captured packets to PCAP
- `--replay mycapture.pcap` : Replay packets from PCAP
- `--email-alerts ...` : Enable and configure email alerts (see below)

---

## 8. Advanced Features

### REST API
- The analyzer starts a REST API server on port 5000.
- Example endpoints:
  - `/stats` : Real-time statistics
  - `/alerts` : Security alerts
  - `/protocols` : Protocol distribution
  - `/topology` : Network topology map
  - `/anomalies` : Anomaly detection results

### Email Alerts
To enable email alerts:
```bash
python packet_analyzer.py -i <interface> --email-alerts \
  --smtp-server smtp.gmail.com --smtp-port 587 \
  --email-from your@email.com --email-to recipient@email.com \
  --email-username your_username --email-password your_password
```

---

## 9. Notes
- **Run as administrator/root** for packet capture.
- **Windows users:** If you see interface names like `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`, use them as-is with the `-i` option.
- **Linux/macOS users:** Use interface names like `eth0`, `wlan0`, or `en0`.
- **Npcap/libpcap is required** for packet capture.
- **All dependencies** are listed in `requirements.txt`.

---

## 10. Troubleshooting
- If you get `ModuleNotFoundError`, ensure all dependencies are installed:
  ```bash
  pip install -r requirements.txt
  ```
- If you get permission errors, run as administrator/root.
- For Npcap issues, reinstall from the official site and restart your terminal.

---

## 11. License
MIT 