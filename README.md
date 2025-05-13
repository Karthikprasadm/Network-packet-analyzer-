# Network Packet Analyzer

A powerful, cross-platform network packet analyzer with advanced protocol analysis, security monitoring, visualization, machine learning-based anomaly detection, REST API, packet capture/replay, and real-time alerting.

## Features
- Real-time packet capture and analysis
  - TCP, UDP, ICMP, DNS, HTTP, FTP, SMTP, POP3, SSL/TLS protocols
  - Detailed packet inspection and header analysis
  - Connection tracking and state monitoring
- Security monitoring and threat detection
  - DDoS attack detection
  - Port scanning detection
  - Suspicious IP monitoring
  - Machine learning-based anomaly detection (Isolation Forest)
  - Real-time security alerts
- Advanced protocol analysis
  - TCP flags and connection states
  - Protocol-specific analysis and statistics
  - Deep packet inspection
- Network visualization and monitoring
  - Real-time traffic visualization
  - Network topology mapping
  - Bandwidth and latency monitoring
  - Performance metrics tracking
- REST API capabilities
  - Live statistics and metrics
  - Security alerts and notifications
  - Network topology information
  - Control endpoints for analysis
- Additional features
  - Packet capture and replay (PCAP format)
  - Comprehensive report generation (PDF, HTML, JSON)
  - Real-time email alert notifications
  - Performance metrics export (CSV)
  - Cross-platform support (Windows, Linux, macOS)

## Requirements
- Python 3.8 or higher
- Required Python packages (see requirements.txt):
  - scapy==2.5.0
  - colorama==0.4.6
  - python-dateutil==2.8.2
  - scapy-http==1.8.2
  - matplotlib==3.7.1
  - networkx==3.1
  - dnspython==2.4.2
  - reportlab==4.0.4
  - jinja2==3.1.2
  - requests==2.31.0
  - python-whois==0.8.0
  - pyOpenSSL==23.2.0
  - flask
  - numpy==1.26.4
  - scikit-learn

## Quick Start
1. Clone the repository
2. Create a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the application:
   ```bash
   python packet_analyzer.py
   ```

For detailed setup and usage instructions, see [how_to_run.md](how_to_run.md).

## Project Structure
- `packet_analyzer.py`: Main application file
- `protocol_analyzer.py`: Protocol analysis implementation
- `security_monitor.py`: Security monitoring and threat detection
- `report_generator.py`: Report generation functionality
- `templates/`: Web interface templates
- `packet_log.txt`: Packet capture logs
- `packet_log.csv`: Performance metrics export

## License
MIT 