#!/usr/bin/env python3

import time
from collections import defaultdict
import requests
import whois
from datetime import datetime, timedelta

class SecurityMonitor:
    def __init__(self):
        self.suspicious_ips = set()
        self.port_scan_threshold = 10  # Number of ports to trigger port scan alert
        self.ddos_threshold = 1000  # Packets per second to trigger DDoS alert
        self.anomaly_threshold = 1500  # Bytes to trigger size anomaly
        self.rate_limit = 100  # Packets per second per IP
        self.ip_stats = defaultdict(lambda: {
            'packet_count': 0,
            'last_reset': time.time(),
            'ports_accessed': set(),
            'total_bytes': 0,
            'last_packet_time': time.time()
        })
        self.alerts = []
        self.malicious_ip_cache = {}
        self.malicious_ip_cache_timeout = 3600  # 1 hour

    def check_malicious_ip(self, ip):
        """Check if an IP is known to be malicious."""
        current_time = time.time()
        
        # Check cache first
        if ip in self.malicious_ip_cache:
            cache_time, is_malicious = self.malicious_ip_cache[ip]
            if current_time - cache_time < self.malicious_ip_cache_timeout:
                return is_malicious

        try:
            # Check VirusTotal API (you need to add your API key)
            # response = requests.get(f'https://www.virustotal.com/vtapi/v2/ip-address/report',
            #                        params={'apikey': 'YOUR_API_KEY', 'ip': ip})
            # is_malicious = response.json().get('positives', 0) > 0

            # For now, using a simple whois check
            w = whois.whois(ip)
            is_malicious = False  # Implement your own logic here
            
            # Cache the result
            self.malicious_ip_cache[ip] = (current_time, is_malicious)
            return is_malicious
        except Exception:
            return False

    def detect_port_scan(self, ip, port):
        """Detect potential port scanning activity."""
        stats = self.ip_stats[ip]
        stats['ports_accessed'].add(port)
        
        if len(stats['ports_accessed']) > self.port_scan_threshold:
            self.add_alert(f"Potential port scan detected from {ip}")
            return True
        return False

    def detect_ddos(self, ip):
        """Detect potential DDoS attacks."""
        stats = self.ip_stats[ip]
        current_time = time.time()
        time_diff = current_time - stats['last_reset']
        
        if time_diff >= 1.0:  # Check every second
            rate = stats['packet_count'] / time_diff
            if rate > self.ddos_threshold:
                self.add_alert(f"Potential DDoS attack detected from {ip}")
                return True
            stats['packet_count'] = 0
            stats['last_reset'] = current_time
        return False

    def detect_size_anomaly(self, ip, packet_size):
        """Detect anomalous packet sizes."""
        stats = self.ip_stats[ip]
        if packet_size > self.anomaly_threshold:
            self.add_alert(f"Anomalous packet size ({packet_size} bytes) from {ip}")
            return True
        return False

    def check_rate_limit(self, ip):
        """Check if an IP is exceeding rate limits."""
        stats = self.ip_stats[ip]
        current_time = time.time()
        time_diff = current_time - stats['last_packet_time']
        
        if time_diff < 1.0:  # Within 1 second
            stats['packet_count'] += 1
            if stats['packet_count'] > self.rate_limit:
                self.add_alert(f"Rate limit exceeded by {ip}")
                return True
        else:
            stats['packet_count'] = 1
            stats['last_packet_time'] = current_time
        return False

    def add_alert(self, message):
        """Add a security alert."""
        timestamp = datetime.now().isoformat()
        self.alerts.append({
            'timestamp': timestamp,
            'message': message
        })

    def get_alerts(self):
        """Get all security alerts."""
        return self.alerts

    def clear_alerts(self):
        """Clear all security alerts."""
        self.alerts = []

    def update_stats(self, ip, packet_size):
        """Update statistics for an IP address."""
        stats = self.ip_stats[ip]
        stats['packet_count'] += 1
        stats['total_bytes'] += packet_size
        stats['last_packet_time'] = time.time()

    def get_ip_stats(self):
        """Get statistics for all IP addresses."""
        return dict(self.ip_stats) 