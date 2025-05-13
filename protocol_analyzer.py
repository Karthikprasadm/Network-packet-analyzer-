#!/usr/bin/env python3

from scapy.all import *
from collections import defaultdict
import time

class ProtocolAnalyzer:
    def __init__(self):
        """Initialize protocol analyzer with data structures for different protocols."""
        self.dns_queries = []
        self.ftp_sessions = []
        self.smtp_sessions = []
        self.pop3_sessions = []
        self.ssl_sessions = []
        self.protocol_stats = defaultdict(int)

    def analyze_dns(self, packet):
        """Analyze DNS packets and extract query information."""
        if DNS in packet:
            timestamp = time.time()
            if DNSQR in packet:
                query = {
                    'timestamp': timestamp,
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'query_name': packet[DNSQR].qname.decode('utf-8', errors='ignore'),
                    'query_type': packet[DNSQR].qtype
                }
                self.dns_queries.append(query)
                self.protocol_stats['DNS'] += 1

    def analyze_ftp(self, packet):
        """Analyze FTP traffic and extract command information."""
        if FTP in packet:
            timestamp = time.time()
            if Raw in packet:
                raw_load = packet[Raw].load.decode('utf-8', errors='ignore')
                if raw_load.startswith(('USER', 'PASS', 'RETR', 'STOR', 'LIST')):
                    session = {
                        'timestamp': timestamp,
                        'src_ip': packet[IP].src,
                        'dst_ip': packet[IP].dst,
                        'command': raw_load.split()[0],
                        'argument': ' '.join(raw_load.split()[1:]) if len(raw_load.split()) > 1 else None
                    }
                    self.ftp_sessions.append(session)
                    self.protocol_stats['FTP'] += 1

    def analyze_smtp(self, packet):
        """Analyze SMTP traffic and extract email information."""
        if SMTP in packet:
            timestamp = time.time()
            if Raw in packet:
                raw_load = packet[Raw].load.decode('utf-8', errors='ignore')
                if any(cmd in raw_load for cmd in ['MAIL FROM:', 'RCPT TO:', 'DATA']):
                    session = {
                        'timestamp': timestamp,
                        'src_ip': packet[IP].src,
                        'dst_ip': packet[IP].dst,
                        'command': raw_load.split()[0] if raw_load.split() else None,
                        'data': raw_load
                    }
                    self.smtp_sessions.append(session)
                    self.protocol_stats['SMTP'] += 1

    def analyze_pop3(self, packet):
        """Analyze POP3 traffic and extract command information."""
        if POP3 in packet:
            timestamp = time.time()
            if Raw in packet:
                raw_load = packet[Raw].load.decode('utf-8', errors='ignore')
                if any(cmd in raw_load for cmd in ['USER', 'PASS', 'RETR', 'DELE', 'QUIT']):
                    session = {
                        'timestamp': timestamp,
                        'src_ip': packet[IP].src,
                        'dst_ip': packet[IP].dst,
                        'command': raw_load.split()[0] if raw_load.split() else None,
                        'argument': ' '.join(raw_load.split()[1:]) if len(raw_load.split()) > 1 else None
                    }
                    self.pop3_sessions.append(session)
                    self.protocol_stats['POP3'] += 1

    def analyze_ssl(self, packet):
        """Analyze SSL/TLS traffic and extract connection information."""
        if packet.haslayer('SSL') or packet.haslayer('TLS'):
            timestamp = time.time()
            session = {
                'timestamp': timestamp,
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'version': packet['SSL'].version if 'SSL' in packet else packet['TLS'].version,
                'cipher_suite': packet['SSL'].cipher_suite if 'SSL' in packet else packet['TLS'].cipher_suite
            }
            self.ssl_sessions.append(session)
            self.protocol_stats['SSL/TLS'] += 1

    def get_dns_queries(self):
        """Get all DNS queries."""
        return self.dns_queries

    def get_ftp_sessions(self):
        """Get all FTP sessions."""
        return self.ftp_sessions

    def get_smtp_sessions(self):
        """Get all SMTP sessions."""
        return self.smtp_sessions

    def get_pop3_sessions(self):
        """Get all POP3 sessions."""
        return self.pop3_sessions

    def get_ssl_sessions(self):
        """Get all SSL/TLS sessions."""
        return self.ssl_sessions

    def get_protocol_stats(self):
        """Get statistics for all protocols."""
        return dict(self.protocol_stats) 