#!/usr/bin/env python3

import sys
import logging
from datetime import datetime
from scapy.all import *
from scapy.layers import http
from colorama import init, Fore, Style
import argparse
import binascii
import re
import matplotlib.pyplot as plt
import networkx as nx
from collections import defaultdict
import threading
import time
from matplotlib.animation import FuncAnimation
import statistics
from queue import Queue
import threading
import ipaddress
from security_monitor import SecurityMonitor
from protocol_analyzer import ProtocolAnalyzer
from report_generator import ReportGenerator
import json
import numpy as np
import os
from flask import Flask, jsonify, request
import threading
import smtplib
from email.mime.text import MIMEText
from concurrent.futures import ThreadPoolExecutor
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')  # Suppress sklearn warnings

# Initialize colorama
init()

# Configure logging
logging.basicConfig(
    filename='packet_log.txt',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

# Initialize Flask app
app = Flask(__name__)

class PerformanceMetrics:
    def __init__(self):
        self.bandwidth = {
            'timestamps': [],
            'bytes_per_sec': [],
            'total_bytes': 0
        }
        self.packet_rates = {
            'timestamps': [],
            'packets_per_sec': [],
            'last_count': 0,
            'last_time': time.time()
        }
        self.latencies = defaultdict(list)
        self.connections = {
            'active': set(),
            'total': 0,
            'established': 0,
            'closed': 0
        }
        self.tcp_states = defaultdict(int)
        self.connection_times = defaultdict(list)

    def update_bandwidth(self, packet_size):
        """Update bandwidth statistics."""
        current_time = time.time()
        self.bandwidth['total_bytes'] += packet_size
        self.bandwidth['timestamps'].append(current_time)
        self.bandwidth['bytes_per_sec'].append(packet_size)

    def update_packet_rate(self):
        """Update packet rate statistics."""
        current_time = time.time()
        time_diff = current_time - self.packet_rates['last_time']
        if time_diff >= 1.0:  # Update every second
            packets_diff = self.packet_count - self.packet_rates['last_count']
            rate = packets_diff / time_diff
            self.packet_rates['timestamps'].append(current_time)
            self.packet_rates['packets_per_sec'].append(rate)
            self.packet_rates['last_count'] = self.packet_count
            self.packet_rates['last_time'] = current_time

    def update_latency(self, src_ip, dst_ip, timestamp):
        """Update latency measurements for a connection."""
        key = tuple(sorted([src_ip, dst_ip]))
        self.latencies[key].append(timestamp)
        if len(self.latencies[key]) >= 2:
            latency = self.latencies[key][-1] - self.latencies[key][-2]
            self.connection_times[key].append(latency)

    def update_connection(self, src_ip, dst_ip, tcp_flags=None):
        """Update connection tracking statistics."""
        connection = tuple(sorted([src_ip, dst_ip]))
        if connection not in self.connections['active']:
            self.connections['active'].add(connection)
            self.connections['total'] += 1
            if tcp_flags and tcp_flags & 0x02:  # SYN flag
                self.connections['established'] += 1
                self.tcp_states['SYN'] += 1
            elif tcp_flags and tcp_flags & 0x04:  # RST flag
                self.connections['closed'] += 1
                self.tcp_states['RST'] += 1
            elif tcp_flags and tcp_flags & 0x01:  # FIN flag
                self.connections['closed'] += 1
                self.tcp_states['FIN'] += 1

    def get_statistics(self):
        """Get current performance statistics."""
        stats = {
            'bandwidth': {
                'current': self.bandwidth['bytes_per_sec'][-1] if self.bandwidth['bytes_per_sec'] else 0,
                'average': statistics.mean(self.bandwidth['bytes_per_sec']) if self.bandwidth['bytes_per_sec'] else 0,
                'total': self.bandwidth['total_bytes']
            },
            'packet_rate': {
                'current': self.packet_rates['packets_per_sec'][-1] if self.packet_rates['packets_per_sec'] else 0,
                'average': statistics.mean(self.packet_rates['packets_per_sec']) if self.packet_rates['packets_per_sec'] else 0
            },
            'latency': {
                'average': statistics.mean([statistics.mean(times) for times in self.connection_times.values()]) if self.connection_times else 0,
                'min': min([min(times) for times in self.connection_times.values()]) if self.connection_times else 0,
                'max': max([max(times) for times in self.connection_times.values()]) if self.connection_times else 0
            },
            'connections': {
                'active': len(self.connections['active']),
                'total': self.connections['total'],
                'established': self.connections['established'],
                'closed': self.connections['closed']
            }
        }
        return stats

class PacketAnalyzer:
    def __init__(self, protocol_filter=None, show_payload=False, log_file='packet_log.csv',
                 ip_range=None, port_range=None, bpf_filter=None):
        self.packet_count = 0
        self.protocol_filter = protocol_filter
        self.show_payload = show_payload
        self.log_file = log_file
        self.ip_range = ip_range
        self.port_range = port_range
        self.bpf_filter = bpf_filter
        
        # Packet capture storage
        self.captured_packets = []
        self.capture_file = 'captured_packets.pcap'
        self.max_captured_packets = 10000  # Limit to prevent memory issues
        
        # Statistics for visualization
        self.protocol_stats = defaultdict(int)
        self.traffic_data = {
            'timestamps': [],
            'packet_counts': [],
            'bytes_transferred': []
        }
        self.connections = defaultdict(int)
        self.start_time = time.time()
        
        # Initialize components
        self.metrics = PerformanceMetrics()
        self.security = SecurityMonitor()
        self.protocol_analyzer = ProtocolAnalyzer()
        self.report_generator = ReportGenerator()
        
        # Set up CSV logging
        self.logger = logging.getLogger('PacketLogger')
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler(self.log_file, 'w', encoding='utf-8')
        handler.setFormatter(logging.Formatter('%(message)s'))
        self.logger.handlers = [handler]
        # Write CSV header with all fields
        self.logger.info('No,Timestamp,Source IP,Destination IP,Protocol,Source Port,Destination Port,HTTP Method,URL,Status Code,Content Type,Payload,Bandwidth,Packet Rate,Latency,Connection State,Security Alert')

        # Initialize visualization
        self.setup_visualization()
        
        # Initialize ML components
        self.anomaly_detector = None
        self.feature_scaler = StandardScaler()
        self.anomaly_threshold = 0.1
        
        # Initialize alert system
        self.alert_config = {
            'email': {
                'enabled': False,
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'username': '',
                'password': '',
                'from_addr': '',
                'to_addr': ''
            }
        }
        
        # Start alert monitoring
        self.start_alert_monitoring()
        
        # Initialize performance optimization
        self.thread_pool = ThreadPoolExecutor(max_workers=4)
        
        # Initialize topology mapping
        self.topology_update_interval = 60  # seconds
        self.last_topology_update = time.time()
        
        # Start API server in a separate thread
        self.api_thread = threading.Thread(target=self.start_api_server)
        self.api_thread.daemon = True
        self.api_thread.start()

    def setup_visualization(self):
        """Set up the visualization windows and figures."""
        # Create figure with subplots
        self.fig = plt.figure(figsize=(15, 12))
        
        # Create a grid layout
        gs = self.fig.add_gridspec(4, 3)
        
        # Security alerts (top row)
        self.ax0 = self.fig.add_subplot(gs[0, :])
        self.ax0.set_title('Security Alerts')
        self.ax0.axis('off')  # Hide axes for text display
        
        # Protocol distribution pie chart (second row, left)
        self.ax1 = self.fig.add_subplot(gs[1, 0])
        self.ax1.set_title('Protocol Distribution')
        
        # Real-time traffic graph (second row, middle-right)
        self.ax2 = self.fig.add_subplot(gs[1, 1:])
        self.ax2.set_title('Real-time Traffic')
        self.ax2.set_xlabel('Time (s)')
        self.ax2.set_ylabel('Packets/s')
        
        # Bandwidth usage graph (third row, left)
        self.ax3 = self.fig.add_subplot(gs[2, 0])
        self.ax3.set_title('Bandwidth Usage')
        self.ax3.set_xlabel('Time (s)')
        self.ax3.set_ylabel('Bytes/s')
        
        # Latency graph (third row, middle-right)
        self.ax4 = self.fig.add_subplot(gs[2, 1:])
        self.ax4.set_title('Connection Latency')
        self.ax4.set_xlabel('Time (s)')
        self.ax4.set_ylabel('Latency (s)')
        
        # Performance metrics bar chart (bottom row, left)
        self.ax5 = self.fig.add_subplot(gs[3, 0])
        self.ax5.set_title('Performance Metrics')
        
        # Network traffic flow diagram (bottom row, middle-right)
        self.ax6 = self.fig.add_subplot(gs[3, 1:])
        self.ax6.set_title('Network Traffic Flow')
        
        # Initialize network graph
        self.G = nx.DiGraph()
        
        # Initialize alert text
        self.alert_text = self.ax0.text(0.02, 0.5, '', transform=self.ax0.transAxes,
                                      bbox=dict(facecolor='white', alpha=0.8))
        
        # Adjust layout
        plt.tight_layout()
        
        # Start animation
        self.ani = FuncAnimation(self.fig, self.update_plots, interval=1000)
        plt.show(block=False)

    def update_plots(self, frame):
        """Update all visualization plots."""
        # Clear previous plots
        self.ax1.clear()
        self.ax2.clear()
        self.ax3.clear()
        self.ax4.clear()
        self.ax5.clear()
        self.ax6.clear()
        
        # Update security alerts
        alerts = self.security.get_alerts()
        if alerts:
            alert_text = "Recent Security Alerts:\n"
            for alert in alerts[-3:]:  # Show last 3 alerts
                alert_text += f"• {alert['message']}\n"
            self.alert_text.set_text(alert_text)
            self.ax0.set_facecolor('#ffebee')  # Light red background for alerts
        else:
            self.alert_text.set_text("No security alerts")
            self.ax0.set_facecolor('#e8f5e9')  # Light green background for no alerts
        
        # Update protocol distribution pie chart
        if self.protocol_stats:
            protocols = list(self.protocol_stats.keys())
            counts = list(self.protocol_stats.values())
            self.ax1.pie(counts, labels=protocols, autopct='%1.1f%%')
            self.ax1.set_title('Protocol Distribution')
        
        # Update real-time traffic graph
        if self.traffic_data['timestamps']:
            self.ax2.plot(self.traffic_data['timestamps'], self.traffic_data['packet_counts'], 'b-')
            self.ax2.set_title('Real-time Traffic')
            self.ax2.set_xlabel('Time (s)')
            self.ax2.set_ylabel('Packets/s')
            
            # Add moving average
            if len(self.traffic_data['packet_counts']) > 10:
                moving_avg = np.convolve(self.traffic_data['packet_counts'], 
                                       np.ones(10)/10, mode='valid')
                self.ax2.plot(self.traffic_data['timestamps'][9:], moving_avg, 'r--', 
                            label='Moving Average')
                self.ax2.legend()
        
        # Update bandwidth graph
        if self.metrics.bandwidth['timestamps']:
            self.ax3.plot(self.metrics.bandwidth['timestamps'], 
                         self.metrics.bandwidth['bytes_per_sec'], 'g-')
            self.ax3.set_title('Bandwidth Usage')
            self.ax3.set_xlabel('Time (s)')
            self.ax3.set_ylabel('Bytes/s')
            
            # Add trend line
            if len(self.metrics.bandwidth['bytes_per_sec']) > 1:
                z = np.polyfit(range(len(self.metrics.bandwidth['bytes_per_sec'])),
                             self.metrics.bandwidth['bytes_per_sec'], 1)
                p = np.poly1d(z)
                self.ax3.plot(self.metrics.bandwidth['timestamps'], 
                            p(range(len(self.metrics.bandwidth['bytes_per_sec']))),
                            'r--', label='Trend')
                self.ax3.legend()
        
        # Update latency graph
        if self.metrics.connection_times:
            avg_latencies = [statistics.mean(times) for times in self.metrics.connection_times.values()]
            if avg_latencies:
                self.ax4.plot(range(len(avg_latencies)), avg_latencies, 'r-')
                self.ax4.set_title('Connection Latency')
                self.ax4.set_xlabel('Connection')
                self.ax4.set_ylabel('Latency (s)')
                
                # Add threshold line
                threshold = 0.1  # 100ms threshold
                self.ax4.axhline(y=threshold, color='r', linestyle='--', 
                               label='Threshold (100ms)')
                self.ax4.legend()
        
        # Update performance metrics bar chart
        stats = self.metrics.get_statistics()
        metrics = ['Bandwidth', 'Packet Rate', 'Latency', 'Connections']
        values = [
            stats['bandwidth']['current'] / 1024,  # Convert to KB/s
            stats['packet_rate']['current'],
            stats['latency']['average'] * 1000,  # Convert to ms
            stats['connections']['active']
        ]
        bars = self.ax5.bar(metrics, values)
        self.ax5.set_title('Performance Metrics')
        plt.setp(self.ax5.xaxis.get_majorticklabels(), rotation=45)
        
        # Add value labels on top of bars
        for bar in bars:
            height = bar.get_height()
            self.ax5.text(bar.get_x() + bar.get_width()/2., height,
                         f'{height:.1f}',
                         ha='center', va='bottom')
        
        # Update network traffic flow diagram
        if self.G.nodes():
            pos = nx.spring_layout(self.G)
            nx.draw(self.G, pos, ax=self.ax6, with_labels=True, node_color='lightblue', 
                   node_size=1500, arrowsize=20, font_size=8)
            self.ax6.set_title('Network Traffic Flow')
            
            # Add edge weights
            edge_labels = nx.get_edge_attributes(self.G, 'weight')
            nx.draw_networkx_edge_labels(self.G, pos, edge_labels=edge_labels)

    def update_statistics(self, packet):
        """Update statistics for visualization."""
        # Update protocol statistics
        if IP in packet:
            if TCP in packet:
                self.protocol_stats['TCP'] += 1
                # Update TCP connection tracking
                self.metrics.update_connection(packet[IP].src, packet[IP].dst, packet[TCP].flags)
            elif UDP in packet:
                self.protocol_stats['UDP'] += 1
            elif ICMP in packet:
                self.protocol_stats['ICMP'] += 1
            else:
                self.protocol_stats['Other'] += 1
            
            # Update traffic data
            current_time = time.time() - self.start_time
            self.traffic_data['timestamps'].append(current_time)
            self.traffic_data['packet_counts'].append(self.packet_count)
            
            # Update connection graph with weights
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            if self.G.has_edge(src_ip, dst_ip):
                self.G[src_ip][dst_ip]['weight'] += 1
            else:
                self.G.add_edge(src_ip, dst_ip, weight=1)
            
            # Update performance metrics
            packet_size = len(packet)
            self.metrics.update_bandwidth(packet_size)
            self.metrics.update_packet_rate()
            self.metrics.update_latency(src_ip, dst_ip, current_time)

    def extract_http_info(self, packet):
        """Extract HTTP/HTTPS information from the packet."""
        http_info = {
            'method': 'N/A',
            'url': 'N/A',
            'status_code': 'N/A',
            'content_type': 'N/A'
        }

        if packet.haslayer(http.HTTPRequest):
            # Extract HTTP request information
            http_info['method'] = packet[http.HTTPRequest].Method.decode()
            http_info['url'] = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
            
            # Extract Content-Type from headers if present
            if packet.haslayer(Raw):
                raw_load = packet[Raw].load.decode('utf-8', errors='ignore')
                content_type_match = re.search(r'Content-Type:\s*([^\r\n]+)', raw_load)
                if content_type_match:
                    http_info['content_type'] = content_type_match.group(1).strip()

        elif packet.haslayer(http.HTTPResponse):
            # Extract HTTP response information
            http_info['status_code'] = str(packet[http.HTTPResponse].Status_Code.decode())
            
            # Extract Content-Type from headers if present
            if packet.haslayer(Raw):
                raw_load = packet[Raw].load.decode('utf-8', errors='ignore')
                content_type_match = re.search(r'Content-Type:\s*([^\r\n]+)', raw_load)
                if content_type_match:
                    http_info['content_type'] = content_type_match.group(1).strip()

        return http_info

    def check_filters(self, packet):
        """Check if packet matches all filters."""
        if not IP in packet:
            return False

        # IP range filter
        if self.ip_range:
            src_ip = ipaddress.ip_address(packet[IP].src)
            dst_ip = ipaddress.ip_address(packet[IP].dst)
            if not (src_ip in self.ip_range or dst_ip in self.ip_range):
                return False

        # Port range filter
        if self.port_range:
            if TCP in packet:
                if not (self.port_range[0] <= packet[TCP].sport <= self.port_range[1] or
                       self.port_range[0] <= packet[TCP].dport <= self.port_range[1]):
                    return False
            elif UDP in packet:
                if not (self.port_range[0] <= packet[UDP].sport <= self.port_range[1] or
                       self.port_range[0] <= packet[UDP].dport <= self.port_range[1]):
                    return False

        return True

    def analyze_tcp_flags(self, packet):
        """Analyze TCP flags and connection states."""
        if TCP in packet:
            flags = {
                'SYN': bool(packet[TCP].flags & 0x02),
                'ACK': bool(packet[TCP].flags & 0x10),
                'FIN': bool(packet[TCP].flags & 0x01),
                'RST': bool(packet[TCP].flags & 0x04),
                'PSH': bool(packet[TCP].flags & 0x08),
                'URG': bool(packet[TCP].flags & 0x20)
            }
            
            # Update connection state tracking
            if flags['SYN'] and not flags['ACK']:
                self.metrics.update_connection_state(packet[IP].src, packet[IP].dst, 'SYN_SENT')
            elif flags['SYN'] and flags['ACK']:
                self.metrics.update_connection_state(packet[IP].src, packet[IP].dst, 'SYN_RECEIVED')
            elif flags['FIN']:
                self.metrics.update_connection_state(packet[IP].src, packet[IP].dst, 'FIN_WAIT')
            elif flags['RST']:
                self.metrics.update_connection_state(packet[IP].src, packet[IP].dst, 'RESET')
            
            return flags
        return None

    def detect_anomalies(self):
        """Detect network anomalies using machine learning."""
        if len(self.traffic_data['packet_counts']) < 10:
            return None
        
        # Prepare features
        features = np.column_stack((
            self.traffic_data['packet_counts'],
            self.metrics.bandwidth['bytes_per_sec'],
            [stats['latency']['average'] for _ in range(len(self.traffic_data['timestamps']))]
        ))
        
        # Normalize features
        features_scaled = self.feature_scaler.fit_transform(features)
        
        # Initialize or update anomaly detector
        if self.anomaly_detector is None:
            self.anomaly_detector = IsolationForest(contamination=self.anomaly_threshold)
            self.anomaly_detector.fit(features_scaled)
        
        # Predict anomalies
        predictions = self.anomaly_detector.predict(features_scaled)
        return predictions

    def generate_topology_map(self):
        """Generate a network topology map."""
        if time.time() - self.last_topology_update < self.topology_update_interval:
            return
        
        self.last_topology_update = time.time()
        
        # Create directed graph
        G = nx.DiGraph()
        
        # Add nodes and edges with weights
        for src, dst in self.connections:
            G.add_edge(src, dst, weight=self.connections[(src, dst)])
        
        # Calculate node positions
        pos = nx.spring_layout(G)
        
        # Create figure
        plt.figure(figsize=(12, 8))
        
        # Draw the graph
        nx.draw(G, pos, with_labels=True, node_color='lightblue',
                node_size=1500, arrowsize=20, font_size=8)
        
        # Add edge labels
        edge_labels = nx.get_edge_attributes(G, 'weight')
        nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)
        
        # Add title and save
        plt.title('Network Topology Map')
        plt.savefig('topology_map.png')
        plt.close()

    def send_alert_email(self, alert):
        """Send alert notification via email."""
        if not self.alert_config['email']['enabled']:
            return
        
        try:
            msg = MIMEText(f"Security Alert: {alert['message']}\n\nTimestamp: {alert['timestamp']}")
            msg['Subject'] = 'Network Security Alert'
            msg['From'] = self.alert_config['email']['from_addr']
            msg['To'] = self.alert_config['email']['to_addr']
            
            with smtplib.SMTP(self.alert_config['email']['smtp_server'], 
                            self.alert_config['email']['smtp_port']) as server:
                server.starttls()
                server.login(self.alert_config['email']['username'],
                           self.alert_config['email']['password'])
                server.send_message(msg)
        except Exception as e:
            print(f"{Fore.RED}[!] Error sending alert email: {str(e)}{Style.RESET_ALL}")

    def start_alert_monitoring(self):
        """Start monitoring for alerts."""
        def check_alerts():
            while True:
                alerts = self.security.get_alerts()
                if alerts:
                    for alert in alerts:
                        self.send_alert_email(alert)
                time.sleep(60)
        
        alert_thread = threading.Thread(target=check_alerts)
        alert_thread.daemon = True
        alert_thread.start()

    def process_packet(self, packet):
        """Process and analyze each captured packet."""
        if not self.check_filters(packet):
            return

        # Process packet in thread pool
        self.thread_pool.submit(self._process_packet_internal, packet)

    def _process_packet_internal(self, packet):
        """Internal packet processing method."""
        self.packet_count += 1
        
        # Store packet for replay
        if len(self.captured_packets) < self.max_captured_packets:
            self.captured_packets.append(packet)
        
        # Update visualization statistics
        self.update_statistics(packet)
        
        # Analyze TCP flags
        tcp_flags = self.analyze_tcp_flags(packet)
        
        # Extract basic packet information
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            
            # Security checks
            packet_size = len(packet)
            self.security.update_stats(src_ip, packet_size)
            self.security.detect_port_scan(src_ip, packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0)
            self.security.detect_ddos(src_ip)
            self.security.detect_size_anomaly(src_ip, packet_size)
            self.security.check_rate_limit(src_ip)
            
            # Protocol analysis
            self.protocol_analyzer.analyze_dns(packet)
            self.protocol_analyzer.analyze_ftp(packet)
            self.protocol_analyzer.analyze_smtp(packet)
            self.protocol_analyzer.analyze_pop3(packet)
            self.protocol_analyzer.analyze_ssl(packet)
            
            # Detect anomalies
            anomalies = self.detect_anomalies()
            if anomalies is not None and -1 in anomalies:
                self.security.add_alert("Anomalous traffic pattern detected")
            
            # Update topology map periodically
            self.generate_topology_map()
            
            # Get protocol name
            if TCP in packet:
                protocol_name = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                protocol_name = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif ICMP in packet:
                protocol_name = "ICMP"
                src_port = dst_port = "N/A"
            else:
                protocol_name = "Other"
                src_port = dst_port = "N/A"

            # Protocol filter
            if self.protocol_filter and protocol_name != self.protocol_filter.upper():
                return

            # Extract HTTP information
            http_info = self.extract_http_info(packet)

            # Extract payload
            payload = ""
            if self.show_payload:
                if TCP in packet or UDP in packet:
                    raw = bytes(packet[TCP].payload) if TCP in packet else bytes(packet[UDP].payload)
                    if raw:
                        try:
                            payload = raw.decode(errors='replace')
                        except Exception:
                            payload = binascii.hexlify(raw).decode()

            # Get performance metrics
            stats = self.metrics.get_statistics()

            # Create packet info string
            packet_info = (
                f"\n{Fore.CYAN}[*] Packet #{self.packet_count}{Style.RESET_ALL}\n"
                f"{Fore.GREEN}Source IP: {src_ip}{Style.RESET_ALL}\n"
                f"{Fore.GREEN}Destination IP: {dst_ip}{Style.RESET_ALL}\n"
                f"{Fore.YELLOW}Protocol: {protocol_name}{Style.RESET_ALL}\n"
                f"{Fore.YELLOW}Source Port: {src_port}{Style.RESET_ALL}\n"
                f"{Fore.YELLOW}Destination Port: {dst_port}{Style.RESET_ALL}\n"
                f"{Fore.BLUE}Bandwidth: {stats['bandwidth']['current']/1024:.2f} KB/s{Style.RESET_ALL}\n"
                f"{Fore.BLUE}Packet Rate: {stats['packet_rate']['current']:.2f} p/s{Style.RESET_ALL}\n"
                f"{Fore.BLUE}Latency: {stats['latency']['average']*1000:.2f} ms{Style.RESET_ALL}\n"
                f"{Fore.BLUE}Active Connections: {stats['connections']['active']}{Style.RESET_ALL}\n"
            )

            # Add HTTP information if available
            if http_info['method'] != 'N/A' or http_info['status_code'] != 'N/A':
                packet_info += f"{Fore.MAGENTA}HTTP Method: {http_info['method']}{Style.RESET_ALL}\n"
                packet_info += f"{Fore.MAGENTA}URL: {http_info['url']}{Style.RESET_ALL}\n"
                packet_info += f"{Fore.MAGENTA}Status Code: {http_info['status_code']}{Style.RESET_ALL}\n"
                packet_info += f"{Fore.MAGENTA}Content Type: {http_info['content_type']}{Style.RESET_ALL}\n"

            # Add security alerts if any
            alerts = self.security.get_alerts()
            if alerts:
                packet_info += f"{Fore.RED}Security Alerts:{Style.RESET_ALL}\n"
                for alert in alerts:
                    packet_info += f"{Fore.RED}- {alert['message']}{Style.RESET_ALL}\n"

            if self.show_payload and payload:
                packet_info += f"{Fore.MAGENTA}Payload: {payload}{Style.RESET_ALL}\n"
            print(packet_info)
            
            # Log packet information
            logging.info(
                f"Packet #{self.packet_count} | "
                f"Source: {src_ip}:{src_port} | "
                f"Destination: {dst_ip}:{dst_port} | "
                f"Protocol: {protocol_name} | "
                f"HTTP Method: {http_info['method']} | "
                f"URL: {http_info['url']} | "
                f"Status Code: {http_info['status_code']} | "
                f"Content Type: {http_info['content_type']} | "
                f"Bandwidth: {stats['bandwidth']['current']/1024:.2f} KB/s | "
                f"Packet Rate: {stats['packet_rate']['current']:.2f} p/s | "
                f"Latency: {stats['latency']['average']*1000:.2f} ms | "
                f"Active Connections: {stats['connections']['active']} | "
                f"Security Alerts: {len(alerts)}"
            )

            # Log packet info as CSV
            timestamp = datetime.now().isoformat()
            csv_line = f'{self.packet_count},{timestamp},{src_ip},{dst_ip},{protocol_name},{src_port},{dst_port},{http_info["method"]},{http_info["url"]},{http_info["status_code"]},{http_info["content_type"]},"{payload.replace('"', '""')}",{stats["bandwidth"]["current"]},{stats["packet_rate"]["current"]},{stats["latency"]["average"]},{stats["connections"]["active"]},{len(alerts)}'
            self.logger.info(csv_line)

    def export_performance_data(self, filename='performance_data.csv'):
        """Export performance metrics to a CSV file."""
        stats = self.metrics.get_statistics()
        
        # Prepare data for export
        data = {
            'timestamp': datetime.now().isoformat(),
            'bandwidth_current_kb_s': stats['bandwidth']['current'] / 1024,
            'bandwidth_average_kb_s': stats['bandwidth']['average'] / 1024,
            'bandwidth_total_mb': stats['bandwidth']['total'] / 1024 / 1024,
            'packet_rate_current': stats['packet_rate']['current'],
            'packet_rate_average': stats['packet_rate']['average'],
            'latency_average_ms': stats['latency']['average'] * 1000,
            'latency_min_ms': stats['latency']['min'] * 1000,
            'latency_max_ms': stats['latency']['max'] * 1000,
            'connections_active': stats['connections']['active'],
            'connections_total': stats['connections']['total'],
            'connections_established': stats['connections']['established'],
            'connections_closed': stats['connections']['closed'],
            'security_alerts_count': len(self.security.get_alerts()),
            'protocol_distribution': json.dumps(self.protocol_stats),
            'suspicious_ips': json.dumps(list(self.security.suspicious_ips)),
            'top_talkers': json.dumps(dict(sorted(self.security.get_ip_stats().items(),
                                                key=lambda x: x[1]['total_bytes'],
                                                reverse=True)[:5]))
        }
        
        # Write to CSV
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=data.keys())
            writer.writeheader()
            writer.writerow(data)
        
        print(f"{Fore.GREEN}[+] Performance data exported to {filename}{Style.RESET_ALL}")

    def start_sniffing(self, interface=None, count=0):
        """Start packet sniffing on the specified interface."""
        print(f"{Fore.CYAN}[*] Starting packet capture...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Press Ctrl+C to stop{Style.RESET_ALL}")
        
        try:
            sniff(
                iface=interface,
                prn=self.process_packet,
                count=count,
                store=0,
                filter=self.bpf_filter
            )
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Stopping packet capture...{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Total packets captured: {self.packet_count}{Style.RESET_ALL}")
            
            # Export performance data
            self.export_performance_data()
            
            # Generate final reports
            report_data = {
                'protocol_stats': self.protocol_stats,
                'ip_stats': self.security.get_ip_stats(),
                'security_alerts': self.security.get_alerts(),
                'metrics': self.metrics.get_statistics(),
                'dns_queries': self.protocol_analyzer.get_dns_queries(),
                'ftp_sessions': self.protocol_analyzer.get_ftp_sessions(),
                'smtp_sessions': self.protocol_analyzer.get_smtp_sessions(),
                'pop3_sessions': self.protocol_analyzer.get_pop3_sessions(),
                'ssl_sessions': self.protocol_analyzer.get_ssl_sessions()
            }
            
            self.report_generator.generate_all_reports(report_data)
            
            # Print final statistics
            stats = self.metrics.get_statistics()
            print(f"\n{Fore.CYAN}[*] Final Statistics:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Total Bandwidth: {stats['bandwidth']['total']/1024/1024:.2f} MB{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Average Packet Rate: {stats['packet_rate']['average']:.2f} p/s{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Average Latency: {stats['latency']['average']*1000:.2f} ms{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Total Connections: {stats['connections']['total']}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Established Connections: {stats['connections']['established']}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Closed Connections: {stats['connections']['closed']}{Style.RESET_ALL}")
            
            plt.close('all')

    def save_captured_packets(self, filename=None):
        """Save captured packets to a PCAP file."""
        if not filename:
            filename = self.capture_file
        
        if self.captured_packets:
            wrpcap(filename, self.captured_packets)
            print(f"{Fore.GREEN}[+] Saved {len(self.captured_packets)} packets to {filename}{Style.RESET_ALL}")
            return True
        return False

    def replay_packets(self, filename=None, count=None, delay=0.1):
        """Replay captured packets from a PCAP file."""
        if not filename:
            filename = self.capture_file
        
        if not os.path.exists(filename):
            print(f"{Fore.RED}[!] File {filename} does not exist{Style.RESET_ALL}")
            return False
        
        try:
            packets = rdpcap(filename)
            if count:
                packets = packets[:count]
            
            print(f"{Fore.CYAN}[*] Replaying {len(packets)} packets...{Style.RESET_ALL}")
            for packet in packets:
                sendp(packet)
                time.sleep(delay)
            print(f"{Fore.GREEN}[+] Packet replay completed{Style.RESET_ALL}")
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Error replaying packets: {str(e)}{Style.RESET_ALL}")
            return False

    def start_api_server(self):
        """Start a REST API server for real-time statistics."""
        @app.route('/stats')
        def get_stats():
            return jsonify(self.metrics.get_statistics())
        
        @app.route('/alerts')
        def get_alerts():
            return jsonify(self.security.get_alerts())
        
        @app.route('/protocols')
        def get_protocols():
            return jsonify(dict(self.protocol_stats))
        
        @app.route('/connections')
        def get_connections():
            return jsonify({
                'active': len(self.metrics.connections['active']),
                'total': self.metrics.connections['total'],
                'established': self.metrics.connections['established'],
                'closed': self.metrics.connections['closed']
            })
        
        @app.route('/topology')
        def get_topology():
            self.generate_topology_map()
            return jsonify({'status': 'success', 'file': 'topology_map.png'})
        
        @app.route('/anomalies')
        def get_anomalies():
            anomalies = self.detect_anomalies()
            return jsonify({'anomalies': anomalies.tolist() if anomalies is not None else []})
        
        @app.route('/capture', methods=['POST'])
        def start_capture():
            duration = request.json.get('duration', 0)
            count = request.json.get('count', 0)
            self.start_sniffing(count=count)
            return jsonify({'status': 'success'})
        
        @app.route('/replay', methods=['POST'])
        def replay():
            filename = request.json.get('filename')
            count = request.json.get('count')
            delay = request.json.get('delay', 0.1)
            success = self.replay_packets(filename, count, delay)
            return jsonify({'status': 'success' if success else 'error'})
        
        @app.route('/configure', methods=['POST'])
        def configure():
            config = request.json
            if 'email' in config:
                self.alert_config['email'].update(config['email'])
            return jsonify({'status': 'success'})
        
        app.run(port=5000, debug=False)

def main():
    parser = argparse.ArgumentParser(description='Network Packet Analyzer')
    parser.add_argument('--interface', '-i', help='Network interface to sniff on')
    parser.add_argument('--protocol', '-p', help='Filter by protocol (TCP, UDP, ICMP)')
    parser.add_argument('--show-payload', action='store_true', help='Display packet payloads')
    parser.add_argument('--log-file', default='packet_log.csv', help='Log file name (CSV format)')
    parser.add_argument('--ip-range', help='IP range to filter (CIDR notation)')
    parser.add_argument('--port-range', help='Port range to filter (e.g., "80-443")')
    parser.add_argument('--bpf', help='Custom BPF filter expression')
    parser.add_argument('--save-pcap', help='Save captured packets to PCAP file')
    parser.add_argument('--replay', help='Replay packets from PCAP file')
    parser.add_argument('--replay-count', type=int, help='Number of packets to replay')
    parser.add_argument('--replay-delay', type=float, default=0.1, help='Delay between replayed packets')
    parser.add_argument('--email-alerts', action='store_true', help='Enable email alerts')
    parser.add_argument('--smtp-server', help='SMTP server for email alerts')
    parser.add_argument('--smtp-port', type=int, help='SMTP port for email alerts')
    parser.add_argument('--email-from', help='From address for email alerts')
    parser.add_argument('--email-to', help='To address for email alerts')
    parser.add_argument('--email-username', help='SMTP username for email alerts')
    parser.add_argument('--email-password', help='SMTP password for email alerts')
    args = parser.parse_args()

    # Parse IP range
    ip_range = None
    if args.ip_range:
        try:
            ip_range = ipaddress.ip_network(args.ip_range)
        except ValueError:
            print(f"{Fore.RED}[!] Invalid IP range format. Use CIDR notation (e.g., 192.168.1.0/24){Style.RESET_ALL}")
            sys.exit(1)

    # Parse port range
    port_range = None
    if args.port_range:
        try:
            start, end = map(int, args.port_range.split('-'))
            port_range = (start, end)
        except ValueError:
            print(f"{Fore.RED}[!] Invalid port range format. Use start-end (e.g., 80-443){Style.RESET_ALL}")
            sys.exit(1)

    analyzer = PacketAnalyzer(
        protocol_filter=args.protocol,
        show_payload=args.show_payload,
        log_file=args.log_file,
        ip_range=ip_range,
        port_range=port_range,
        bpf_filter=args.bpf
    )

    # Configure email alerts if enabled
    if args.email_alerts:
        analyzer.alert_config['email'].update({
            'enabled': True,
            'smtp_server': args.smtp_server,
            'smtp_port': args.smtp_port,
            'from_addr': args.email_from,
            'to_addr': args.email_to,
            'username': args.email_username,
            'password': args.email_password
        })

    if args.replay:
        analyzer.replay_packets(args.replay, args.replay_count, args.replay_delay)
    else:
        analyzer.start_sniffing(interface=args.interface)
        if args.save_pcap:
            analyzer.save_captured_packets(args.save_pcap)

if __name__ == "__main__":
    main() 