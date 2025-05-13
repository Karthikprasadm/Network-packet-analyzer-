#!/usr/bin/env python3

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
import jinja2
import os
from datetime import datetime
import json

class ReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.template_loader = jinja2.FileSystemLoader(searchpath="./templates")
        self.template_env = jinja2.Environment(loader=self.template_loader)

    def generate_pdf_report(self, data, output_file="network_report.pdf"):
        """Generate a PDF report."""
        doc = SimpleDocTemplate(output_file, pagesize=letter)
        elements = []

        # Title
        elements.append(Paragraph("Network Analysis Report", self.styles['Title']))
        elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
                                self.styles['Normal']))

        # Protocol Distribution
        elements.append(Paragraph("Protocol Distribution", self.styles['Heading1']))
        protocol_data = [['Protocol', 'Count', 'Percentage']]
        total = sum(data['protocol_stats'].values())
        for protocol, count in data['protocol_stats'].items():
            percentage = (count / total * 100) if total > 0 else 0
            protocol_data.append([protocol, str(count), f"{percentage:.1f}%"])
        
        protocol_table = Table(protocol_data)
        protocol_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(protocol_table)

        # Top Talkers
        elements.append(Paragraph("Top Talkers", self.styles['Heading1']))
        talker_data = [['IP Address', 'Packets', 'Bytes', 'Percentage']]
        total_bytes = sum(ip['total_bytes'] for ip in data['ip_stats'].values())
        for ip, stats in sorted(data['ip_stats'].items(), 
                              key=lambda x: x[1]['total_bytes'], 
                              reverse=True)[:10]:
            percentage = (stats['total_bytes'] / total_bytes * 100) if total_bytes > 0 else 0
            talker_data.append([ip, str(stats['packet_count']), 
                              str(stats['total_bytes']), f"{percentage:.1f}%"])
        
        talker_table = Table(talker_data)
        talker_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(talker_table)

        # Security Alerts
        if data['security_alerts']:
            elements.append(Paragraph("Security Alerts", self.styles['Heading1']))
            alert_data = [['Timestamp', 'Alert']]
            for alert in data['security_alerts']:
                alert_data.append([alert['timestamp'], alert['message']])
            
            alert_table = Table(alert_data)
            alert_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(alert_table)

        # Build PDF
        doc.build(elements)

    def generate_html_report(self, data, output_file="network_report.html"):
        """Generate an HTML report."""
        template = self.template_env.get_template('report_template.html')
        output = template.render(
            data=data,
            generated_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
        
        with open(output_file, 'w') as f:
            f.write(output)

    def generate_json_report(self, data, output_file="network_report.json"):
        """Generate a JSON report."""
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=4)

    def generate_all_reports(self, data):
        """Generate all report formats."""
        self.generate_pdf_report(data)
        self.generate_html_report(data)
        self.generate_json_report(data) 