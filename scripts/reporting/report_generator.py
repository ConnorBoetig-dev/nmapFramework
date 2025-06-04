#!/usr/bin/env python3
"""
Network Scan Report Generator
Creates actionable HTML and text reports from parsed nmap data
"""

import json
import argparse
import sys
from pathlib import Path
from datetime import datetime
from jinja2 import Template
import csv
from collections import Counter

class ReportGenerator:
    def __init__(self):
        self.data = None
        self.template_dir = Path("templates")
        self.template_dir.mkdir(exist_ok=True)
        
    def load_data(self, json_file):
        """Load parsed nmap data from JSON file"""
        try:
            with open(json_file, 'r') as f:
                self.data = json.load(f)
            return True
        except FileNotFoundError:
            print(f"File not found: {json_file}")
            return False
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON: {e}")
            return False
    
    def generate_html_report(self, output_file):
        """Generate comprehensive HTML report"""
        if not self.data:
            print("No data loaded")
            return False
        
        # Create HTML template
        html_template = self._get_html_template()
        
        # Prepare data for template
        template_data = self._prepare_template_data()
        
        # Render template
        template = Template(html_template)
        html_content = template.render(**template_data)
        
        # Write to file
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        print(f"HTML report generated: {output_file}")
        return True
    
    def generate_text_report(self, output_file):
        """Generate simple text report"""
        if not self.data:
            print("No data loaded")
            return False
        
        report_lines = []
        report_lines.append("=" * 60)
        report_lines.append("NETWORK SCAN REPORT")
        report_lines.append("=" * 60)
        report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Scanner: {self.data['scan_info'].get('scanner', 'nmap')}")
        report_lines.append(f"Command: {self.data['scan_info'].get('command_line', 'N/A')}")
        report_lines.append("")
        
        # Executive Summary
        insights = self.data['insights']
        report_lines.append("EXECUTIVE SUMMARY")
        report_lines.append("-" * 20)
        report_lines.append(f"Total Hosts Scanned: {insights['total_hosts']}")
        report_lines.append(f"Hosts Online: {insights['hosts_up']}")
        report_lines.append(f"Total Open Ports: {insights['total_open_ports']}")
        report_lines.append(f"Unique Services: {len(insights['unique_services'])}")
        report_lines.append(f"Security Issues Found: {len(insights['potential_issues'])}")
        report_lines.append("")
        
        # Security Issues
        if insights['potential_issues']:
            report_lines.append("SECURITY CONCERNS")
            report_lines.append("-" * 20)
            for issue in insights['potential_issues']:
                severity_marker = "🔴" if issue['severity'] == 'high' else "🟡"
                report_lines.append(f"{severity_marker} {issue['host']}:{issue['port']} - {issue['issue']}")
            report_lines.append("")
        
        # Service Distribution
        if insights['unique_services']:
            report_lines.append("SERVICES DETECTED")
            report_lines.append("-" * 20)
            service_count = Counter()
            for host in self.data['hosts']:
                for port in host['ports']:
                    if port['state'] == 'open':
                        service_count[port['service'].get('name', 'unknown')] += 1
            
            for service, count in service_count.most_common():
                report_lines.append(f"{service}: {count} instances")
            report_lines.append("")
        
        # OS Distribution
        if insights['os_distribution']:
            report_lines.append("OPERATING SYSTEMS")
            report_lines.append("-" * 20)
            for os_name, count in insights['os_distribution'].items():
                report_lines.append(f"{os_name}: {count} hosts")
            report_lines.append("")
        
        # Host Details
        report_lines.append("HOST DETAILS")
        report_lines.append("-" * 20)
        for host in self.data['hosts']:
            ip = host['addresses'].get('ipv4', host['addresses'].get('ipv6', 'unknown'))
            hostname = host['hostnames'][0]['name'] if host['hostnames'] else 'No hostname'
            
            report_lines.append(f"Host: {ip} ({hostname})")
            
            # OS Information
            if host['os'].get('matches'):
                best_match = max(host['os']['matches'], key=lambda x: x['accuracy'])
                if best_match['accuracy'] > 70:
                    report_lines.append(f"  OS: {best_match['name']} ({best_match['accuracy']}% confidence)")
            
            # Open Ports
            open_ports = [p for p in host['ports'] if p['state'] == 'open']
            if open_ports:
                report_lines.append(f"  Open Ports: {len(open_ports)}")
                for port in open_ports[:10]:  # Limit to first 10 ports
                    service = port['service'].get('name', 'unknown')
                    version = port['service'].get('version', '')
                    product = port['service'].get('product', '')
                    version_info = f" ({product} {version})".strip() if product or version else ""
                    report_lines.append(f"    {port['port']}/{port['protocol']}: {service}{version_info}")
                
                if len(open_ports) > 10:
                    report_lines.append(f"    ... and {len(open_ports) - 10} more ports")
            
            report_lines.append("")
        
        # Write to file
        with open(output_file, 'w') as f:
            f.write('\n'.join(report_lines))
        
        print(f"Text report generated: {output_file}")
        return True
    
    def _prepare_template_data(self):
        """Prepare data for HTML template"""
        insights = self.data['insights']
        
        # Calculate additional statistics
        service_stats = Counter()
        port_stats = Counter()
        os_stats = Counter(insights['os_distribution'])
        
        for host in self.data['hosts']:
            for port in host['ports']:
                if port['state'] == 'open':
                    service_stats[port['service'].get('name', 'unknown')] += 1
                    port_stats[port['port']] += 1
        
        # Prepare severity counts
        severity_counts = Counter()
        for issue in insights['potential_issues']:
            severity_counts[issue['severity']] += 1
        
        return {
            'scan_info': self.data['scan_info'],
            'generated_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'insights': insights,
            'hosts': self.data['hosts'],
            'service_stats': service_stats.most_common(10),
            'port_stats': port_stats.most_common(10),
            'os_stats': os_stats.most_common(),
            'severity_counts': dict(severity_counts),
            'total_issues': len(insights['potential_issues'])
        }
    
    def _get_html_template(self):
        """Return HTML template for report"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .summary-card { background: #f8f9fa; padding: 15px; border-radius: 8px; border-left: 4px solid #007bff; }
        .summary-card h3 { margin: 0 0 10px 0; color: #495057; font-size: 14px; text-transform: uppercase; }
        .summary-card .value { font-size: 24px; font-weight: bold; color: #007bff; }
        .section { margin-bottom: 30px; }
        .section-title { font-size: 20px; font-weight: bold; margin-bottom: 15px; color: #333; border-bottom: 2px solid #007bff; padding-bottom: 5px; }
        .alert { padding: 12px; border-radius: 6px; margin-bottom: 10px; }
        .alert-high { background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
        .alert-medium { background-color: #fff3cd; border: 1px solid #ffeaa7; color: #856404; }
        .host-card { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px; padding: 15px; margin-bottom: 15px; }
        .host-header { font-weight: bold; color: #495057; margin-bottom: 10px; }
        .port-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 10px; }
        .port-item { background: white; padding: 8px; border-radius: 4px; border-left: 3px solid #28a745; font-family: monospace; font-size: 12px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .stats-table { width: 100%; border-collapse: collapse; }
        .stats-table th, .stats-table td { padding: 8px; text-align: left; border-bottom: 1px solid #dee2e6; }
        .stats-table th { background-color: #f8f9fa; font-weight: bold; }
        .footer { text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6; color: #6c757d; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Network Scan Report</h1>
            <p>Generated: {{ generated_time }}</p>
            <p>Scanner: {{ scan_info.scanner }} {{ scan_info.version }}</p>
        </div>

        <!-- Executive Summary -->
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Total Hosts</h3>
                <div class="value">{{ insights.total_hosts }}</div>
            </div>
            <div class="summary-card">
                <h3>Hosts Online</h3>
                <div class="value">{{ insights.hosts_up }}</div>
            </div>
            <div class="summary-card">
                <h3>Open Ports</h3>
                <div class="value">{{ insights.total_open_ports }}</div>
            </div>
            <div class="summary-card">
                <h3>Services Found</h3>
                <div class="value">{{ insights.unique_services|length }}</div>
            </div>
            <div class="summary-card">
                <h3>Security Issues</h3>
                <div class="value" style="color: #dc3545;">{{ total_issues }}</div>
            </div>
        </div>

        <!-- Security Issues -->
        {% if insights.potential_issues %}
        <div class="section">
            <div class="section-title">🔒 Security Concerns</div>
            {% for issue in insights.potential_issues %}
            <div class="alert alert-{{ issue.severity }}">
                <strong>{{ issue.host }}:{{ issue.port }}</strong> - {{ issue.issue }}
                <br><small>Service: {{ issue.service }} | Severity: {{ issue.severity|upper }}</small>
            </div>
            {% endfor %}
        </div>
        {% endif %}

        <!-- Statistics -->
        <div class="section">
            <div class="section-title">📊 Network Statistics</div>
            <div class="stats-grid">
                <div>
                    <h4>Top Services</h4>
                    <table class="stats-table">
                        <thead>
                            <tr><th>Service</th><th>Count</th></tr>
                        </thead>
                        <tbody>
                            {% for service, count in service_stats %}
                            <tr><td>{{ service }}</td><td>{{ count }}</td></tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>

                <div>
                    <h4>Common Ports</h4>
                    <table class="stats-table">
                        <thead>
                            <tr><th>Port</th><th>Count</th></tr>
                        </thead>
                        <tbody>
                            {% for port, count in port_stats %}
                            <tr><td>{{ port }}</td><td>{{ count }}</td></tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>

            {% if os_stats %}
            <div style="margin-top: 20px;">
                <h4>Operating Systems</h4>
                <table class="stats-table">
                    <thead>
                        <tr><th>Operating System</th><th>Count</th></tr>
                    </thead>
                    <tbody>
                        {% for os, count in os_stats %}
                        <tr><td>{{ os }}</td><td>{{ count }}</td></tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endif %}
        </div>

        <!-- Host Details -->
        <div class="section">
            <div class="section-title">🖥️ Host Details</div>
            {% for host in hosts %}
            <div class="host-card">
                <div class="host-header">
                    {{ host.addresses.ipv4 or host.addresses.ipv6 or 'Unknown IP' }}
                    {% if host.hostnames %}
                        ({{ host.hostnames[0].name }})
                    {% endif %}
                </div>
                
                {% if host.os.matches %}
                    {% set best_os = host.os.matches|max(attribute='accuracy') %}
                    {% if best_os.accuracy > 70 %}
                    <p><strong>OS:</strong> {{ best_os.name }} ({{ best_os.accuracy }}% confidence)</p>
                    {% endif %}
                {% endif %}

                {% if host.uptime %}
                <p><strong>Uptime:</strong> {{ host.uptime.seconds }} seconds</p>
                {% endif %}

                {% set open_ports = host.ports|selectattr('state', 'equalto', 'open')|list %}
                {% if open_ports %}
                <p><strong>Open Ports ({{ open_ports|length }}):</strong></p>
                <div class="port-list">
                    {% for port in open_ports %}
                    <div class="port-item">
                        <strong>{{ port.port }}/{{ port.protocol }}</strong><br>
                        {{ port.service.name or 'unknown' }}
                        {% if port.service.product %}
                            <br>{{ port.service.product }}
                            {% if port.service.version %}{{ port.service.version }}{% endif %}
                        {% endif %}
                    </div>
                    {% endfor %}
                </div>
                {% endif %}
            </div>
            {% endfor %}
        </div>

        <div class="footer">
            <p>Report generated by Network Mapping Framework</p>
            <p>Scan command: {{ scan_info.command_line }}</p>
        </div>
    </div>
</body>
</html>
        """

def main():
    parser = argparse.ArgumentParser(description="Generate network scan reports")
    parser.add_argument("json_file", help="Path to parsed JSON file")
    parser.add_argument("-o", "--output", default="output/reports",
                       help="Output directory")
    parser.add_argument("--format", choices=["html", "text", "both"], default="both",
                       help="Report format")
    
    args = parser.parse_args()
    
    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Load data and generate reports
    generator = ReportGenerator()
    if not generator.load_data(args.json_file):
        sys.exit(1)
    
    # Generate output filename base
    json_path = Path(args.json_file)
    base_name = json_path.stem.replace('_parsed', '')
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if args.format in ["html", "both"]:
        html_file = output_dir / f"{base_name}_report_{timestamp}.html"
        generator.generate_html_report(html_file)
    
    if args.format in ["text", "both"]:
        text_file = output_dir / f"{base_name}_report_{timestamp}.txt"
        generator.generate_text_report(text_file)
    
    print(f"\nReports generated in: {output_dir}")

if __name__ == "__main__":
    main()
