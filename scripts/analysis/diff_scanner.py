#!/usr/bin/env python3
"""
Scan Diff Analyzer
Compares two network scans and generates diff reports
"""

import json
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import csv
from jinja2 import Template
import sys

class ScanDiffer:
    def __init__(self):
        self.base_scan = None
        self.compare_scan = None
        self.diff_results = {
            'summary': {},
            'hosts': {
                'added': [],
                'removed': [],
                'changed': []
            },
            'ports': {
                'added': [],
                'removed': [],
                'changed': []
            },
            'services': {
                'added': [],
                'removed': [],
                'changed': []
            }
        }
    
    def load_scans(self, base_file, compare_file):
        """Load two scan files for comparison"""
        try:
            with open(base_file, 'r') as f:
                self.base_scan = json.load(f)
            with open(compare_file, 'r') as f:
                self.compare_scan = json.load(f)
            return True
        except Exception as e:
            print(f"Error loading scan files: {e}")
            return False
    
    def analyze_diff(self):
        """Perform comprehensive diff analysis"""
        # Create lookup dictionaries for fast comparison
        base_hosts = self._create_host_lookup(self.base_scan)
        compare_hosts = self._create_host_lookup(self.compare_scan)
        
        base_ports = self._create_port_lookup(self.base_scan)
        compare_ports = self._create_port_lookup(self.compare_scan)
        
        # Analyze host differences
        base_ips = set(base_hosts.keys())
        compare_ips = set(compare_hosts.keys())
        
        # New hosts
        for ip in compare_ips - base_ips:
            self.diff_results['hosts']['added'].append({
                'ip': ip,
                'hostname': self._get_hostname(compare_hosts[ip]),
                'ports': len([p for p in compare_hosts[ip]['ports'] if p['state'] == 'open'])
            })
        
        # Removed hosts
        for ip in base_ips - compare_ips:
            self.diff_results['hosts']['removed'].append({
                'ip': ip,
                'hostname': self._get_hostname(base_hosts[ip]),
                'ports': len([p for p in base_hosts[ip]['ports'] if p['state'] == 'open'])
            })
        
        # Analyze port differences
        base_port_keys = set(base_ports.keys())
        compare_port_keys = set(compare_ports.keys())
        
        # New ports
        for key in compare_port_keys - base_port_keys:
            ip, port = key
            port_data = compare_ports[key]
            self.diff_results['ports']['added'].append({
                'ip': ip,
                'port': port,
                'protocol': port_data['protocol'],
                'service': port_data['service'].get('name', 'unknown'),
                'product': port_data['service'].get('product', ''),
                'version': port_data['service'].get('version', '')
            })
        
        # Removed ports
        for key in base_port_keys - compare_port_keys:
            ip, port = key
            port_data = base_ports[key]
            self.diff_results['ports']['removed'].append({
                'ip': ip,
                'port': port,
                'protocol': port_data['protocol'],
                'service': port_data['service'].get('name', 'unknown'),
                'product': port_data['service'].get('product', ''),
                'version': port_data['service'].get('version', '')
            })
        
        # Changed services (same port, different service info)
        for key in base_port_keys & compare_port_keys:
            base_port = base_ports[key]
            compare_port = compare_ports[key]
            
            # Check for service changes
            if self._service_changed(base_port['service'], compare_port['service']):
                ip, port = key
                self.diff_results['services']['changed'].append({
                    'ip': ip,
                    'port': port,
                    'protocol': compare_port['protocol'],
                    'old_service': base_port['service'].get('name', 'unknown'),
                    'new_service': compare_port['service'].get('name', 'unknown'),
                    'old_version': base_port['service'].get('version', ''),
                    'new_version': compare_port['service'].get('version', ''),
                    'old_product': base_port['service'].get('product', ''),
                    'new_product': compare_port['service'].get('product', '')
                })
        
        # Generate summary
        self.diff_results['summary'] = {
            'base_scan_date': self.base_scan['scan_info'].get('scan_date', 'unknown'),
            'compare_scan_date': self.compare_scan['scan_info'].get('scan_date', 'unknown'),
            'base_target': self.base_scan['scan_metadata'].get('target', 'unknown'),
            'compare_target': self.compare_scan['scan_metadata'].get('target', 'unknown'),
            'hosts_added': len(self.diff_results['hosts']['added']),
            'hosts_removed': len(self.diff_results['hosts']['removed']),
            'ports_added': len(self.diff_results['ports']['added']),
            'ports_removed': len(self.diff_results['ports']['removed']),
            'services_changed': len(self.diff_results['services']['changed'])
        }
    
    def _create_host_lookup(self, scan_data):
        """Create a dictionary for fast host lookup"""
        lookup = {}
        for host in scan_data['hosts']:
            ip = host['addresses'].get('ipv4', host['addresses'].get('ipv6', 'unknown'))
            lookup[ip] = host
        return lookup
    
    def _create_port_lookup(self, scan_data):
        """Create a dictionary for fast port lookup"""
        lookup = {}
        for host in scan_data['hosts']:
            ip = host['addresses'].get('ipv4', host['addresses'].get('ipv6', 'unknown'))
            for port in host['ports']:
                if port['state'] == 'open':
                    key = (ip, port['port'])
                    lookup[key] = port
        return lookup
    
    def _get_hostname(self, host):
        """Extract hostname from host data"""
        if host['hostnames']:
            return host['hostnames'][0]['name']
        return ''
    
    def _service_changed(self, old_service, new_service):
        """Check if service information has changed"""
        # Compare key service attributes
        attrs = ['name', 'product', 'version']
        for attr in attrs:
            if old_service.get(attr, '') != new_service.get(attr, ''):
                return True
        return False
    
    def export_to_csv(self, output_file):
        """Export diff results to CSV"""
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            fieldnames = [
                'change_type', 'ip', 'hostname', 'port', 'protocol', 
                'service', 'product', 'version', 'old_value', 'new_value'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            # Write added hosts
            for host in self.diff_results['hosts']['added']:
                writer.writerow({
                    'change_type': 'HOST_ADDED',
                    'ip': host['ip'],
                    'hostname': host['hostname'],
                    'port': '',
                    'protocol': '',
                    'service': '',
                    'product': '',
                    'version': '',
                    'old_value': '',
                    'new_value': f"{host['ports']} open ports"
                })
            
            # Write removed hosts
            for host in self.diff_results['hosts']['removed']:
                writer.writerow({
                    'change_type': 'HOST_REMOVED',
                    'ip': host['ip'],
                    'hostname': host['hostname'],
                    'port': '',
                    'protocol': '',
                    'service': '',
                    'product': '',
                    'version': '',
                    'old_value': f"{host['ports']} open ports",
                    'new_value': ''
                })
            
            # Write added ports
            for port in self.diff_results['ports']['added']:
                writer.writerow({
                    'change_type': 'PORT_ADDED',
                    'ip': port['ip'],
                    'hostname': '',
                    'port': port['port'],
                    'protocol': port['protocol'],
                    'service': port['service'],
                    'product': port['product'],
                    'version': port['version'],
                    'old_value': '',
                    'new_value': 'open'
                })
            
            # Write removed ports
            for port in self.diff_results['ports']['removed']:
                writer.writerow({
                    'change_type': 'PORT_REMOVED',
                    'ip': port['ip'],
                    'hostname': '',
                    'port': port['port'],
                    'protocol': port['protocol'],
                    'service': port['service'],
                    'product': port['product'],
                    'version': port['version'],
                    'old_value': 'open',
                    'new_value': ''
                })
            
            # Write service changes
            for service in self.diff_results['services']['changed']:
                writer.writerow({
                    'change_type': 'SERVICE_CHANGED',
                    'ip': service['ip'],
                    'hostname': '',
                    'port': service['port'],
                    'protocol': service['protocol'],
                    'service': service['new_service'],
                    'product': service['new_product'],
                    'version': service['new_version'],
                    'old_value': f"{service['old_service']} {service['old_version']}",
                    'new_value': f"{service['new_service']} {service['new_version']}"
                })
        
        print(f"📊 Diff CSV exported to: {output_file}")
    
    def export_to_html(self, output_file):
        """Export diff results to HTML"""
        html_template = self._get_html_template()
        
        template = Template(html_template)
        html_content = template.render(
            diff=self.diff_results,
            generated_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"📄 Diff HTML report exported to: {output_file}")
    
    def _get_html_template(self):
        """Return HTML template for diff report"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Scan Diff Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 30px;
        }
        h1 {
            color: #333;
            margin-bottom: 30px;
        }
        .summary {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        .summary-card {
            background: white;
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #e0e0e0;
            text-align: center;
        }
        .summary-card h3 {
            margin: 0;
            color: #666;
            font-size: 14px;
            text-transform: uppercase;
        }
        .summary-card .value {
            font-size: 28px;
            font-weight: bold;
            color: #333;
            margin: 10px 0;
        }
        .added { color: #28a745; }
        .removed { color: #dc3545; }
        .changed { color: #ffc107; }
        .section {
            margin-bottom: 40px;
        }
        .section h2 {
            color: #333;
            border-bottom: 2px solid #007bff;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }
        th {
            background: #f8f9fa;
            font-weight: 600;
            color: #333;
        }
        tr:hover {
            background: #f8f9fa;
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }
        .badge-added { background: #d4edda; color: #155724; }
        .badge-removed { background: #f8d7da; color: #721c24; }
        .badge-changed { background: #fff3cd; color: #856404; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔄 Network Scan Diff Report</h1>
        
        <div class="summary">
            <h2>Summary</h2>
            <p><strong>Base Scan:</strong> {{ diff.summary.base_scan_date }} (Target: {{ diff.summary.base_target }})</p>
            <p><strong>Compare Scan:</strong> {{ diff.summary.compare_scan_date }} (Target: {{ diff.summary.compare_target }})</p>
            
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Hosts Added</h3>
                    <div class="value added">+{{ diff.summary.hosts_added }}</div>
                </div>
                <div class="summary-card">
                    <h3>Hosts Removed</h3>
                    <div class="value removed">-{{ diff.summary.hosts_removed }}</div>
                </div>
                <div class="summary-card">
                    <h3>Ports Added</h3>
                    <div class="value added">+{{ diff.summary.ports_added }}</div>
                </div>
                <div class="summary-card">
                    <h3>Ports Removed</h3>
                    <div class="value removed">-{{ diff.summary.ports_removed }}</div>
                </div>
                <div class="summary-card">
                    <h3>Services Changed</h3>
                    <div class="value changed">{{ diff.summary.services_changed }}</div>
                </div>
            </div>
        </div>
        
        {% if diff.hosts.added %}
        <div class="section">
            <h2>➕ New Hosts</h2>
            <table>
                <tr>
                    <th>IP Address</th>
                    <th>Hostname</th>
                    <th>Open Ports</th>
                </tr>
                {% for host in diff.hosts.added %}
                <tr>
                    <td>{{ host.ip }}</td>
                    <td>{{ host.hostname or '-' }}</td>
                    <td>{{ host.ports }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}
        
        {% if diff.hosts.removed %}
        <div class="section">
            <h2>➖ Removed Hosts</h2>
            <table>
                <tr>
                    <th>IP Address</th>
                    <th>Hostname</th>
                    <th>Open Ports</th>
                </tr>
                {% for host in diff.hosts.removed %}
                <tr>
                    <td>{{ host.ip }}</td>
                    <td>{{ host.hostname or '-' }}</td>
                    <td>{{ host.ports }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}
        
        {% if diff.ports.added %}
        <div class="section">
            <h2>➕ New Open Ports</h2>
            <table>
                <tr>
                    <th>IP Address</th>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Product</th>
                    <th>Version</th>
                </tr>
                {% for port in diff.ports.added %}
                <tr>
                    <td>{{ port.ip }}</td>
                    <td>{{ port.port }}/{{ port.protocol }}</td>
                    <td>{{ port.service }}</td>
                    <td>{{ port.product or '-' }}</td>
                    <td>{{ port.version or '-' }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}
        
        {% if diff.ports.removed %}
        <div class="section">
            <h2>➖ Closed Ports</h2>
            <table>
                <tr>
                    <th>IP Address</th>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Product</th>
                    <th>Version</th>
                </tr>
                {% for port in diff.ports.removed %}
                <tr>
                    <td>{{ port.ip }}</td>
                    <td>{{ port.port }}/{{ port.protocol }}</td>
                    <td>{{ port.service }}</td>
                    <td>{{ port.product or '-' }}</td>
                    <td>{{ port.version or '-' }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}
        
        {% if diff.services.changed %}
        <div class="section">
            <h2>🔄 Service Changes</h2>
            <table>
                <tr>
                    <th>IP Address</th>
                    <th>Port</th>
                    <th>Old Service</th>
                    <th>New Service</th>
                    <th>Old Version</th>
                    <th>New Version</th>
                </tr>
                {% for service in diff.services.changed %}
                <tr>
                    <td>{{ service.ip }}</td>
                    <td>{{ service.port }}/{{ service.protocol }}</td>
                    <td>{{ service.old_service }}</td>
                    <td>{{ service.new_service }}</td>
                    <td>{{ service.old_version or '-' }}</td>
                    <td>{{ service.new_version or '-' }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}
        
        <div style="text-align: center; margin-top: 40px; color: #666;">
            <p>Generated: {{ generated_time }}</p>
        </div>
    </div>
</body>
</html>
        """

def main():
    parser = argparse.ArgumentParser(description="Compare two network scans")
    parser.add_argument("--base", required=True, help="Base scan JSON file")
    parser.add_argument("--compare", required=True, help="Compare scan JSON file")
    parser.add_argument("--format", choices=["html", "csv", "both"], default="html",
                       help="Output format for diff report")
    parser.add_argument("-o", "--output", default="output/reports",
                       help="Output directory")
    
    args = parser.parse_args()
    
    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Load and analyze
    differ = ScanDiffer()
    if not differ.load_scans(args.base, args.compare):
        sys.exit(1)
    
    differ.analyze_diff()
    
    # Generate output
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if args.format in ["html", "both"]:
        html_file = output_dir / f"diff_report_{timestamp}.html"
        differ.export_to_html(html_file)
    
    if args.format in ["csv", "both"]:
        csv_file = output_dir / f"diff_report_{timestamp}.csv"
        differ.export_to_csv(csv_file)
    
    # Print summary
    print(f"\n📊 Diff Summary:")
    print(f"  Hosts: +{differ.diff_results['summary']['hosts_added']} / -{differ.diff_results['summary']['hosts_removed']}")
    print(f"  Ports: +{differ.diff_results['summary']['ports_added']} / -{differ.diff_results['summary']['ports_removed']}")
    print(f"  Services Changed: {differ.diff_results['summary']['services_changed']}")

if __name__ == "__main__":
    main()
