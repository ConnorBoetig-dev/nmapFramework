#!/usr/bin/env python3
"""
Enhanced Network Scan Report Generator
Creates interactive HTML, text, and CSV reports with real-time features
"""

import json
import argparse
import sys
import webbrowser
import platform
import subprocess
import os
from pathlib import Path
from datetime import datetime
from jinja2 import Template
import csv
from collections import Counter
import time
import threading

class ReportGenerator:
    def __init__(self, json_file=None):
        self.data = None
        self.template_dir = Path("templates")
        self.template_dir.mkdir(exist_ok=True)
        
        # If json_file provided in constructor, load it
        if json_file:
            self.load_data(json_file)
        
    def load_data(self, json_file):
        """Load parsed nmap data from JSON file"""
        try:
            with open(json_file, 'r') as f:
                self.data = json.load(f)
            return True
        except FileNotFoundError:
            print(f"❌ File not found: {json_file}")
            return False
        except json.JSONDecodeError as e:
            print(f"❌ Error parsing JSON: {e}")
            return False
    
    def generate_reports(self, report_format, timestamp, no_open=False):
        """Generate reports in specified format(s)"""
        if not self.data:
            print("❌ No data loaded")
            return []
        
        generated_files = []
        output_dir = Path("output/reports")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Get base filename from scan data
        scan_type = self.data.get('scan_metadata', {}).get('scan_type', 'scan')
        base_filename = f"scan_{scan_type}_report_{timestamp}"
        
        # Generate reports based on format
        if report_format in ['html', 'all']:
            html_file = output_dir / f"{base_filename}.html"
            if self.generate_html_report(html_file, auto_open=(not no_open)):
                generated_files.append(str(html_file))
        
        if report_format in ['text', 'all']:
            text_file = output_dir / f"{base_filename}.txt"
            if self.generate_text_report(text_file):
                generated_files.append(str(text_file))
        
        if report_format in ['csv', 'all']:
            csv_file = output_dir / f"{base_filename}.csv"
            if self.generate_csv_report(csv_file):
                generated_files.append(str(csv_file))
        
        return generated_files
    
    def generate_csv_report(self, output_file):
        """Generate CSV report with scan results"""
        if not self.data:
            print("❌ No data loaded")
            return False
        
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                # Define CSV fields
                fieldnames = [
                    'ip_address', 'hostname', 'state', 'os', 'os_accuracy',
                    'port', 'protocol', 'service', 'product', 'version',
                    'severity', 'issue', 'risk_score'
                ]
                
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                # Process each host
                for host in self.data['hosts']:
                    ip = host['addresses'].get('ipv4', host['addresses'].get('ipv6', 'unknown'))
                    hostname = host['hostnames'][0]['name'] if host['hostnames'] else ''
                    state = host.get('state', 'up')
                    
                    # Get OS info
                    os_name = ''
                    os_accuracy = 0
                    if host['os'].get('matches'):
                        best_os = max(host['os']['matches'], key=lambda x: x['accuracy'])
                        os_name = best_os['name']
                        os_accuracy = best_os['accuracy']
                    
                    # Get open ports
                    open_ports = [p for p in host['ports'] if p['state'] == 'open']
                    
                    if open_ports:
                        # Write one row per port
                        for port in open_ports:
                            # Find any security issues for this port
                            issues = []
                            for issue in self.data['insights']['potential_issues']:
                                if issue['host'] == ip and issue['port'] == port['port']:
                                    issues.append(issue)
                            
                            if issues:
                                # Write one row per issue
                                for issue in issues:
                                    writer.writerow({
                                        'ip_address': ip,
                                        'hostname': hostname,
                                        'state': state,
                                        'os': os_name,
                                        'os_accuracy': os_accuracy,
                                        'port': port['port'],
                                        'protocol': port['protocol'],
                                        'service': port['service'].get('name', 'unknown'),
                                        'product': port['service'].get('product', ''),
                                        'version': port['service'].get('version', ''),
                                        'severity': issue['severity'],
                                        'issue': issue['issue'],
                                        'risk_score': self._calculate_port_risk_score(port, issue)
                                    })
                            else:
                                # No issues for this port
                                writer.writerow({
                                    'ip_address': ip,
                                    'hostname': hostname,
                                    'state': state,
                                    'os': os_name,
                                    'os_accuracy': os_accuracy,
                                    'port': port['port'],
                                    'protocol': port['protocol'],
                                    'service': port['service'].get('name', 'unknown'),
                                    'product': port['service'].get('product', ''),
                                    'version': port['service'].get('version', ''),
                                    'severity': '',
                                    'issue': '',
                                    'risk_score': self._calculate_port_risk_score(port, None)
                                })
                    else:
                        # Host with no open ports
                        writer.writerow({
                            'ip_address': ip,
                            'hostname': hostname,
                            'state': state,
                            'os': os_name,
                            'os_accuracy': os_accuracy,
                            'port': '',
                            'protocol': '',
                            'service': '',
                            'product': '',
                            'version': '',
                            'severity': '',
                            'issue': '',
                            'risk_score': 0
                        })
                
                # Add summary rows at the end
                writer.writerow({})  # Empty row
                writer.writerow({
                    'ip_address': 'SUMMARY',
                    'hostname': f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                    'state': '',
                    'os': '',
                    'os_accuracy': '',
                    'port': '',
                    'protocol': '',
                    'service': '',
                    'product': '',
                    'version': '',
                    'severity': '',
                    'issue': '',
                    'risk_score': ''
                })
                
                insights = self.data['insights']
                writer.writerow({
                    'ip_address': 'Total Hosts',
                    'hostname': str(insights['total_hosts']),
                    'state': 'Hosts Up',
                    'os': str(insights['hosts_up']),
                    'os_accuracy': '',
                    'port': 'Open Ports',
                    'protocol': str(insights['total_open_ports']),
                    'service': 'Security Issues',
                    'product': str(len(insights['potential_issues'])),
                    'version': '',
                    'severity': '',
                    'issue': '',
                    'risk_score': ''
                })
            
            print(f"✅ CSV report generated: {output_file}")
            return True
            
        except Exception as e:
            print(f"❌ Error generating CSV report: {e}")
            return False
    
    def _calculate_port_risk_score(self, port, issue=None):
        """Calculate risk score for a port/service"""
        score = 0
        
        # Base score by port number
        risky_ports = {
            21: 30,    # FTP
            22: 5,     # SSH (low risk if properly secured)
            23: 50,    # Telnet
            25: 20,    # SMTP
            53: 10,    # DNS
            80: 15,    # HTTP
            110: 20,   # POP3
            111: 25,   # RPC
            135: 30,   # Windows RPC
            139: 30,   # NetBIOS
            143: 20,   # IMAP
            443: 5,    # HTTPS (low risk)
            445: 35,   # SMB
            1433: 40,  # MSSQL
            3306: 40,  # MySQL
            3389: 30,  # RDP
            5432: 40,  # PostgreSQL
            5900: 35,  # VNC
            8080: 15,  # HTTP Alt
            8443: 5,   # HTTPS Alt
        }
        
        score += risky_ports.get(port['port'], 10)
        
        # Adjust by service
        service_name = port['service'].get('name', '').lower()
        if 'telnet' in service_name:
            score += 40
        elif 'ftp' in service_name:
            score += 20
        elif 'vnc' in service_name:
            score += 30
        elif 'smb' in service_name or 'netbios' in service_name:
            score += 20
        elif 'http' in service_name and 'https' not in service_name:
            score += 10
        
        # Add issue severity if present
        if issue:
            if issue['severity'] == 'high':
                score += 50
            elif issue['severity'] == 'medium':
                score += 25
        
        # Cap at 100
        return min(score, 100)
    
    def open_report(self, filepath):
        """Cross-platform method to open HTML report in default browser"""
        file_url = filepath.absolute().as_uri()
        
        # Always display the clickable link first
        print(f"\n✨ HTML Report Ready!")
        print(f"📎 Click here to open: {file_url}")
        print(f"   (Ctrl+Click or Cmd+Click in most terminals)")
        
        try:
            if platform.system() == 'Darwin':       # macOS
                subprocess.call(['open', file_url])
            elif platform.system() == 'Windows':    # Windows
                os.startfile(str(filepath))
            else:                                   # Linux/Unix
                # Try multiple methods for better compatibility
                try:
                    subprocess.call(['xdg-open', file_url])
                except:
                    # Fallback to webbrowser module
                    webbrowser.open(file_url)
            
            print(f"🌐 Report opened in browser: {filepath.name}")
            return True
        except Exception as e:
            print(f"⚠️  Could not auto-open report: {e}")
            print(f"💡 Please click the link above to open the report manually")
            return False
    
    def generate_html_report(self, output_file, auto_open=True):
        """Generate comprehensive HTML report with enhanced features"""
        if not self.data:
            print("❌ No data loaded")
            return False
        
        # Create enhanced HTML template
        html_template = self._get_enhanced_html_template()
        
        # Prepare data for template
        template_data = self._prepare_template_data()
        
        # Add scan metadata for quick rescan
        template_data['scan_metadata'] = self._extract_scan_metadata()
        
        # Render template
        template = Template(html_template)
        html_content = template.render(**template_data)
        
        # Write to file
        output_path = Path(output_file)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ HTML report generated: {output_file}")
        
        # Auto-open report if requested
        if auto_open:
            time.sleep(0.5)  # Small delay to ensure file is written
            self.open_report(output_path)
        else:
            # Still show the clickable link even if not auto-opening
            file_url = output_path.absolute().as_uri()
            print(f"\n📎 View report: {file_url}")
            print(f"   (Ctrl+Click or Cmd+Click in most terminals)")
        
        return True
    
    def generate_text_report(self, output_file):
        """Generate enhanced text report with progress indicators"""
        if not self.data:
            print("❌ No data loaded")
            return False
        
        # Show progress for large datasets
        total_hosts = len(self.data['hosts'])
        
        report_lines = []
        report_lines.append("═" * 80)
        report_lines.append("NETWORK SECURITY ANALYSIS REPORT")
        report_lines.append("═" * 80)
        report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Scanner: {self.data['scan_info'].get('scanner', 'nmap')}")
        report_lines.append(f"Command: {self.data['scan_info'].get('command_line', 'N/A')}")
        report_lines.append("")
        
        # Executive Summary with visual indicators
        insights = self.data['insights']
        report_lines.append("📊 EXECUTIVE SUMMARY")
        report_lines.append("─" * 30)
        report_lines.append(f"🖥️  Total Hosts Scanned: {insights['total_hosts']}")
        report_lines.append(f"✅ Hosts Online: {insights['hosts_up']}")
        report_lines.append(f"🔓 Total Open Ports: {insights['total_open_ports']}")
        report_lines.append(f"⚙️  Unique Services: {len(insights['unique_services'])}")
        
        # Security summary with severity indicators
        high_issues = sum(1 for i in insights['potential_issues'] if i['severity'] == 'high')
        med_issues = sum(1 for i in insights['potential_issues'] if i['severity'] == 'medium')
        
        if high_issues > 0:
            report_lines.append(f"🔴 Critical Security Issues: {high_issues}")
        if med_issues > 0:
            report_lines.append(f"🟡 Medium Security Issues: {med_issues}")
        if high_issues == 0 and med_issues == 0:
            report_lines.append("🟢 No major security issues detected")
        report_lines.append("")
        
        # Security Issues with categorization
        if insights['potential_issues']:
            report_lines.append("🔒 SECURITY ANALYSIS")
            report_lines.append("─" * 30)
            
            # Group issues by category
            issues_by_category = self._categorize_security_issues(insights['potential_issues'])
            
            for category, issues in issues_by_category.items():
                report_lines.append(f"\n▶ {category} ({len(issues)} issues)")
                for issue in issues:
                    severity_icon = "🔴" if issue['severity'] == 'high' else "🟡"
                    report_lines.append(f"  {severity_icon} {issue['host']}:{issue['port']} - {issue['issue']}")
            report_lines.append("")
        
        # Service Distribution with ASCII chart
        if insights['unique_services']:
            report_lines.append("📡 SERVICE DISTRIBUTION")
            report_lines.append("─" * 30)
            service_count = Counter()
            for host in self.data['hosts']:
                for port in host['ports']:
                    if port['state'] == 'open':
                        service_count[port['service'].get('name', 'unknown')] += 1
            
            max_count = max(service_count.values()) if service_count else 1
            for service, count in service_count.most_common():
                bar_length = int((count / max_count) * 30)
                bar = "█" * bar_length
                report_lines.append(f"{service:15s} {bar} {count}")
            report_lines.append("")
        
        # OS Distribution
        if insights['os_distribution']:
            report_lines.append("💻 OPERATING SYSTEMS")
            report_lines.append("─" * 30)
            for os_name, count in insights['os_distribution'].items():
                report_lines.append(f"  • {os_name}: {count} hosts")
            report_lines.append("")
        
        # Host Details with progress indicator
        report_lines.append("🖥️  HOST DETAILS")
        report_lines.append("─" * 30)
        
        for i, host in enumerate(self.data['hosts'], 1):
            # Show progress for large scans
            if total_hosts > 10 and i % 5 == 0:
                print(f"  Processing host {i}/{total_hosts}...", end='\r')
            
            ip = host['addresses'].get('ipv4', host['addresses'].get('ipv6', 'unknown'))
            hostname = host['hostnames'][0]['name'] if host['hostnames'] else 'No hostname'
            
            report_lines.append(f"\n📍 Host: {ip} ({hostname})")
            
            # OS Information with confidence
            if host['os'].get('matches'):
                best_match = max(host['os']['matches'], key=lambda x: x['accuracy'])
                if best_match['accuracy'] > 70:
                    confidence_icon = "🟢" if best_match['accuracy'] > 90 else "🟡"
                    report_lines.append(f"  {confidence_icon} OS: {best_match['name']} ({best_match['accuracy']}% confidence)")
            
            # Open Ports with service details
            open_ports = [p for p in host['ports'] if p['state'] == 'open']
            if open_ports:
                report_lines.append(f"  🔓 Open Ports: {len(open_ports)}")
                
                # Group ports by risk level
                risky_ports = []
                normal_ports = []
                
                for port in open_ports:
                    port_info = self._format_port_info(port)
                    if self._is_risky_port(port):
                        risky_ports.append(("⚠️ ", port_info))
                    else:
                        normal_ports.append(("  ", port_info))
                
                # Show risky ports first
                for prefix, info in risky_ports[:5]:
                    report_lines.append(f"    {prefix}{info}")
                for prefix, info in normal_ports[:5]:
                    report_lines.append(f"    {prefix}{info}")
                
                if len(open_ports) > 10:
                    report_lines.append(f"    ... and {len(open_ports) - 10} more ports")
        
        # Clear progress indicator
        if total_hosts > 10:
            print(" " * 50, end='\r')
        
        # Summary statistics
        report_lines.append("\n" + "═" * 80)
        report_lines.append("📈 SCAN STATISTICS")
        report_lines.append("─" * 30)
        scan_time = self.data['scan_info'].get('elapsed_time', 'Unknown')
        report_lines.append(f"⏱️  Scan Duration: {scan_time}")
        report_lines.append(f"📅 Scan Date: {self.data['scan_info'].get('scan_date', 'Unknown')}")
        
        # Next steps recommendations
        report_lines.append("\n💡 RECOMMENDED NEXT STEPS")
        report_lines.append("─" * 30)
        recommendations = self._generate_recommendations(insights)
        for i, rec in enumerate(recommendations, 1):
            report_lines.append(f"{i}. {rec}")
        
        # Write to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report_lines))
        
        print(f"✅ Text report generated: {output_file}")
        return True
    
    def _extract_scan_metadata(self):
        """Extract scan metadata for quick rescan functionality"""
        scan_info = self.data.get('scan_info', {})
        command = scan_info.get('command_line', '')
        
        # Parse scan type from command
        scan_type = 'comprehensive'
        if '-F' in command:
            scan_type = 'quick'
        elif '-p-' in command:
            scan_type = 'full_tcp'
        elif '-sU' in command:
            scan_type = 'udp_scan'
        elif '--script=vuln' in command:
            scan_type = 'vulnerability_scan'
        elif 'http-*' in command:
            scan_type = 'web_discovery'
        elif '*sql*' in command or '*db*' in command:
            scan_type = 'database_discovery'
        elif '-sS' in command:
            scan_type = 'stealth_scan'
        elif 'everything' in command or 'vuln,http' in command:
            scan_type = 'everything_with_vuln'
        
        # Extract target from hosts
        targets = []
        for host in self.data.get('hosts', []):
            if 'addresses' in host:
                targets.append(host['addresses'].get('ipv4', ''))
        
        # Determine target range
        if targets:
            # Simple logic to determine if it's a range
            first_ip = targets[0]
            if len(targets) > 1:
                target = f"{'.'.join(first_ip.split('.')[:-1])}.0/24"
            else:
                target = first_ip
        else:
            target = "unknown"
        
        # Also get from scan_metadata if available
        if 'scan_metadata' in self.data and 'target' in self.data['scan_metadata']:
            target = self.data['scan_metadata']['target']
        if 'scan_metadata' in self.data and 'scan_type' in self.data['scan_metadata']:
            scan_type = self.data['scan_metadata']['scan_type']
        
        return {
            'scan_type': scan_type,
            'target': target,
            'command': command
        }
    
    def _categorize_security_issues(self, issues):
        """Categorize security issues by type"""
        categories = {
            'Unencrypted Services': [],
            'Database Exposure': [],
            'Remote Access': [],
            'Network Services': [],
            'Web Services': [],
            'Other': []
        }
        
        for issue in issues:
            categorized = False
            issue_text = issue['issue'].lower()
            
            if any(x in issue_text for x in ['unencrypted', 'telnet', 'ftp', 'http service']):
                categories['Unencrypted Services'].append(issue)
                categorized = True
            elif any(x in issue_text for x in ['database', 'mysql', 'postgresql', 'mongodb', 'redis']):
                categories['Database Exposure'].append(issue)
                categorized = True
            elif any(x in issue_text for x in ['rdp', 'vnc', 'ssh']):
                categories['Remote Access'].append(issue)
                categorized = True
            elif any(x in issue_text for x in ['smb', 'netbios', 'snmp']):
                categories['Network Services'].append(issue)
                categorized = True
            elif any(x in issue_text for x in ['web', 'http', 'https']):
                categories['Web Services'].append(issue)
                categorized = True
            
            if not categorized:
                categories['Other'].append(issue)
        
        # Remove empty categories
        return {k: v for k, v in categories.items() if v}
    
    def _format_port_info(self, port):
        """Format port information concisely"""
        service = port['service'].get('name', 'unknown')
        version = port['service'].get('version', '')
        product = port['service'].get('product', '')
        
        info = f"{port['port']}/{port['protocol']}: {service}"
        if product:
            info += f" ({product}"
            if version:
                info += f" {version}"
            info += ")"
        
        return info
    
    def _is_risky_port(self, port):
        """Determine if a port/service combination is risky"""
        risky_services = ['telnet', 'ftp', 'vnc', 'rdp', 'smb', 'netbios-ssn']
        risky_ports = [21, 23, 135, 139, 445, 3389, 5900]
        
        service_name = port['service'].get('name', '').lower()
        return (service_name in risky_services or 
                port['port'] in risky_ports or
                (port['port'] == 80 and 'http' in service_name))
    
    def _generate_recommendations(self, insights):
        """Generate actionable recommendations based on findings"""
        recommendations = []
        
        # Check for critical issues
        high_issues = [i for i in insights['potential_issues'] if i['severity'] == 'high']
        if high_issues:
            recommendations.append("🔴 Address critical security issues immediately")
            
            # Specific recommendations based on issue types
            if any('telnet' in i['issue'].lower() for i in high_issues):
                recommendations.append("🔒 Replace Telnet with SSH for secure remote access")
            if any('ftp' in i['issue'].lower() for i in high_issues):
                recommendations.append("🔒 Replace FTP with SFTP or FTPS for secure file transfer")
            if any('database' in i['issue'].lower() for i in high_issues):
                recommendations.append("🛡️ Restrict database access to specific IP addresses")
        
        # General recommendations
        if insights['total_open_ports'] > 50:
            recommendations.append("🎯 Review and minimize exposed services")
        
        if not insights['os_distribution']:
            recommendations.append("🔍 Run OS detection scan for better visibility")
        
        recommendations.append("📅 Schedule regular security scans (weekly/monthly)")
        recommendations.append("📝 Document all exposed services and their business justification")
        
        return recommendations
    
    def _prepare_template_data(self):
        """Prepare enhanced data for HTML template"""
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
        
        # Risk score calculation
        risk_score = self._calculate_risk_score(insights)
        
        # Categorize issues for better display
        categorized_issues = self._categorize_security_issues(insights['potential_issues'])
        
        return {
            'scan_info': self.data['scan_info'],
            'generated_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'insights': insights,
            'hosts': self.data['hosts'],
            'service_stats': service_stats.most_common(10),
            'port_stats': port_stats.most_common(10),
            'os_stats': os_stats.most_common(),
            'severity_counts': dict(severity_counts),
            'total_issues': len(insights['potential_issues']),
            'risk_score': risk_score,
            'categorized_issues': categorized_issues,
            'recommendations': self._generate_recommendations(insights),
            'scan_metadata': self._extract_scan_metadata()  # Add this line
        }
    
    def _calculate_risk_score(self, insights):
        """Calculate overall network risk score"""
        score = 100  # Start with perfect score
        
        # Deduct for security issues
        high_issues = sum(1 for i in insights['potential_issues'] if i['severity'] == 'high')
        med_issues = sum(1 for i in insights['potential_issues'] if i['severity'] == 'medium')
        
        score -= high_issues * 15  # -15 points per high severity issue
        score -= med_issues * 5    # -5 points per medium severity issue
        
        # Deduct for exposed services
        risky_services = ['telnet', 'ftp', 'vnc', 'rdp', 'smb']
        for service in insights['unique_services']:
            if any(risky in service.lower() for risky in risky_services):
                score -= 5
        
        # Ensure score doesn't go below 0
        score = max(0, score)
        
        # Determine risk level
        if score >= 90:
            return {'score': score, 'level': 'Low', 'color': '#28a745'}
        elif score >= 70:
            return {'score': score, 'level': 'Medium', 'color': '#ffc107'}
        elif score >= 50:
            return {'score': score, 'level': 'High', 'color': '#fd7e14'}
        else:
            return {'score': score, 'level': 'Critical', 'color': '#dc3545'}
    
    def _get_enhanced_html_template(self):
        """Return enhanced HTML template with interactive features"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Security Analysis Report</title>
    <style>
        :root {
            --primary: #667eea;
            --secondary: #764ba2;
            --success: #28a745;
            --danger: #dc3545;
            --warning: #ffc107;
            --info: #17a2b8;
            --dark: #343a40;
            --light: #f8f9fa;
        }

        * { box-sizing: border-box; }
        
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 16px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            color: white;
            padding: 40px;
            position: relative;
            overflow: hidden;
        }

        .header::before {
            content: '';
            position: absolute;
            top: -50%;
            right: -50%;
            width: 200%;
            height: 200%;
            background: repeating-linear-gradient(
                45deg,
                transparent,
                transparent 10px,
                rgba(255,255,255,.05) 10px,
                rgba(255,255,255,.05) 20px
            );
            animation: slide 20s linear infinite;
        }

        @keyframes slide {
            0% { transform: translate(0, 0); }
            100% { transform: translate(50px, 50px); }
        }

        .header-content {
            position: relative;
            z-index: 1;
        }

        .header h1 {
            margin: 0 0 10px 0;
            font-size: 2.5em;
            font-weight: 700;
        }

        .header-meta {
            display: flex;
            gap: 30px;
            margin-top: 20px;
            flex-wrap: wrap;
        }

        .header-meta-item {
            display: flex;
            align-items: center;
            gap: 8px;
            background: rgba(255,255,255,0.2);
            padding: 8px 16px;
            border-radius: 20px;
            backdrop-filter: blur(10px);
        }

        .content {
            padding: 40px;
        }

        .risk-indicator {
            position: absolute;
            top: 40px;
            right: 40px;
            text-align: center;
            background: white;
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            min-width: 150px;
        }

        .risk-score {
            font-size: 3em;
            font-weight: 700;
            margin: 10px 0;
        }

        .risk-level {
            font-size: 1.2em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }

        .summary-card {
            background: var(--light);
            padding: 25px;
            border-radius: 12px;
            position: relative;
            overflow: hidden;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }

        .summary-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.1);
        }

        .summary-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: var(--primary);
        }

        .summary-card.danger::before { background: var(--danger); }
        .summary-card.warning::before { background: var(--warning); }
        .summary-card.success::before { background: var(--success); }
        .summary-card.info::before { background: var(--info); }

        .summary-card h3 {
            margin: 0 0 15px 0;
            color: #6c757d;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .summary-card .value {
            font-size: 2.5em;
            font-weight: 700;
            color: var(--dark);
            line-height: 1;
        }

        .summary-card .subtitle {
            font-size: 0.9em;
            color: #6c757d;
            margin-top: 8px;
        }

        .section {
            margin-bottom: 40px;
            background: var(--light);
            border-radius: 12px;
            padding: 30px;
        }

        .section-title {
            font-size: 1.8em;
            font-weight: 700;
            margin-bottom: 25px;
            color: var(--dark);
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .section-title::after {
            content: '';
            flex: 1;
            height: 2px;
            background: linear-gradient(to right, var(--primary), transparent);
        }

        .alert {
            padding: 16px 20px;
            border-radius: 8px;
            margin-bottom: 12px;
            display: flex;
            align-items: flex-start;
            gap: 12px;
            animation: fadeIn 0.3s ease;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .alert-icon {
            font-size: 1.2em;
            line-height: 1;
        }

        .alert-content {
            flex: 1;
        }

        .alert-high {
            background-color: #fee;
            border: 1px solid #fcc;
            color: var(--danger);
        }

        .alert-medium {
            background-color: #fffbeb;
            border: 1px solid #fed97a;
            color: #8b5d0a;
        }

        .issue-category {
            margin-bottom: 25px;
        }

        .category-header {
            font-weight: 600;
            font-size: 1.1em;
            margin-bottom: 12px;
            color: var(--dark);
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .category-count {
            background: var(--primary);
            color: white;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.8em;
        }

        .quick-actions {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 40px;
            color: white;
        }

        .quick-actions h3 {
            margin: 0 0 20px 0;
            font-size: 1.5em;
        }

        .action-buttons {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }

        .action-button {
            background: rgba(255,255,255,0.2);
            border: 2px solid rgba(255,255,255,0.3);
            color: white;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            backdrop-filter: blur(10px);
        }

        .action-button:hover {
            background: rgba(255,255,255,0.3);
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }

        .host-card {
            background: white;
            border: 1px solid #e9ecef;
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 20px;
            transition: all 0.3s ease;
        }

        .host-card:hover {
            box-shadow: 0 5px 20px rgba(0,0,0,0.08);
            transform: translateY(-2px);
        }

        .host-header {
            font-weight: 700;
            font-size: 1.2em;
            color: var(--dark);
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .host-badge {
            background: var(--info);
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 500;
        }

        .port-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 12px;
            margin-top: 15px;
        }

        .port-item {
            background: var(--light);
            padding: 12px;
            border-radius: 8px;
            border-left: 3px solid var(--success);
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.9em;
            transition: all 0.2s ease;
        }

        .port-item:hover {
            transform: translateX(5px);
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .port-item.risky {
            border-left-color: var(--warning);
            background: #fffbeb;
        }

        .stats-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
        }

        .chart-container {
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }

        .chart-container h4 {
            margin: 0 0 20px 0;
            color: var(--dark);
            font-size: 1.2em;
        }

        .chart-bar {
            margin-bottom: 12px;
        }

        .chart-label {
            display: flex;
            justify-content: space-between;
            margin-bottom: 4px;
            font-size: 0.9em;
        }

        .chart-progress {
            height: 24px;
            background: #e9ecef;
            border-radius: 12px;
            overflow: hidden;
            position: relative;
        }

        .chart-fill {
            height: 100%;
            background: linear-gradient(to right, var(--primary), var(--secondary));
            border-radius: 12px;
            transition: width 1s ease;
            display: flex;
            align-items: center;
            padding: 0 10px;
            color: white;
            font-size: 0.8em;
            font-weight: 600;
        }

        .recommendations {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
            border-radius: 12px;
            padding: 30px;
            margin-top: 40px;
        }

        .recommendations h3 {
            margin: 0 0 20px 0;
            font-size: 1.5em;
        }

        .recommendations ul {
            margin: 0;
            padding: 0;
            list-style: none;
        }

        .recommendations li {
            padding: 12px 0;
            border-bottom: 1px solid rgba(255,255,255,0.2);
            display: flex;
            align-items: flex-start;
            gap: 10px;
        }

        .recommendations li:last-child {
            border-bottom: none;
        }

        .footer {
            text-align: center;
            padding: 40px;
            background: var(--light);
            color: #6c757d;
            border-top: 1px solid #dee2e6;
        }

        .footer code {
            background: #e9ecef;
            padding: 4px 8px;
            border-radius: 4px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.9em;
        }

        /* Responsive */
        @media (max-width: 768px) {
            .header { padding: 30px 20px; }
            .content { padding: 20px; }
            .risk-indicator { position: static; margin-bottom: 20px; }
            .summary-grid { grid-template-columns: 1fr; }
            .stats-container { grid-template-columns: 1fr; }
        }

        /* Print styles */
        @media print {
            body { background: white; }
            .container { box-shadow: none; }
            .quick-actions { display: none; }
            .host-card { break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-content">
                <h1>🛡️ Network Security Analysis Report</h1>
                <div class="header-meta">
                    <div class="header-meta-item">
                        📅 {{ generated_time }}
                    </div>
                    <div class="header-meta-item">
                        🔍 {{ scan_info.scanner }} {{ scan_info.version }}
                    </div>
                    <div class="header-meta-item">
                        ⚡ Scan Type: {{ scan_metadata.scan_type }}
                    </div>
                </div>
            </div>
            <div class="risk-indicator">
                <div>Risk Score</div>
                <div class="risk-score" style="color: {{ risk_score.color }}">{{ risk_score.score }}</div>
                <div class="risk-level" style="color: {{ risk_score.color }}">{{ risk_score.level }}</div>
            </div>
        </div>

        <div class="content">
            <!-- Quick Actions -->
            <div class="quick-actions">
                <h3>🚀 Quick Actions</h3>
                <div class="action-buttons">
                    <button class="action-button" onclick="window.print()">
                        🖨️ Print Report
                    </button>
                    <button class="action-button" onclick="copyRescanCommand()">
                        📋 Copy Rescan Command
                    </button>
                    <button class="action-button" onclick="exportData()">
                        💾 Export Data
                    </button>
                    <button class="action-button" onclick="scrollToIssues()">
                        ⚠️ Jump to Issues
                    </button>
                </div>
            </div>

            <!-- Executive Summary -->
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Total Hosts</h3>
                    <div class="value">{{ insights.total_hosts }}</div>
                    <div class="subtitle">Scanned in network</div>
                </div>
                <div class="summary-card success">
                    <h3>Hosts Online</h3>
                    <div class="value">{{ insights.hosts_up }}</div>
                    <div class="subtitle">{{ ((insights.hosts_up / insights.total_hosts * 100) | round(1)) if insights.total_hosts > 0 else 0 }}% response rate</div>
                </div>
                <div class="summary-card info">
                    <h3>Open Ports</h3>
                    <div class="value">{{ insights.total_open_ports }}</div>
                    <div class="subtitle">Across all hosts</div>
                </div>
                <div class="summary-card warning">
                    <h3>Services Found</h3>
                    <div class="value">{{ insights.unique_services|length }}</div>
                    <div class="subtitle">Unique service types</div>
                </div>
                <div class="summary-card danger">
                    <h3>Security Issues</h3>
                    <div class="value">{{ total_issues }}</div>
                    <div class="subtitle">
                        {% if severity_counts.high %}{{ severity_counts.high }} critical{% endif %}
                        {% if severity_counts.high and severity_counts.medium %}, {% endif %}
                        {% if severity_counts.medium %}{{ severity_counts.medium }} medium{% endif %}
                    </div>
                </div>
            </div>

            <!-- Security Issues -->
            {% if categorized_issues %}
            <div class="section" id="security-issues">
                <div class="section-title">🔒 Security Analysis</div>
                {% for category, issues in categorized_issues.items() %}
                <div class="issue-category">
                    <div class="category-header">
                        {{ category }}
                        <span class="category-count">{{ issues|length }}</span>
                    </div>
                    {% for issue in issues %}
                    <div class="alert alert-{{ issue.severity }}">
                        <div class="alert-icon">
                            {% if issue.severity == 'high' %}🔴{% else %}🟡{% endif %}
                        </div>
                        <div class="alert-content">
                            <strong>{{ issue.host }}:{{ issue.port }}</strong> - {{ issue.issue }}
                            <br><small>Service: {{ issue.service }} | Protocol: TCP</small>
                        </div>
                    </div>
                    {% endfor %}
                </div>
                {% endfor %}
            </div>
            {% endif %}

            <!-- Network Statistics -->
            <div class="section">
                <div class="section-title">📊 Network Statistics</div>
                <div class="stats-container">
                    <div class="chart-container">
                        <h4>Top Services</h4>
                        {% for service, count in service_stats %}
                        <div class="chart-bar">
                            <div class="chart-label">
                                <span>{{ service }}</span>
                                <span>{{ count }}</span>
                            </div>
                            <div class="chart-progress">
                                <div class="chart-fill" style="width: {{ (count / service_stats[0][1] * 100) if service_stats[0][1] > 0 else 0 }}%">
                                    {{ ((count / insights.total_open_ports * 100) | round(1)) if insights.total_open_ports > 0 else 0 }}%
                                </div>
                            </div>
                        </div>
                        {% endfor %}
                    </div>

                    <div class="chart-container">
                        <h4>Common Ports</h4>
                        {% for port, count in port_stats %}
                        <div class="chart-bar">
                            <div class="chart-label">
                                <span>Port {{ port }}</span>
                                <span>{{ count }} hosts</span>
                            </div>
                            <div class="chart-progress">
                                <div class="chart-fill" style="width: {{ (count / port_stats[0][1] * 100) if port_stats[0][1] > 0 else 0 }}%">
                                    {{ ((count / insights.hosts_up * 100) | round(1)) if insights.hosts_up > 0 else 0 }}%
                                </div>
                            </div>
                        </div>
                        {% endfor %}
                    </div>
                </div>

                {% if os_stats %}
                <div class="chart-container" style="margin-top: 30px;">
                    <h4>Operating Systems</h4>
                    {% for os, count in os_stats %}
                    <div class="chart-bar">
                        <div class="chart-label">
                            <span>{{ os }}</span>
                            <span>{{ count }} hosts</span>
                        </div>
                        <div class="chart-progress">
                            <div class="chart-fill" style="width: {{ (count / insights.hosts_up * 100) if insights.hosts_up > 0 else 0 }}%">
                                {{ ((count / insights.hosts_up * 100) | round(1)) if insights.hosts_up > 0 else 0 }}%
                            </div>
                        </div>
                    </div>
                    {% endfor %}
                </div>
                {% endif %}
            </div>

            <!-- Host Details -->
            <div class="section">
                <div class="section-title">🖥️ Host Details</div>
                {% for host in hosts %}
                <div class="host-card">
                    <div class="host-header">
                        <span>
                            {{ host.addresses.ipv4 or host.addresses.ipv6 or 'Unknown IP' }}
                            {% if host.hostnames %}
                                ({{ host.hostnames[0].name }})
                            {% endif %}
                        </span>
                        {% if host.os.matches %}
                            {% set best_os = host.os.matches|max(attribute='accuracy') %}
                            {% if best_os.accuracy > 70 %}
                            <span class="host-badge">{{ best_os.name }}</span>
                            {% endif %}
                        {% endif %}
                    </div>

                    {% set open_ports = host.ports|selectattr('state', 'equalto', 'open')|list %}
                    {% if open_ports %}
                    <div>
                        <strong>Open Ports ({{ open_ports|length }}):</strong>
                        <div class="port-grid">
                            {% for port in open_ports %}
                            {% set is_risky = port.port in [21, 23, 135, 139, 445, 3389, 5900] or port.service.name in ['telnet', 'ftp', 'vnc'] %}
                            <div class="port-item {% if is_risky %}risky{% endif %}">
                                <strong>{{ port.port }}/{{ port.protocol }}</strong> - {{ port.service.name or 'unknown' }}
                                {% if port.service.product %}
                                    <br>{{ port.service.product }}
                                    {% if port.service.version %}v{{ port.service.version }}{% endif %}
                                {% endif %}
                            </div>
                            {% endfor %}
                        </div>
                    </div>
                    {% endif %}
                </div>
                {% endfor %}
            </div>

            <!-- Recommendations -->
            <div class="recommendations">
                <h3>💡 Recommendations</h3>
                <ul>
                    {% for rec in recommendations %}
                    <li>
                        <span>{{ loop.index }}.</span>
                        <span>{{ rec }}</span>
                    </li>
                    {% endfor %}
                </ul>
            </div>
        </div>

        <div class="footer">
            <p>Generated by Network Security Scanner | Powered by Nmap</p>
            <p><code>{{ scan_info.command_line }}</code></p>
        </div>
    </div>

    <script>
        // Animation for progress bars
        window.addEventListener('load', function() {
            const fills = document.querySelectorAll('.chart-fill');
            fills.forEach(fill => {
                const width = fill.style.width;
                fill.style.width = '0';
                setTimeout(() => {
                    fill.style.width = width;
                }, 100);
            });
        });

        // Copy rescan command
        function copyRescanCommand() {
            const command = `python3 pipeline.py {{ scan_metadata.target }} -t {{ scan_metadata.scan_type }}`;
            navigator.clipboard.writeText(command).then(() => {
                alert('Rescan command copied to clipboard!\\n\\n' + command);
            });
        }

        // Scroll to security issues
        function scrollToIssues() {
            const element = document.getElementById('security-issues');
            if (element) {
                element.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        }

        // Export data (simplified version)
        function exportData() {
            const data = {
                scan_date: '{{ generated_time }}',
                risk_score: {{ risk_score.score }},
                total_hosts: {{ insights.total_hosts }},
                hosts_up: {{ insights.hosts_up }},
                open_ports: {{ insights.total_open_ports }},
                security_issues: {{ total_issues }}
            };
            
            const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'network_scan_summary.json';
            a.click();
        }

        // Auto-refresh notification (for demo)
        setTimeout(() => {
            console.log('Report generated successfully at {{ generated_time }}');
        }, 1000);
    </script>
</body>
</html>
        """

def show_progress_animation(message, duration=2):
    """Show a simple progress animation"""
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    end_time = time.time() + duration
    i = 0
    
    while time.time() < end_time:
        print(f"\r{frames[i % len(frames)]} {message}", end="", flush=True)
        time.sleep(0.1)
        i += 1
    
    print(f"\r✓ {message}")

def main():
    parser = argparse.ArgumentParser(description="Generate enhanced network scan reports")
    parser.add_argument("json_file", help="Path to parsed JSON file")
    parser.add_argument("-o", "--output", default="output/reports",
                       help="Output directory")
    parser.add_argument("--format", choices=["html", "text", "csv", "all"], default="all",
                       help="Report format")
    parser.add_argument("--no-open", action="store_true",
                       help="Don't auto-open HTML report")
    parser.add_argument("--template", help="Custom HTML template file")
    
    args = parser.parse_args()
    
    print("🚀 Network Report Generator - Enhanced Edition")
    print("=" * 60)
    
    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Load data and generate reports
    generator = ReportGenerator()
    
    show_progress_animation("Loading scan data", 1)
    
    if not generator.load_data(args.json_file):
        sys.exit(1)
    
    # Generate output filename base
    json_path = Path(args.json_file)
    base_name = json_path.stem.replace('_parsed', '')
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    success = True
    
    if args.format in ["html", "all"]:
        show_progress_animation("Generating HTML report", 1.5)
        html_file = output_dir / f"{base_name}_report_{timestamp}.html"
        success = generator.generate_html_report(html_file, auto_open=not args.no_open)
    
    if args.format in ["text", "all"]:
        show_progress_animation("Generating text report", 1)
        text_file = output_dir / f"{base_name}_report_{timestamp}.txt"
        success = success and generator.generate_text_report(text_file)
    
    if args.format in ["csv", "all"]:
        show_progress_animation("Generating CSV report", 1)
        csv_file = output_dir / f"{base_name}_report_{timestamp}.csv"
        success = success and generator.generate_csv_report(csv_file)
    
    if success:
        print("\n" + "=" * 60)
        print("✅ Report generation complete!")
        print(f"📁 Reports saved in: {output_dir}")
        print("=" * 60)
    else:
        print("\n❌ Report generation failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
