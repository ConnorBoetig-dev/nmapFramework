#!/usr/bin/env python3
"""
Nmap XML Parser
Extracts actionable insights from nmap XML output files
"""

import xml.etree.ElementTree as ET
import json
import csv
import argparse
import sys
from pathlib import Path
from collections import defaultdict
import ipaddress

class NmapXMLParser:
    def __init__(self):
        self.hosts = []
        self.services = defaultdict(list)
        self.os_matches = {}
        self.open_ports = defaultdict(list)
        self.insights = {
            'total_hosts': 0,
            'hosts_up': 0,
            'total_open_ports': 0,
            'unique_services': set(),
            'potential_issues': [],
            'service_versions': {},
            'os_distribution': defaultdict(int)
        }
    
    def parse_xml(self, xml_file):
        """Parse nmap XML file and extract all relevant information"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
        except ET.ParseError as e:
            print(f"Error parsing XML file: {e}")
            return False
        except FileNotFoundError:
            print(f"File not found: {xml_file}")
            return False
        
        # Extract scan info
        self.scan_info = {
            'scanner': root.get('scanner', 'nmap'),
            'version': root.get('version', 'unknown'),
            'start_time': root.get('startstr', 'unknown'),
            'command_line': root.get('args', 'unknown')
        }
        
        # Parse each host
        for host in root.findall('host'):
            host_data = self._parse_host(host)
            if host_data:
                self.hosts.append(host_data)
        
        self._generate_insights()
        return True
    
    def _parse_host(self, host_elem):
        """Parse individual host information"""
        # Get host state
        status = host_elem.find('status')
        if status is None or status.get('state') != 'up':
            return None
        
        host_data = {
            'state': 'up',
            'addresses': {},
            'hostnames': [],
            'ports': [],
            'os': {},
            'uptime': None
        }
        
        # Extract addresses
        for addr in host_elem.findall('address'):
            addr_type = addr.get('addrtype')
            addr_value = addr.get('addr')
            host_data['addresses'][addr_type] = addr_value
        
        # Extract hostnames
        hostnames_elem = host_elem.find('hostnames')
        if hostnames_elem is not None:
            for hostname in hostnames_elem.findall('hostname'):
                host_data['hostnames'].append({
                    'name': hostname.get('name'),
                    'type': hostname.get('type')
                })
        
        # Extract port information
        ports_elem = host_elem.find('ports')
        if ports_elem is not None:
            for port in ports_elem.findall('port'):
                port_data = self._parse_port(port)
                if port_data:
                    host_data['ports'].append(port_data)
        
        # Extract OS information
        os_elem = host_elem.find('os')
        if os_elem is not None:
            host_data['os'] = self._parse_os(os_elem)
        
        # Extract uptime
        uptime_elem = host_elem.find('uptime')
        if uptime_elem is not None:
            host_data['uptime'] = {
                'seconds': uptime_elem.get('seconds'),
                'lastboot': uptime_elem.get('lastboot')
            }
        
        return host_data
    
    def _parse_port(self, port_elem):
        """Parse port information"""
        state_elem = port_elem.find('state')
        if state_elem is None or state_elem.get('state') != 'open':
            return None
        
        port_data = {
            'port': int(port_elem.get('portid')),
            'protocol': port_elem.get('protocol'),
            'state': state_elem.get('state'),
            'reason': state_elem.get('reason'),
            'service': {}
        }
        
        # Extract service information
        service_elem = port_elem.find('service')
        if service_elem is not None:
            port_data['service'] = {
                'name': service_elem.get('name', 'unknown'),
                'product': service_elem.get('product', ''),
                'version': service_elem.get('version', ''),
                'extrainfo': service_elem.get('extrainfo', ''),
                'ostype': service_elem.get('ostype', ''),
                'method': service_elem.get('method', ''),
                'conf': service_elem.get('conf', '')
            }
        
        return port_data
    
    def _parse_os(self, os_elem):
        """Parse OS detection information"""
        os_data = {'matches': [], 'ports_used': []}
        
        # Parse OS matches
        for osmatch in os_elem.findall('osmatch'):
            match_data = {
                'name': osmatch.get('name'),
                'accuracy': int(osmatch.get('accuracy', 0)),
                'line': osmatch.get('line', ''),
                'classes': []
            }
            
            for osclass in osmatch.findall('osclass'):
                class_data = {
                    'type': osclass.get('type'),
                    'vendor': osclass.get('vendor'),
                    'osfamily': osclass.get('osfamily'),
                    'osgen': osclass.get('osgen'),
                    'accuracy': int(osclass.get('accuracy', 0))
                }
                match_data['classes'].append(class_data)
            
            os_data['matches'].append(match_data)
        
        return os_data
    
    def _generate_insights(self):
        """Generate actionable insights from parsed data"""
        self.insights['total_hosts'] = len(self.hosts)
        self.insights['hosts_up'] = len([h for h in self.hosts if h['state'] == 'up'])
        
        # Analyze ports and services
        for host in self.hosts:
            ip = host['addresses'].get('ipv4', host['addresses'].get('ipv6', 'unknown'))
            
            for port in host['ports']:
                if port['state'] == 'open':
                    self.insights['total_open_ports'] += 1
                    service_name = port['service'].get('name', 'unknown')
                    self.insights['unique_services'].add(service_name)
                    
                    # Track service versions
                    service_key = f"{service_name}:{port['port']}"
                    version = port['service'].get('version', 'unknown')
                    if service_key not in self.insights['service_versions']:
                        self.insights['service_versions'][service_key] = []
                    self.insights['service_versions'][service_key].append({
                        'host': ip,
                        'version': version,
                        'product': port['service'].get('product', '')
                    })
                    
                    # Check for potential security issues
                    self._check_security_issues(ip, port)
            
            # Analyze OS information
            if host['os'].get('matches'):
                best_match = max(host['os']['matches'], key=lambda x: x['accuracy'])
                if best_match['accuracy'] > 70:
                    os_name = best_match['name']
                    self.insights['os_distribution'][os_name] += 1
        
        # Convert set to list for JSON serialization
        self.insights['unique_services'] = list(self.insights['unique_services'])
    
    def _check_security_issues(self, ip, port):
        """Identify potential security issues"""
        service = port['service'].get('name', '').lower()
        port_num = port['port']
        
        # Common security concerns
        security_checks = {
            'telnet': "Unencrypted remote access protocol detected",
            'ftp': "Unencrypted file transfer protocol detected", 
            'http': "Unencrypted web service detected",
            'snmp': "SNMP service detected - check community strings",
            'ssh': "SSH service detected - ensure strong authentication",
            'rdp': "RDP service detected - ensure secure configuration",
            'smb': "SMB service detected - check for vulnerabilities",
            'mysql': "MySQL database exposed",
            'postgresql': "PostgreSQL database exposed",
            'mongodb': "MongoDB database exposed"
        }
        
        # Port-based checks
        risky_ports = {
            21: "FTP - Unencrypted file transfer",
            23: "Telnet - Unencrypted remote access",
            53: "DNS - Potential amplification attacks",
            135: "RPC - Windows service, potential attack vector",
            139: "NetBIOS - Windows file sharing",
            445: "SMB - Windows file sharing, high-risk",
            1433: "MSSQL - Database server exposed",
            3389: "RDP - Remote desktop access",
            5432: "PostgreSQL - Database server exposed",
            27017: "MongoDB - Database server exposed"
        }
        
        if service in security_checks:
            self.insights['potential_issues'].append({
                'host': ip,
                'port': port_num,
                'service': service,
                'issue': security_checks[service],
                'severity': 'medium'
            })
        
        if port_num in risky_ports:
            self.insights['potential_issues'].append({
                'host': ip,
                'port': port_num,
                'service': service,
                'issue': risky_ports[port_num],
                'severity': 'high'
            })
    
    def export_to_json(self, output_file):
        """Export parsed data to JSON"""
        data = {
            'scan_info': self.scan_info,
            'hosts': self.hosts,
            'insights': self.insights
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        print(f"Data exported to JSON: {output_file}")
    
    def export_to_csv(self, output_dir):
        """Export parsed data to CSV files"""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Export hosts summary
        hosts_file = output_dir / "hosts_summary.csv"
        with open(hosts_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['IP', 'Hostname', 'OS', 'Open_Ports', 'Services'])
            
            for host in self.hosts:
                ip = host['addresses'].get('ipv4', host['addresses'].get('ipv6', 'unknown'))
                hostname = host['hostnames'][0]['name'] if host['hostnames'] else ''
                os_name = ''
                if host['os'].get('matches'):
                    best_match = max(host['os']['matches'], key=lambda x: x['accuracy'])
                    os_name = best_match['name'] if best_match['accuracy'] > 70 else ''
                
                open_ports = [str(p['port']) for p in host['ports'] if p['state'] == 'open']
                services = [p['service']['name'] for p in host['ports'] if p['state'] == 'open']
                
                writer.writerow([ip, hostname, os_name, ','.join(open_ports), ','.join(services)])
        
        # Export detailed port information
        ports_file = output_dir / "ports_detailed.csv"
        with open(ports_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['IP', 'Port', 'Protocol', 'Service', 'Version', 'Product'])
            
            for host in self.hosts:
                ip = host['addresses'].get('ipv4', host['addresses'].get('ipv6', 'unknown'))
                for port in host['ports']:
                    if port['state'] == 'open':
                        writer.writerow([
                            ip, port['port'], port['protocol'],
                            port['service'].get('name', ''),
                            port['service'].get('version', ''),
                            port['service'].get('product', '')
                        ])
        
        print(f"CSV files exported to: {output_dir}")

def main():
    parser = argparse.ArgumentParser(description="Parse Nmap XML results")
    parser.add_argument("xml_file", help="Path to nmap XML file")
    parser.add_argument("-o", "--output", default="output/processed",
                       help="Output directory")
    parser.add_argument("--format", choices=["json", "csv", "both"], default="both",
                       help="Output format")
    
    args = parser.parse_args()
    
    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Parse XML file
    parser_obj = NmapXMLParser()
    if not parser_obj.parse_xml(args.xml_file):
        sys.exit(1)
    
    # Generate output filename base
    xml_path = Path(args.xml_file)
    base_name = xml_path.stem
    
    # Export data
    if args.format in ["json", "both"]:
        json_file = output_dir / f"{base_name}_parsed.json"
        parser_obj.export_to_json(json_file)
    
    if args.format in ["csv", "both"]:
        csv_dir = output_dir / f"{base_name}_csv"
        parser_obj.export_to_csv(csv_dir)
        
        # Also organize CSVs in reports directory
        reports_csv_dir = Path("output/reports/csv") / base_name
        reports_csv_dir.mkdir(parents=True, exist_ok=True)
        
        import shutil
        if csv_dir.exists():
            for csv_file in csv_dir.glob("*.csv"):
                shutil.copy2(csv_file, reports_csv_dir / csv_file.name)
            print(f"📊 CSV files also copied to: {reports_csv_dir}")
    
    # Print summary
    print(f"\nScan Summary:")
    print(f"Total hosts scanned: {parser_obj.insights['total_hosts']}")
    print(f"Hosts up: {parser_obj.insights['hosts_up']}")
    print(f"Total open ports: {parser_obj.insights['total_open_ports']}")
    print(f"Unique services: {len(parser_obj.insights['unique_services'])}")
    print(f"Potential security issues: {len(parser_obj.insights['potential_issues'])}")

if __name__ == "__main__":
    main()
