#!/usr/bin/env python3
"""
Automated Nmap Scanner - Enhanced Version
Performs comprehensive network scans with advanced security analysis
"""

import nmap
import argparse
import os
import sys
import json
import datetime
from pathlib import Path

class NetworkScanner:
    def __init__(self, output_dir="output/xml/raw"):
        self.nm = nmap.PortScanner()
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def scan_network(self, targets, scan_type="comprehensive", timing=3):
        """
        Perform network scan with specified parameters
        
        Args:
            targets (str): Target IP range or single IP
            scan_type (str): Type of scan to perform
            timing (int): Timing template (0-5, 5 is fastest)
        """
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Define scan configurations - Enhanced with advanced scan types
        scan_configs = {
            "quick": {
                "arguments": f"-T{timing} -F --version-intensity 0",
                "description": "Quick scan - top 100 ports",
                "estimated_time": "1-2 minutes"
            },
            "comprehensive": {
                "arguments": f"-T{timing} -sT -sV -A --version-intensity 5",
                "description": "Comprehensive scan - service detection (TCP connect, no root needed)",
                "estimated_time": "5-10 minutes"
            },
            "comprehensive_root": {
                "arguments": f"-T{timing} -sS -sV -O -A --version-intensity 5",
                "description": "Comprehensive scan with SYN stealth and OS detection (requires root)",
                "estimated_time": "5-10 minutes"
            },
            "full_tcp": {
                "arguments": f"-T{timing} -sT -sV -p- --version-intensity 3",
                "description": "Full TCP port scan with service detection (all 65535 ports, no root)",
                "estimated_time": "15-30 minutes"
            },
            "full_tcp_root": {
                "arguments": f"-T{timing} -sS -sV -p- --version-intensity 3",
                "description": "Full TCP port scan with SYN stealth (requires root)",
                "estimated_time": "15-30 minutes"
            },
            "udp_top": {
                "arguments": f"-T{timing} -sU --top-ports 1000 -sV",
                "description": "Top 1000 UDP ports with service detection (requires root for UDP)",
                "estimated_time": "10-20 minutes"
            },
            "udp_scan": {
                "arguments": f"-T{timing} -sU --top-ports 100 -sV",
                "description": "UDP port scan for top 100 ports (requires root)",
                "estimated_time": "10-20 minutes"
            },
            "discovery": {
                "arguments": f"-T{timing} -sn",
                "description": "Host discovery only - ping sweep",
                "estimated_time": "30 seconds - 2 minutes"
            },
            "full_comprehensive": {
                "arguments": f"-T{timing} -sT -sV -A --script=default,discovery,safe --top-ports 2000",
                "description": "Complete TCP scan with all safe scripts (no root needed)",
                "estimated_time": "20-45 minutes"
            },
            "full_comprehensive_root": {
                "arguments": f"-T{timing} -sS -sU -sV -O -A --script=default,discovery,safe --top-ports 2000",
                "description": "Complete TCP/UDP scan with all safe scripts (requires root)",
                "estimated_time": "20-45 minutes"
            },
            "vulnerability_scan": {
                "arguments": f"-T{timing} -sT -sV --script=vuln --top-ports 2000 --version-intensity 7",
                "description": "Focused vulnerability detection (no root needed)",
                "estimated_time": "15-25 minutes"
            },
            "stealth_comprehensive": {
                "arguments": f"-T{timing} -sS -sV -O --script=default,safe -f --randomize-hosts --source-port 443",
                "description": "Stealth comprehensive scan with fragmentation (requires root)",
                "estimated_time": "10-20 minutes"
            },
            "stealth_scan": {
                "arguments": f"-T2 -sS -sV -f --randomize-hosts --source-port 443",
                "description": "Stealthy half-open scan (requires root)",
                "estimated_time": "5-10 minutes"
            },
            "web_discovery": {
                "arguments": f"-T{timing} -sT -sV --script=http-*,ssl-*,tls-* -p 80,443,8080,8443,8000,8888,9000",
                "description": "Web application and SSL/TLS discovery",
                "estimated_time": "5-10 minutes"
            },
            "database_discovery": {
                "arguments": f"-T{timing} -sT -sV --script=*sql*,*db*,oracle-*,mongodb-* -p 1433,3306,5432,27017,1521,6379",
                "description": "Database service discovery and basic enumeration",
                "estimated_time": "3-8 minutes"
            },
            "smb_discovery": {
                "arguments": f"-T{timing} -sT -sV --script=smb-*,netbios-* -p 135,139,445,137",
                "description": "SMB/NetBIOS discovery and enumeration",
                "estimated_time": "3-7 minutes"
            },
            "everything_novuln": {
                "arguments": f"-T{timing} -sT -sV -A -p- --script=default,discovery,safe,http-*,ssl-*,*sql*,*db*",
                "description": "Complete scan: Discovery + Quick + Comprehensive + Full TCP + Web + DB",
                "estimated_time": "20-40 minutes"
            },
            "everything_withvuln": {
                "arguments": f"-T{timing} -sT -sV -A -p- --script=default,discovery,safe,vuln,http-*,ssl-*,*sql*,*db*",
                "description": "Ultimate scan: Everything + Vulnerability detection",
                "estimated_time": "30-60 minutes"
            },
            "top_1000_intense": {
                "arguments": f"-T4 -sT -sV -A --top-ports 1000 --version-intensity 9",
                "description": "Top 1000 ports with aggressive service detection",
                "estimated_time": "5-10 minutes"
            },
            "max_intensity": {
                "arguments": f"-T{timing} -sS -sU -sV -O -A --script=all --version-intensity 9 -p- --min-rate 1000",
                "description": "Maximum intensity scan - all ports, all scripts (requires root)",
                "estimated_time": "45-120 minutes"
            },
            "max_intensity_noroot": {
                "arguments": f"-T{timing} -sT -sV -A --script=safe,default,discovery --version-intensity 9 --top-ports 5000",
                "description": "Maximum intensity scan without root - TCP connect scan",
                "estimated_time": "25-60 minutes"
            },
            "custom_ports": {
                "arguments": f"-T{timing} -sT -sV --script=default,safe",
                "description": "Custom port range scan (specify with --ports argument)",
                "estimated_time": "Variable"
            }
        }
        
        if scan_type not in scan_configs:
            print(f"Unknown scan type: {scan_type}")
            print(f"Available types:")
            for scan_name, config in scan_configs.items():
                print(f"  {scan_name:<25} - {config['description']}")
                print(f"                          Estimated time: {config['estimated_time']}")
            return None
            
        config = scan_configs[scan_type]
        output_file = self.output_dir / f"scan_{scan_type}_{timestamp}.xml"
        
        print(f"\U0001f3af Starting {config['description']}...")
        print(f"\U0001f4e1 Target: {targets}")
        print(f"\u2699\ufe0f  Arguments: {config['arguments']}")
        print(f"\u23f1\ufe0f  Estimated time: {config['estimated_time']}")
        print(f"\U0001f4c1 Output: {output_file}")
        print("=" * 60)
        
        try:
            # Perform the scan
            self.nm.scan(
                hosts=targets,
                arguments=config['arguments']
            )
            
            # Save XML output manually with better encoding handling
            xml_output = self.nm.get_nmap_last_output()
            with open(output_file, 'w', encoding='utf-8') as f:
                if isinstance(xml_output, bytes):
                    f.write(xml_output.decode('utf-8', errors='replace'))
                else:
                    f.write(xml_output)
            
            # Enhanced scan summary with more details
            hosts_up = [h for h in self.nm.all_hosts() if self.nm[h].state() == 'up']
            total_ports = 0
            open_ports = 0
            
            for host in hosts_up:
                for protocol in self.nm[host].all_protocols():
                    ports = self.nm[host][protocol].keys()
                    total_ports += len(ports)
                    open_ports += len([p for p in ports if self.nm[host][protocol][p]['state'] == 'open'])
            
            scan_summary = {
                "timestamp": timestamp,
                "scan_type": scan_type,
                "targets": targets,
                "arguments": config['arguments'],
                "description": config['description'],
                "estimated_time": config['estimated_time'],
                "xml_file": str(output_file),
                "hosts_scanned": len(self.nm.all_hosts()),
                "hosts_up": len(hosts_up),
                "total_ports_scanned": total_ports,
                "open_ports_found": open_ports,
                "scan_stats": {
                    "elapsed_time": self.nm.scanstats().get('elapsed', 'Unknown'),
                    "up_hosts": self.nm.scanstats().get('uphosts', 'Unknown'),
                    "down_hosts": self.nm.scanstats().get('downhosts', 'Unknown')
                }
            }
            
            summary_file = self.output_dir / f"summary_{scan_type}_{timestamp}.json"
            with open(summary_file, 'w') as f:
                json.dump(scan_summary, f, indent=2)
                
            print("\u2705 Scan completed successfully!")
            print(f"\U0001f4ca Results Summary:")
            print(f"   \u2022 Hosts up: {len(hosts_up)}/{len(self.nm.all_hosts())}")
            print(f"   \u2022 Open ports found: {open_ports}")
            print(f"   \u2022 Total ports scanned: {total_ports}")
            print(f"\U0001f4c1 Results saved to: {output_file}")
            print(f"\U0001f4cb Summary saved to: {summary_file}")
            
            return output_file
            
        except Exception as e:
            print(f"\u274c Scan failed: {str(e)}")
            return None
    
    def get_recommended_scan_sequence(self, target_type="network"):
        """
        Get recommended scan sequence for comprehensive analysis
        """
        sequences = {
            "network": [
                ("discovery", "Find live hosts"),
                ("comprehensive", "Service detection (no root)"),
                ("vulnerability_scan", "Security vulnerability assessment"),
                ("web_discovery", "Web application discovery")
            ],
            "host": [
                ("comprehensive", "Service detection (no root)"),
                ("full_tcp", "Complete TCP port coverage"),
                ("vulnerability_scan", "Security assessment"),
                ("web_discovery", "Web services")
            ],
            "webapp": [
                ("web_discovery", "Web application discovery"),
                ("vulnerability_scan", "Web vulnerability assessment"),
                ("comprehensive", "Complete service analysis")
            ],
            "database": [
                ("database_discovery", "Database service enumeration"),
                ("vulnerability_scan", "Database security assessment"),
                ("comprehensive", "Complete analysis")
            ],
            "maximum_noroot": [
                ("discovery", "Host discovery"),
                ("max_intensity_noroot", "Maximum intensity without root"),
                ("vulnerability_scan", "Security assessment"),
                ("web_discovery", "Web application analysis"),
                ("database_discovery", "Database enumeration")
            ]
        }
        
        return sequences.get(target_type, sequences["network"])

def main():
    parser = argparse.ArgumentParser(description="Advanced Network Scanner with Comprehensive Analysis")
    parser.add_argument("targets", help="Target IP range (e.g., 192.168.1.0/24) or single IP")
    parser.add_argument("-t", "--type", default="comprehensive", 
                       choices=["quick", "comprehensive", "comprehensive_root", "full_tcp", "full_tcp_root", 
                               "udp_top", "udp_scan", "discovery", "full_comprehensive", "full_comprehensive_root", 
                               "vulnerability_scan", "stealth_comprehensive", "stealth_scan", "web_discovery", 
                               "database_discovery", "smb_discovery", "everything_novuln", "everything_withvuln",
                               "top_1000_intense", "max_intensity", "max_intensity_noroot", "custom_ports"],
                       help="Scan type")
    parser.add_argument("-T", "--timing", type=int, default=3, choices=range(0, 6),
                       help="Timing template (0=paranoid, 1=sneaky, 2=polite, 3=normal, 4=aggressive, 5=insane)")
    parser.add_argument("-o", "--output", default="output/xml/raw",
                       help="Output directory")
    parser.add_argument("--ports", help="Custom port range (use with custom_ports scan type)")
    parser.add_argument("--sequence", choices=["network", "host", "webapp", "database", "maximum_noroot"],
                       help="Show recommended scan sequence for target type")
    parser.add_argument("--list-scans", action="store_true",
                       help="List all available scan types with descriptions")
    
    args = parser.parse_args()
    
    scanner = NetworkScanner(args.output)
    
    # Handle special arguments
    if args.list_scans:
        print("\U0001f50d Available Scan Types:")
        print("=" * 80)
        scan_configs = {
            "quick": "Quick scan - top 100 ports (1-2 min)",
            "comprehensive": "Service detection, no root needed (5-10 min)",
            "comprehensive_root": "Full comprehensive with OS detection, needs root (5-10 min)",
            "full_tcp": "All TCP ports, no root (15-30 min)",
            "full_tcp_root": "All TCP ports with SYN stealth, needs root (15-30 min)", 
            "udp_top": "Top 1000 UDP ports, needs root (10-20 min)",
            "udp_scan": "UDP scan top 100 ports, needs root (10-20 min)",
            "discovery": "Host discovery only (30 sec - 2 min)",
            "full_comprehensive": "Complete TCP scan, no root (20-45 min)",
            "full_comprehensive_root": "Complete TCP/UDP scan, needs root (20-45 min)",
            "vulnerability_scan": "Vulnerability detection, no root (15-25 min)",
            "stealth_comprehensive": "Stealth comprehensive scan, needs root (10-20 min)",
            "stealth_scan": "Stealthy SYN scan, needs root (5-10 min)",
            "web_discovery": "Web application discovery (5-10 min)",
            "database_discovery": "Database service enumeration (3-8 min)",
            "smb_discovery": "SMB/NetBIOS discovery (3-7 min)",
            "everything_novuln": "Everything scan without vulnerability (20-40 min)",
            "everything_withvuln": "Everything scan with vulnerability (30-60 min)",
            "top_1000_intense": "Top 1000 ports intensive scan (5-10 min)",
            "max_intensity": "Maximum intensity, needs root (45-120 min)",
            "max_intensity_noroot": "Maximum intensity, no root needed (25-60 min)",
            "custom_ports": "Custom port range scan"
        }
        
        print("\U0001f7e2 NO ROOT REQUIRED:")
        no_root_scans = ["quick", "comprehensive", "full_tcp", "discovery", "full_comprehensive", 
                        "vulnerability_scan", "web_discovery", "database_discovery", "smb_discovery", 
                        "everything_novuln", "everything_withvuln", "top_1000_intense",
                        "max_intensity_noroot", "custom_ports"]
        for scan in no_root_scans:
            if scan in scan_configs:
                print(f"  {scan:<25} - {scan_configs[scan]}")
            
        print("\n\U0001f534 ROOT REQUIRED:")
        root_scans = ["comprehensive_root", "full_tcp_root", "udp_top", "udp_scan", 
                     "full_comprehensive_root", "stealth_comprehensive", "stealth_scan", "max_intensity"]
        for scan in root_scans:
            if scan in scan_configs:
                print(f"  {scan:<25} - {scan_configs[scan]}")
        return
    
    if args.sequence:
        print(f"\U0001f3af Recommended scan sequence for {args.sequence} analysis:")
        print("=" * 60)
        sequence = scanner.get_recommended_scan_sequence(args.sequence)
        for i, (scan_type, description) in enumerate(sequence, 1):
            print(f"{i}. {scan_type:<25} - {description}")
        print(f"\nTo run sequence:")
        for scan_type, _ in sequence:
            print(f"python3 {sys.argv[0]} {args.targets} -t {scan_type}")
        return
    
    # Check if running as root and recommend alternatives
    root_required_scans = ["comprehensive_root", "full_tcp_root", "udp_top", "udp_scan",
                          "full_comprehensive_root", "stealth_comprehensive", "stealth_scan", "max_intensity"]
    
    if args.type in root_required_scans and os.geteuid() != 0:
        print("\u26a0\ufe0f  Warning: This scan type requires root privileges")
        print("   Consider these alternatives that don't need root:")
        alternatives = {
            "comprehensive_root": "comprehensive",
            "full_tcp_root": "full_tcp", 
            "full_comprehensive_root": "full_comprehensive",
            "max_intensity": "max_intensity_noroot",
            "udp_top": "top_1000_intense",
            "udp_scan": "top_1000_intense",
            "stealth_scan": "comprehensive",
            "stealth_comprehensive": "comprehensive"
        }
        if args.type in alternatives:
            alt = alternatives[args.type]
            print(f"   Try: python3 {sys.argv[0]} {args.targets} -t {alt} -T {args.timing}")
        print()
    
    # Handle custom ports
    if args.type == "custom_ports" and not args.ports:
        print("\u274c Error: --ports argument required for custom_ports scan type")
        print("   Example: --ports 22,80,443,8080-8090")
        sys.exit(1)
    
    print(f"\U0001f680 Starting advanced network scan...")
    print(f"\U0001f3af Target: {args.targets}")
    print(f"\U0001f4ca Scan Type: {args.type}")
    print(f"\u26a1 Timing: T{args.timing}")
    print("=" * 60)
    
    result = scanner.scan_network(args.targets, args.type, args.timing)
    
    if result:
        print("\n" + "=" * 60)
        print("\U0001f389 Scan completed! Next steps:")
        print(f"1. Parse results: python3 scripts/parsing/xml_parser.py {result}")
        print(f"2. Generate report: python3 scripts/reporting/report_generator.py {result}")
        print(f"3. Or run full pipeline: python3 pipeline.py --xml-file {result}")
        print("=" * 60)
    else:
        print("\u274c Scan failed. Check error messages above.")
        sys.exit(1)

if __name__ == "__main__":
    main()
