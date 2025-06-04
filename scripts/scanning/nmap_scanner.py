#!/usr/bin/env python3
"""
Automated Nmap Scanner
Performs comprehensive network scans and saves results to XML format
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
        
        # Define scan configurations
        scan_configs = {
            "quick": {
                "arguments": f"-T{timing} -F --version-intensity 0",
                "description": "Quick scan - top 100 ports"
            },
            "comprehensive": {
                "arguments": f"-T{timing} -sS -sV -O -A --version-intensity 5",
                "description": "Comprehensive scan - service detection, OS detection"
            },
            "full_tcp": {
                "arguments": f"-T{timing} -sS -sV -p- --version-intensity 3",
                "description": "Full TCP port scan with service detection"
            },
            "udp_top": {
                "arguments": f"-T{timing} -sU --top-ports 1000 -sV",
                "description": "Top 1000 UDP ports with service detection"
            },
            "discovery": {
                "arguments": f"-T{timing} -sn",
                "description": "Host discovery only"
            }
        }
        
        if scan_type not in scan_configs:
            print(f"Unknown scan type: {scan_type}")
            print(f"Available types: {', '.join(scan_configs.keys())}")
            return None
            
        config = scan_configs[scan_type]
        output_file = self.output_dir / f"scan_{scan_type}_{timestamp}.xml"
        
        print(f"Starting {config['description']}...")
        print(f"Target: {targets}")
        print(f"Arguments: {config['arguments']}")
        print(f"Output: {output_file}")
        
        try:
            # Perform the scan
            self.nm.scan(
                hosts=targets,
                arguments=config['arguments']
            )
            
            # Save XML output manually
            xml_output = self.nm.get_nmap_last_output()
            with open(output_file, 'w', encoding='utf-8') as f:
                if isinstance(xml_output, bytes):
                    f.write(xml_output.decode('utf-8'))
                else:
                    f.write(xml_output)
            
            # Save scan summary
            scan_summary = {
                "timestamp": timestamp,
                "scan_type": scan_type,
                "targets": targets,
                "arguments": config['arguments'],
                "xml_file": str(output_file),
                "hosts_scanned": len(self.nm.all_hosts()),
                "hosts_up": len([h for h in self.nm.all_hosts() if self.nm[h].state() == 'up'])
            }
            
            summary_file = self.output_dir / f"summary_{scan_type}_{timestamp}.json"
            with open(summary_file, 'w') as f:
                json.dump(scan_summary, f, indent=2)
                
            print(f"Scan completed successfully!")
            print(f"Results saved to: {output_file}")
            print(f"Summary saved to: {summary_file}")
            
            return output_file
            
        except Exception as e:
            print(f"Scan failed: {str(e)}")
            return None

def main():
    parser = argparse.ArgumentParser(description="Automated Network Scanner")
    parser.add_argument("targets", help="Target IP range (e.g., 192.168.1.0/24)")
    parser.add_argument("-t", "--type", default="comprehensive", 
                       choices=["quick", "comprehensive", "full_tcp", "udp_top", "discovery"],
                       help="Scan type")
    parser.add_argument("-T", "--timing", type=int, default=3, choices=range(0, 6),
                       help="Timing template (0-5)")
    parser.add_argument("-o", "--output", default="output/xml/raw",
                       help="Output directory")
    
    args = parser.parse_args()
    
    # Check if running as root for certain scan types
    if args.type in ["comprehensive", "full_tcp"] and os.geteuid() != 0:
        print("Warning: Some scan types require root privileges for best results")
        print("Consider running with sudo for OS detection and SYN scans")
    
    scanner = NetworkScanner(args.output)
    result = scanner.scan_network(args.targets, args.type, args.timing)
    
    if result:
        print(f"\nNext steps:")
        print(f"1. Parse results: python3 scripts/parsing/xml_parser.py {result}")
        print(f"2. Generate report: python3 scripts/reporting/report_generator.py {result}")
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
