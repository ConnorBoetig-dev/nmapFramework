#!/usr/bin/env python3
"""
Enhanced Nmap Network Scanner with Live Progress
Professional wrapper around nmap with real-time progress tracking
"""

import nmap
import json
import sys
import os
import subprocess
import threading
import time
import re
from pathlib import Path
from datetime import datetime
from queue import Queue

# Try to import tqdm for better progress bars
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    print("Note: Install tqdm for better progress bars (pip install tqdm)")

# Color support
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    class MockColor:
        def __getattr__(self, name):
            return ""
    Fore = Back = Style = MockColor()

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.output_dir = Path("output/xml/raw")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.progress_queue = Queue()
        self.scan_stats = {
            'hosts_total': 0,
            'hosts_up': 0,
            'hosts_scanned': 0,
            'open_ports': 0,
            'percent_complete': 0,
            'current_host': '',
            'phase': 'Initializing'
        }
    
    def _parse_nmap_progress(self, line):
        """Parse nmap output line for progress information"""
        # Parse percentage from stats line
        percent_match = re.search(r'About (\d+\.\d+)% done', line)
        if percent_match:
            self.scan_stats['percent_complete'] = float(percent_match.group(1))
        
        # Parse host discovery
        if 'Nmap scan report for' in line:
            host_match = re.search(r'Nmap scan report for (.+)', line)
            if host_match:
                self.scan_stats['current_host'] = host_match.group(1)
                self.scan_stats['hosts_scanned'] += 1
        
        # Parse host status
        if 'Host is up' in line:
            self.scan_stats['hosts_up'] += 1
        
        # Parse open ports
        if '/tcp' in line and 'open' in line:
            self.scan_stats['open_ports'] += 1
        
        # Parse scan phases
        if 'Initiating' in line:
            phase_match = re.search(r'Initiating (.+) at', line)
            if phase_match:
                self.scan_stats['phase'] = phase_match.group(1)
        
        # ETA parsing
        eta_match = re.search(r'ETC: (\d+:\d+)', line)
        if eta_match:
            self.scan_stats['eta'] = eta_match.group(1)
    
    def _run_nmap_with_progress(self, target, arguments, output_file):
        """Run nmap with real-time progress tracking"""
        # Build command
        cmd = [
            'nmap',
            '-oX', output_file,  # XML output
            '--stats-every', '2s',  # Update stats every 2 seconds
            '-v'  # Verbose for more output
        ] + arguments.split() + [target]
        
        # Start time for duration calculation
        start_time = time.time()
        
        # Run nmap with subprocess
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )
        
        # Process output line by line
        for line in process.stdout:
            line = line.strip()
            if line:
                # Parse progress information
                self._parse_nmap_progress(line)
                
                # Calculate elapsed time
                elapsed = time.time() - start_time
                self.scan_stats['elapsed'] = elapsed
                
                # Put update in queue
                self.progress_queue.put({
                    'line': line,
                    'stats': self.scan_stats.copy()
                })
        
        # Wait for process to complete
        process.wait()
        
        return process.returncode == 0
    
    def _display_progress(self):
        """Display progress updates from the queue"""
        if TQDM_AVAILABLE:
            # Use tqdm progress bar
            with tqdm(total=100, desc="Scanning", unit="%", 
                     bar_format='{desc}: {percentage:3.0f}%|{bar}| [{elapsed}<{remaining}]') as pbar:
                
                last_percent = 0
                while True:
                    try:
                        update = self.progress_queue.get(timeout=0.1)
                        stats = update['stats']
                        
                        # Update progress bar
                        current_percent = stats['percent_complete']
                        if current_percent > last_percent:
                            pbar.update(current_percent - last_percent)
                            last_percent = current_percent
                        
                        # Update description with current activity
                        desc = f"Scanning {stats['current_host']}" if stats['current_host'] else stats['phase']
                        pbar.set_description(desc)
                        
                        # Update postfix with stats
                        pbar.set_postfix({
                            'Hosts': f"{stats['hosts_up']}/{stats['hosts_scanned']}",
                            'Ports': stats['open_ports']
                        })
                        
                        # Check if scan is complete
                        if 'Nmap done' in update['line']:
                            pbar.update(100 - last_percent)
                            break
                            
                    except:
                        # Queue timeout - check if thread is still alive
                        if not hasattr(self, '_scan_thread') or not self._scan_thread.is_alive():
                            break
        else:
            # Fallback progress display without tqdm
            last_update = 0
            spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
            spinner_idx = 0
            
            while True:
                try:
                    update = self.progress_queue.get(timeout=0.1)
                    stats = update['stats']
                    
                    # Update every 0.5 seconds to avoid too much output
                    current_time = time.time()
                    if current_time - last_update > 0.5:
                        # Clear line and print progress
                        print(f"\r{spinner[spinner_idx % len(spinner)]} "
                              f"{Fore.CYAN}Progress: {stats['percent_complete']:.1f}%{Style.RESET_ALL} | "
                              f"{Fore.GREEN}Hosts: {stats['hosts_up']}/{stats['hosts_scanned']}{Style.RESET_ALL} | "
                              f"{Fore.YELLOW}Ports: {stats['open_ports']}{Style.RESET_ALL} | "
                              f"Phase: {stats['phase'][:30]}", end='', flush=True)
                        
                        spinner_idx += 1
                        last_update = current_time
                    
                    # Check if scan is complete
                    if 'Nmap done' in update['line']:
                        print()  # New line after progress
                        break
                        
                except:
                    # Queue timeout - check if thread is still alive
                    if not hasattr(self, '_scan_thread') or not self._scan_thread.is_alive():
                        print()  # New line after progress
                        break
    
    def scan_network(self, target, scan_type="comprehensive", timing=3):
        """
        Perform network scan with specified parameters and live progress
        
        Args:
            target: IP address, hostname, or network range to scan
            scan_type: Type of scan to perform
            timing: Nmap timing template (0-5, higher is faster but less accurate)
        
        Returns:
            Path to the generated XML file
        """
        # Define scan configurations
        scan_configs = {
            "discovery": {
                "arguments": f"-sn -T{timing}",
                "description": "Host discovery scan",
                "estimated_time": "1-2 minutes"
            },
            "quick": {
                "arguments": f"-T{timing} -F --version-intensity 0",
                "description": "Quick scan - top 100 ports",
                "estimated_time": "1-2 minutes"
            },
            "comprehensive": {
                "arguments": f"-T{timing} -sT -sV -A --version-intensity 5",
                "description": "Comprehensive scan with service/OS detection",
                "estimated_time": "5-10 minutes"
            },
            "full_tcp": {
                "arguments": f"-T{timing} -sT -sV -p- --version-intensity 3",
                "description": "Full TCP port scan (all 65535 ports)",
                "estimated_time": "15-30 minutes"
            },
            "udp_top": {
                "arguments": f"-T{timing} -sU --top-ports 100 -sV",
                "description": "Top 100 UDP ports",
                "estimated_time": "10-20 minutes"
            },
            "vulnerability": {
                "arguments": f"-T{timing} -sT -sV --script=vuln --top-ports 2000",
                "description": "Vulnerability scan with NSE scripts",
                "estimated_time": "15-25 minutes"
            },
            "vulnerability_scan": {  # Alias for compatibility
                "arguments": f"-T{timing} -sT -sV --script=vuln --top-ports 2000",
                "description": "Vulnerability scan with NSE scripts",
                "estimated_time": "15-25 minutes"
            },
            "web_discovery": {
                "arguments": f"-T{timing} -sT -sV --script=http-enum,http-headers,ssl-cert -p 80,443,8080,8443",
                "description": "Web service discovery",
                "estimated_time": "5-10 minutes"
            },
            "database_discovery": {
                "arguments": f"-T{timing} -sT -sV --script=mysql*,ms-sql*,mongodb*,redis* -p 1433,3306,5432,27017,6379",
                "description": "Database service discovery",
                "estimated_time": "3-8 minutes"
            },
            "stealth_scan": {
                "arguments": f"-T2 -sS -sV -f --randomize-hosts",
                "description": "Stealthy SYN scan",
                "estimated_time": "5-10 minutes"
            },
            "udp_scan": {
                "arguments": f"-T{timing} -sU --top-ports 100 -sV",
                "description": "UDP scan of top 100 ports",
                "estimated_time": "10-20 minutes"
            },
            "everything_with_vuln": {
                "arguments": f"-T{timing} -sT -sV -A -p- --script=default,vuln,discovery",
                "description": "Complete scan with all ports and vulnerability detection",
                "estimated_time": "30-60 minutes"
            }
        }
        
        # Get scan configuration
        config = scan_configs.get(scan_type, scan_configs["comprehensive"])
        
        # Print scan information
        print(f"\n{Fore.CYAN}🎯 Starting {scan_type.title()} scan - {config['description']}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}📡 Target: {target}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}⚙️  Arguments: {config['arguments']}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}⏱️  Estimated time: {config['estimated_time']}{Style.RESET_ALL}")
        
        # Generate output filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        xml_filename = self.output_dir / f"scan_{scan_type}_{timestamp}.xml"
        print(f"{Fore.GREEN}📁 Output: {xml_filename}{Style.RESET_ALL}")
        print("=" * 60)
        
        # Reset stats
        self.scan_stats = {
            'hosts_total': 0,
            'hosts_up': 0,
            'hosts_scanned': 0,
            'open_ports': 0,
            'percent_complete': 0,
            'current_host': '',
            'phase': 'Initializing'
        }
        
        # Clear the queue
        while not self.progress_queue.empty():
            self.progress_queue.get()
        
        # Start scan in thread
        self._scan_thread = threading.Thread(
            target=self._run_nmap_with_progress,
            args=(target, config['arguments'], str(xml_filename))
        )
        self._scan_thread.start()
        
        # Display progress
        self._display_progress()
        
        # Wait for scan to complete
        self._scan_thread.join()
        
        # Parse final results for summary
        if xml_filename.exists():
            try:
                nm_result = nmap.PortScanner()
                nm_result.analyse_nmap_xml_scan(open(str(xml_filename)).read())
                
                # Count results
                total_hosts = len(nm_result.all_hosts())
                hosts_up = len([h for h in nm_result.all_hosts() if nm_result[h].state() == 'up'])
                open_ports = sum(len([p for p in nm_result[h].all_tcp() if nm_result[h].tcp(p)['state'] == 'open']) 
                               for h in nm_result.all_hosts())
                
                # Save summary
                summary_file = self.output_dir / f"summary_{scan_type}_{timestamp}.json"
                summary_data = {
                    "scan_type": scan_type,
                    "target": target,
                    "timestamp": timestamp,
                    "total_hosts": total_hosts,
                    "hosts_up": hosts_up,
                    "open_ports": open_ports,
                    "xml_file": str(xml_filename),
                    "duration": self.scan_stats.get('elapsed', 0)
                }
                
                with open(summary_file, 'w') as f:
                    json.dump(summary_data, f, indent=2)
                
                # Print summary
                print(f"\n{Fore.GREEN}✅ Scan completed successfully!{Style.RESET_ALL}")
                print(f"{Fore.CYAN}📊 Results Summary:{Style.RESET_ALL}")
                print(f"   • Hosts up: {hosts_up}/{total_hosts}")
                print(f"   • Open ports found: {open_ports}")
                print(f"   • Scan duration: {self.scan_stats.get('elapsed', 0):.1f} seconds")
                print(f"{Fore.GREEN}📁 Results saved to: {xml_filename}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}📋 Summary saved to: {summary_file}{Style.RESET_ALL}")
                
                return str(xml_filename)
                
            except Exception as e:
                print(f"{Fore.RED}❌ Error parsing results: {e}{Style.RESET_ALL}")
                return str(xml_filename)
        else:
            print(f"{Fore.RED}❌ Scan failed - no output file generated{Style.RESET_ALL}")
            return None
    
    def parse_results(self, xml_file):
        """Parse nmap XML results into structured format"""
        try:
            with open(xml_file, 'r') as f:
                self.nm.analyse_nmap_xml_scan(f.read())
            
            results = {
                'scan_info': self.nm.scaninfo(),
                'hosts': []
            }
            
            for host in self.nm.all_hosts():
                host_info = {
                    'ip': host,
                    'hostname': self.nm[host].hostname(),
                    'state': self.nm[host].state(),
                    'os': self._get_os_info(host),
                    'ports': []
                }
                
                # Get all protocols
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        host_info['ports'].append({
                            'port': port,
                            'protocol': proto,
                            'state': port_info['state'],
                            'service': port_info['name'],
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', '')
                        })
                
                results['hosts'].append(host_info)
            
            return results
            
        except Exception as e:
            print(f"Error parsing XML file: {e}")
            return None
    
    def _get_os_info(self, host):
        """Extract OS information for a host"""
        os_info = {}
        if 'osclass' in self.nm[host]:
            for osclass in self.nm[host]['osclass']:
                os_info = {
                    'type': osclass.get('type', ''),
                    'vendor': osclass.get('vendor', ''),
                    'family': osclass.get('osfamily', ''),
                    'generation': osclass.get('osgen', ''),
                    'accuracy': osclass.get('accuracy', '')
                }
                break  # Just take the first match
        return os_info

def main():
    """Example usage and testing"""
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target> [scan_type]")
        print("\nScan types:")
        print("  - discovery: Host discovery only")
        print("  - quick: Fast scan of common ports")
        print("  - comprehensive: Detailed scan with OS/service detection")
        print("  - full_tcp: All TCP ports")
        print("  - vulnerability: Vulnerability detection")
        print("  - web_discovery: Web service enumeration")
        print("  - database_discovery: Database service detection")
        sys.exit(1)
    
    target = sys.argv[1]
    scan_type = sys.argv[2] if len(sys.argv) > 2 else "quick"
    
    scanner = NetworkScanner()
    
    print(f"\n{Fore.CYAN}🚀 Network Scanner - Live Progress Edition{Style.RESET_ALL}")
    print("=" * 60)
    
    # Check if running as root for certain scan types
    root_required = ["udp_top", "stealth_scan", "udp_scan"]
    if scan_type in root_required and os.geteuid() != 0:
        print(f"{Fore.RED}❌ Error: {scan_type} requires root privileges{Style.RESET_ALL}")
        print("Please run with sudo")
        sys.exit(1)
    
    # Perform scan
    xml_file = scanner.scan_network(target, scan_type)
    
    if xml_file:
        print(f"\n{Fore.GREEN}✨ Scan completed! Check the results in:{Style.RESET_ALL}")
        print(f"   {xml_file}")

if __name__ == "__main__":
    main()
