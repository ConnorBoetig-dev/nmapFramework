#!/usr/bin/env python3
"""
Network Security Scanner Pipeline - Ultimate Edition
Professional network mapping with intelligent time estimates and enhanced UI
Now with smart privilege escalation!
"""

import argparse
import sys
import os
import subprocess
import json
import time
from pathlib import Path
from datetime import datetime
import re
import ipaddress
import webbrowser
import platform
import shutil

# Try to import colorama for cross-platform colored output
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ''

class NetworkScannerPipeline:
    def __init__(self):
        # Enhanced scan profiles with actual nmap commands
        self.scan_types = {
            '1': {
                'id': 'quick',
                'name': 'Quick Scan',
                'desc': '⚡ Fast scan of top 100 ports',
                'nmap_args': '-T3 -F --version-intensity 0',
                'time_per_host': 0.5,  # minutes
                'base_time': 0.5,
                'requires_root': False
            },
            '2': {
                'id': 'comprehensive', 
                'name': 'Comprehensive Scan',
                'desc': '🔍 Detailed service detection with OS fingerprinting',
                'nmap_args': '-T3 -sT -sV -A --version-intensity 5',
                'time_per_host': 2,
                'base_time': 1,
                'requires_root': False
            },
            '3': {
                'id': 'full_tcp',
                'name': 'Full TCP Scan', 
                'desc': '🌐 All 65,535 TCP ports with service detection',
                'nmap_args': '-T3 -sT -sV -p- --version-intensity 3',
                'time_per_host': 15,
                'base_time': 5,
                'requires_root': False
            },
            '4': {
                'id': 'vulnerability_scan',
                'name': 'Vulnerability Scan',
                'desc': '🛡️ Security vulnerability detection with NSE scripts',
                'nmap_args': '-T3 -sT -sV --script=vuln --top-ports 2000 --version-intensity 7',
                'time_per_host': 10,
                'base_time': 3,
                'requires_root': False
            },
            '5': {
                'id': 'web_discovery',
                'name': 'Web Application Discovery',
                'desc': '🌍 Web services and SSL/TLS analysis',
                'nmap_args': '-T3 -sT -sV --script=http-*,ssl-*,tls-* -p 80,443,8080,8443,8000,8888,9000',
                'time_per_host': 3,
                'base_time': 1,
                'requires_root': False
            },
            '6': {
                'id': 'database_discovery',
                'name': 'Database Discovery',
                'desc': '🗄️ Database service enumeration',
                'nmap_args': '-T3 -sT -sV --script=*sql*,*db*,oracle-*,mongodb-* -p 1433,3306,5432,27017,1521,6379',
                'time_per_host': 2,
                'base_time': 1,
                'requires_root': False
            },
            '7': {
                'id': 'discovery',
                'name': 'Host Discovery Only',
                'desc': '📡 Quick ping sweep to find live hosts',
                'nmap_args': '-T3 -sn',
                'time_per_host': 0.1,
                'base_time': 0.2,
                'requires_root': False
            },
            '8': {
                'id': 'stealth_scan',
                'name': 'Stealth SYN Scan',
                'desc': '🥷 Stealthy half-open scan (requires root)',
                'nmap_args': '-T2 -sS -sV -f --randomize-hosts --source-port 443',
                'time_per_host': 3,
                'base_time': 2,
                'requires_root': True
            },
            '9': {
                'id': 'everything_novuln',
                'name': 'Everything (No Vulnerability)',
                'desc': '🚀 Complete scan: Discovery + Quick + Comprehensive + Full TCP + Web + DB',
                'nmap_args': '-T3 -sT -sV -A -p- --script=default,discovery,safe,http-*,ssl-*,*sql*,*db*',
                'time_per_host': 20,
                'base_time': 5,
                'requires_root': False,
                'composite': ['discovery', 'quick', 'comprehensive', 'full_tcp', 'web_discovery', 'database_discovery']
            },
            '10': {
                'id': 'everything_withvuln',
                'name': 'Everything (With Vulnerability)', 
                'desc': '💯 Ultimate scan: Everything + Vulnerability detection',
                'nmap_args': '-T3 -sT -sV -A -p- --script=default,discovery,safe,vuln,http-*,ssl-*,*sql*,*db*',
                'time_per_host': 30,
                'base_time': 10,
                'requires_root': False,
                'composite': ['discovery', 'quick', 'comprehensive', 'full_tcp', 'web_discovery', 'database_discovery', 'vulnerability_scan']
            },
            '11': {
                'id': 'top_1000_intense',
                'name': 'Top 1000 Ports Intensive',
                'desc': '🎯 Top 1000 ports with aggressive service detection',
                'nmap_args': '-T4 -sT -sV -A --top-ports 1000 --version-intensity 9',
                'time_per_host': 5,
                'base_time': 2,
                'requires_root': False
            },
            '12': {
                'id': 'udp_scan',
                'name': 'UDP Scan (Top 100)',
                'desc': '📊 UDP port scan for top 100 ports (requires root)',
                'nmap_args': '-T3 -sU --top-ports 100 -sV',
                'time_per_host': 8,
                'base_time': 3,
                'requires_root': True
            }
        }
        
        self.report_formats = {
            '1': ('html', 'Interactive HTML Report', '🌐 Beautiful web-based report with charts and visualizations'),
            '2': ('text', 'Text Report', '📄 Simple text report for terminal viewing'),
            '3': ('both', 'Both HTML and Text', '📊 Generate both report formats'),
        }
        
    def check_dependencies(self):
        """Check if required system dependencies are installed"""
        missing_deps = []
        
        # Check for nmap
        if not shutil.which('nmap'):
            missing_deps.append('nmap')
        
        return missing_deps
    
    def check_python_dependencies(self):
        """Check if Python dependencies are available"""
        missing_modules = []
        required_modules = ['colorama', 'lxml', 'jinja2', 'pandas', 'bs4']
        
        for module in required_modules:
            try:
                __import__(module)
            except ImportError:
                missing_modules.append(module)
        
        return missing_modules
    
    def is_running_as_root(self):
        """Check if script is running with root privileges"""
        return os.geteuid() == 0
    
    def is_in_virtualenv(self):
        """Check if running in a virtual environment"""
        return hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
    
    def get_virtualenv_path(self):
        """Get the virtual environment path"""
        if os.environ.get('VIRTUAL_ENV'):
            return os.environ['VIRTUAL_ENV']
        return None
    
    def needs_privilege_escalation(self, scan_type):
        """Check if the selected scan type requires root privileges"""
        scan_id = scan_type if isinstance(scan_type, str) else scan_type['id']
        for scan_info in self.scan_types.values():
            if scan_info['id'] == scan_id:
                return scan_info.get('requires_root', False)
        return False
    
    def escalate_privileges(self, args_list):
        """Re-execute the script with sudo, preserving virtual environment"""
        print(f"\n{Fore.YELLOW}🔒 This operation requires administrator privileges.")
        print(f"{Fore.WHITE}Please enter your password to continue...\n")
        
        # Prepare environment variables to preserve
        env_vars = []
        
        # Preserve virtual environment
        venv_path = self.get_virtualenv_path()
        if venv_path:
            env_vars.extend([
                f'VIRTUAL_ENV={venv_path}',
                f'PATH={venv_path}/bin:{os.environ.get("PATH", "")}',
                f'PYTHONPATH={os.environ.get("PYTHONPATH", "")}'
            ])
        
        # Build sudo command
        sudo_cmd = ['sudo']
        
        # Add environment preservation
        for env_var in env_vars:
            sudo_cmd.extend(['-E', env_var])
        
        # Add the Python executable and script
        sudo_cmd.extend([sys.executable] + args_list)
        
        # Add a marker to avoid infinite recursion
        sudo_cmd.append('--elevated')
        
        try:
            # Execute with sudo
            result = subprocess.run(sudo_cmd)
            sys.exit(result.returncode)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Operation cancelled by user.")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}❌ Failed to escalate privileges: {e}")
            sys.exit(1)
    
    def print_banner(self):
        """Display welcome banner"""
        banner = """
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║     🛡️  Network Security Scanner - Ultimate Pipeline  🛡️         ║
║                                                                   ║
║     Professional network mapping and security analysis tool       ║
║                    Now with intelligent time estimates!           ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
        """
        print(Fore.CYAN + Style.BRIGHT + banner)
    
    def print_section(self, title):
        """Print section header"""
        print(f"\n{Fore.YELLOW + Style.BRIGHT}{'─' * 70}")
        print(f"{Fore.YELLOW + Style.BRIGHT}  {title}")
        print(f"{Fore.YELLOW + Style.BRIGHT}{'─' * 70}")
    
    def estimate_host_count(self, target):
        """Estimate number of hosts in target"""
        try:
            # Single IP
            ipaddress.ip_address(target)
            return 1
        except ValueError:
            try:
                # Network range
                network = ipaddress.ip_network(target, strict=False)
                # For /24 and smaller, return actual count
                # For larger, cap at 256 for estimation
                return min(network.num_addresses, 256)
            except ValueError:
                # Multiple IPs or hostname
                if ',' in target:
                    return len(target.split(','))
                else:
                    # Hostname - assume single host
                    return 1
    
    def calculate_scan_time(self, scan_type, host_count):
        """Calculate realistic scan time estimate"""
        scan_info = self.scan_types[scan_type]
        base_time = scan_info['base_time']
        time_per_host = scan_info['time_per_host']
        
        # Calculate total time
        total_time = base_time + (time_per_host * host_count)
        
        # Format time estimate
        if total_time < 1:
            time_str = "Less than 1 minute"
        elif total_time < 60:
            time_str = f"{int(total_time)}-{int(total_time * 1.2)} minutes"
        else:
            hours = total_time / 60
            time_str = f"{hours:.1f}-{hours * 1.2:.1f} hours"
        
        # Add per-host info for transparency
        if host_count > 1:
            time_str += f" (~{time_per_host} min per host)"
        
        return time_str, total_time
    
    def validate_ip_or_network(self, target):
        """Validate IP address or network range"""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            try:
                ipaddress.ip_network(target, strict=False)
                return True
            except ValueError:
                return False
    
    def get_scan_target(self):
        """Interactive prompt for scan target"""
        self.print_section("🎯 Target Selection")
        
        print(f"\n{Fore.GREEN}Enter the target to scan:")
        print(f"{Fore.WHITE}  • Single IP: {Style.DIM}192.168.1.100")
        print(f"{Fore.WHITE}  • Network range: {Style.DIM}192.168.1.0/24")
        print(f"{Fore.WHITE}  • Multiple IPs: {Style.DIM}192.168.1.1,192.168.1.2")
        print(f"{Fore.WHITE}  • Hostname: {Style.DIM}example.com")
        
        while True:
            target = input(f"\n{Fore.CYAN}Target ▸ {Style.RESET_ALL}").strip()
            
            if not target:
                print(f"{Fore.RED}❌ Target cannot be empty. Please try again.")
                continue
            
            # Validate and estimate hosts
            host_count = self.estimate_host_count(target)
            
            if ',' in target:
                targets = [t.strip() for t in target.split(',')]
                valid = True
                for t in targets:
                    if not self.validate_ip_or_network(t):
                        print(f"{Fore.RED}❌ Invalid IP/network: {t}")
                        valid = False
                        break
                if valid:
                    print(f"{Fore.GREEN}✓ Valid target: {host_count} hosts")
                    return target, host_count
            elif self.validate_ip_or_network(target):
                print(f"{Fore.GREEN}✓ Valid target: ~{host_count} hosts")
                return target, host_count
            else:
                # Assume hostname
                print(f"{Fore.YELLOW}⚠️  Treating '{target}' as hostname (1 host)")
                return target, 1
    
    def get_scan_type(self, host_count):
        """Interactive prompt for scan type with nmap commands shown"""
        self.print_section("🔍 Scan Type Selection")
        
        print(f"\n{Fore.GREEN}Choose your scan type:")
        
        for key, scan in self.scan_types.items():
            root_warning = f" {Fore.RED}(requires root)" if scan['requires_root'] else ""
            time_est, _ = self.calculate_scan_time(key, host_count)
            
            print(f"\n  {Fore.CYAN}{key}. {Fore.WHITE + Style.BRIGHT}{scan['name']}{root_warning}")
            print(f"     {Style.DIM}{scan['desc']}")
            print(f"     {Fore.BLUE}Time estimate: {time_est}")
            print(f"     {Fore.MAGENTA}Nmap command: {Style.DIM}nmap {scan['nmap_args']} <target>")
        
        while True:
            choice = input(f"\n{Fore.CYAN}Select scan type [1-{len(self.scan_types)}] ▸ {Style.RESET_ALL}").strip()
            
            if choice in self.scan_types:
                scan = self.scan_types[choice]
                time_est, _ = self.calculate_scan_time(choice, host_count)
                print(f"{Fore.GREEN}✓ Selected: {scan['name']} (estimated {time_est})")
                return scan['id']
            else:
                print(f"{Fore.RED}❌ Invalid choice. Please select 1-{len(self.scan_types)}.")
    
    def get_report_format(self):
        """Interactive prompt for report format"""
        self.print_section("📊 Report Format")
        
        print(f"\n{Fore.GREEN}Select report format:")
        for key, (format_id, name, desc) in self.report_formats.items():
            print(f"\n  {Fore.CYAN}{key}. {Fore.WHITE + Style.BRIGHT}{name}")
            print(f"     {Style.DIM}{desc}")
        
        while True:
            choice = input(f"\n{Fore.CYAN}Select format [1-3] ▸ {Style.RESET_ALL}").strip()
            
            if choice in self.report_formats:
                format_type, name, _ = self.report_formats[choice]
                print(f"{Fore.GREEN}✓ Selected: {name}")
                return format_type
            else:
                print(f"{Fore.RED}❌ Invalid choice. Please select 1-3.")
    
    def get_auto_open_preference(self):
        """Ask if user wants to auto-open HTML reports"""
        self.print_section("🌐 Auto-Open Reports")
        
        print(f"\n{Fore.GREEN}Would you like to automatically open HTML reports in your browser?")
        print(f"{Style.DIM}(The report path will be shown as a clickable link regardless)")
        
        while True:
            choice = input(f"\n{Fore.CYAN}Auto-open reports? [Y/n] ▸ {Style.RESET_ALL}").strip().lower()
            
            if choice in ['', 'y', 'yes']:
                print(f"{Fore.GREEN}✓ Reports will auto-open")
                return True
            elif choice in ['n', 'no']:
                print(f"{Fore.GREEN}✓ Reports will not auto-open")
                return False
            else:
                print(f"{Fore.RED}❌ Please enter Y or N")
    
    def confirm_scan(self, target, host_count, scan_type, report_format, auto_open):
        """Show scan summary and confirm"""
        self.print_section("📋 Scan Summary")
        
        # Get scan details
        scan_id = scan_type
        scan = next(s for s in self.scan_types.values() if s['id'] == scan_id)
        format_name = next(name for _, (ft, name, _) in self.report_formats.items() if ft == report_format)
        
        time_est, total_minutes = self.calculate_scan_time(next(k for k, v in self.scan_types.items() if v['id'] == scan_id), host_count)
        
        print(f"\n{Fore.WHITE}  🎯 Target: {Fore.CYAN + Style.BRIGHT}{target}")
        print(f"{Fore.WHITE}  📍 Estimated hosts: {Fore.CYAN + Style.BRIGHT}{host_count}")
        print(f"{Fore.WHITE}  🔍 Scan Type: {Fore.CYAN + Style.BRIGHT}{scan['name']}")
        print(f"{Fore.WHITE}  📊 Report Format: {Fore.CYAN + Style.BRIGHT}{format_name}")
        print(f"{Fore.WHITE}  🌐 Auto-open: {Fore.CYAN + Style.BRIGHT}{'Yes' if auto_open else 'No'}")
        print(f"{Fore.WHITE}  ⏱️  Time estimate: {Fore.YELLOW + Style.BRIGHT}{time_est}")
        
        print(f"\n{Fore.MAGENTA}Full nmap command that will be executed:")
        print(f"{Style.DIM}nmap {scan['nmap_args']} {target}")
        
        # Show breakdown for composite scans
        if 'composite' in scan:
            print(f"\n{Fore.YELLOW}This composite scan includes:")
            for component in scan['composite']:
                comp_scan = next(s for s in self.scan_types.values() if s['id'] == component)
                print(f"  • {comp_scan['name']}")
        
        while True:
            choice = input(f"\n{Fore.GREEN}Proceed with scan? [Y/n] ▸ {Style.RESET_ALL}").strip().lower()
            
            if choice in ['', 'y', 'yes']:
                return True
            elif choice in ['n', 'no']:
                print(f"{Fore.YELLOW}Scan cancelled by user.")
                return False
            else:
                print(f"{Fore.RED}❌ Please enter Y or N")
    
    def show_progress(self, message, duration=1):
        """Show animated progress indicator"""
        frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        end_time = time.time() + duration
        i = 0
        
        while time.time() < end_time:
            print(f"\r{Fore.CYAN}{frames[i % len(frames)]} {message}", end="", flush=True)
            time.sleep(0.1)
            i += 1
        
        print(f"\r{Fore.GREEN}✓ {message}")
    
    def run_command(self, cmd, description):
        """Run a command and show progress"""
        print(f"\n{Fore.CYAN}▶ {description}")
        print(f"{Style.DIM}  Command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"{Fore.GREEN}✓ {description} completed successfully")
                return True, result.stdout
            else:
                print(f"{Fore.RED}❌ {description} failed")
                print(f"{Style.DIM}  Error: {result.stderr}")
                return False, result.stderr
        except Exception as e:
            print(f"{Fore.RED}❌ Error running command: {e}")
            return False, str(e)
    
    def extract_output_files(self, stdout):
        """Extract output file paths from command output"""
        files = {}
        
        # Look for XML file
        xml_match = re.search(r'Results saved to: (.+\.xml)', stdout)
        if xml_match:
            files['xml'] = xml_match.group(1).strip()
        
        # Look for JSON file
        json_match = re.search(r'Data exported to JSON: (.+\.json)', stdout)
        if json_match:
            files['json'] = json_match.group(1).strip()
        
        # Look for HTML report
        html_match = re.search(r'HTML report generated: (.+\.html)', stdout)
        if html_match:
            files['html'] = html_match.group(1).strip()
        
        # Look for text report
        text_match = re.search(r'Text report generated: (.+\.txt)', stdout)
        if text_match:
            files['text'] = text_match.group(1).strip()
        
        return files
    
    def open_html_report(self, filepath):
        """Open HTML report in browser with proper file:// URL"""
        try:
            # Convert to absolute path and create file URL
            abs_path = Path(filepath).absolute()
            file_url = abs_path.as_uri()
            
            # Try different methods based on platform
            if platform.system() == 'Darwin':  # macOS
                subprocess.call(['open', file_url])
            elif platform.system() == 'Windows':  # Windows
                os.startfile(file_url)
            else:  # Linux/Unix
                # Try xdg-open first, fall back to webbrowser
                try:
                    subprocess.call(['xdg-open', file_url])
                except:
                    webbrowser.open(file_url)
            
            return True
        except Exception as e:
            print(f"{Fore.YELLOW}⚠️  Could not auto-open report: {e}")
            return False
    
    def display_clickable_link(self, filepath):
        """Display file path as clickable link"""
        abs_path = Path(filepath).absolute()
        file_url = abs_path.as_uri()
        
        print(f"\n{Fore.GREEN + Style.BRIGHT}📄 HTML Report Generated!")
        print(f"{Fore.WHITE}Click the link below to open in your browser:")
        print(f"{Fore.CYAN + Style.BRIGHT}{file_url}")
        print(f"{Style.DIM}(You can Ctrl+Click or Cmd+Click this link in most terminals)")
    
    def run_pipeline(self, target, scan_type, report_format, auto_open):
        """Execute the complete scanning pipeline"""
        self.print_section("🚀 Running Network Security Scan")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        files = {}
        
        # Step 1: Run nmap scan
        scanner_script = Path("scripts/scanning/nmap_scanner.py")
        if not scanner_script.exists():
            print(f"{Fore.RED}❌ Scanner script not found: {scanner_script}")
            return False
        
        scan_cmd = [
            sys.executable,
            str(scanner_script),
            target,
            "-t", scan_type,
            "-T", "3"  # Normal timing
        ]
        
        success, output = self.run_command(scan_cmd, "Running network scan")
        if not success:
            return False
        
        # Extract XML file path
        scan_files = self.extract_output_files(output)
        if 'xml' not in scan_files:
            print(f"{Fore.RED}❌ Could not find XML output file")
            return False
        
        xml_file = scan_files['xml']
        files['xml'] = xml_file
        
        # Step 2: Parse XML
        parser_script = Path("scripts/parsing/xml_parser.py")
        if not parser_script.exists():
            print(f"{Fore.RED}❌ Parser script not found: {parser_script}")
            return False
        
        parse_cmd = [
            sys.executable,
            str(parser_script),
            xml_file,
            "--format", "json"
        ]
        
        self.show_progress("Parsing scan results", 1)
        success, output = self.run_command(parse_cmd, "Parsing XML results")
        if not success:
            return False
        
        # Extract JSON file path
        parse_files = self.extract_output_files(output)
        if 'json' not in parse_files:
            print(f"{Fore.RED}❌ Could not find parsed JSON file")
            return False
        
        json_file = parse_files['json']
        files['json'] = json_file
        
        # Step 3: Generate reports
        report_script = Path("scripts/reporting/report_generator.py")
        if not report_script.exists():
            # Try the enhanced version
            report_script = Path("scripts/reporting/enhanced_report_generator.py")
            if not report_script.exists():
                print(f"{Fore.RED}❌ Report generator script not found")
                return False
        
        report_cmd = [
            sys.executable,
            str(report_script),
            json_file,
            "--format", report_format
        ]
        
        # Don't pass --no-open flag, handle opening ourselves
        
        self.show_progress("Generating reports", 1.5)
        success, output = self.run_command(report_cmd, "Generating reports")
        if not success:
            return False
        
        # Extract report file paths
        report_files = self.extract_output_files(output)
        files.update(report_files)
        
        # Handle HTML report opening
        if 'html' in files and report_format in ['html', 'both']:
            html_path = files['html']
            
            # Always display clickable link
            self.display_clickable_link(html_path)
            
            # Try to auto-open if requested
            if auto_open:
                print(f"\n{Fore.CYAN}🌐 Opening report in browser...")
                if self.open_html_report(html_path):
                    print(f"{Fore.GREEN}✓ Report opened in browser")
                else:
                    print(f"{Fore.YELLOW}⚠️  Please click the link above to open the report")
        
        # Show final summary
        self.print_section("✅ Scan Complete!")
        
        print(f"\n{Fore.GREEN + Style.BRIGHT}Successfully completed network security analysis!")
        print(f"\n{Fore.WHITE}📁 Generated files:")
        
        if 'xml' in files:
            print(f"  • XML scan data: {Style.DIM}{files['xml']}")
        if 'json' in files:
            print(f"  • Parsed data: {Style.DIM}{files['json']}")
        if 'html' in files and report_format in ['html', 'both']:
            print(f"  • {Fore.CYAN}HTML report: {Style.BRIGHT}{files['html']}")
        if 'text' in files:
            print(f"  • Text report: {Style.DIM}{files['text']}")
        
        # Show quick stats if available
        try:
            with open(files['json'], 'r') as f:
                data = json.load(f)
                insights = data.get('insights', {})
                
                if insights:
                    print(f"\n{Fore.WHITE}📊 Quick Summary:")
                    print(f"  • Hosts found: {Fore.CYAN}{insights.get('hosts_up', 0)}/{insights.get('total_hosts', 0)}")
                    print(f"  • Open ports: {Fore.CYAN}{insights.get('total_open_ports', 0)}")
                    print(f"  • Services: {Fore.CYAN}{len(insights.get('unique_services', []))}")
                    
                    issues = insights.get('potential_issues', [])
                    if issues:
                        high_issues = sum(1 for i in issues if i.get('severity') == 'high')
                        med_issues = sum(1 for i in issues if i.get('severity') == 'medium')
                        
                        if high_issues > 0:
                            print(f"  • {Fore.RED}Security issues: {high_issues} critical")
                        if med_issues > 0:
                            print(f"  • {Fore.YELLOW}Security issues: {med_issues} medium")
        except:
            pass  # Don't fail if we can't read stats
        
        return True
    
    def interactive_mode(self):
        """Run in interactive mode"""
        # Check dependencies first
        missing_deps = self.check_dependencies()
        if missing_deps:
            print(f"{Fore.RED}❌ Missing system dependencies: {', '.join(missing_deps)}")
            print(f"{Fore.YELLOW}Please run the setup script first: python3 setup_dependencies.py")
            sys.exit(1)
        
        missing_modules = self.check_python_dependencies()
        if missing_modules:
            print(f"{Fore.RED}❌ Missing Python modules: {', '.join(missing_modules)}")
            print(f"{Fore.YELLOW}Please activate your virtual environment or run:")
            print(f"{Fore.WHITE}  pip install -r requirements.txt")
            sys.exit(1)
        
        self.print_banner()
        
        print(f"\n{Fore.GREEN}Welcome! Let's set up your network security scan.")
        print(f"{Style.DIM}I'll guide you through each step with time estimates.\n")
        
        # Get all inputs
        target, host_count = self.get_scan_target()
        scan_type = self.get_scan_type(host_count)
        report_format = self.get_report_format()
        auto_open = self.get_auto_open_preference() if report_format in ['html', 'both'] else False
        
        # Check if privilege escalation is needed
        if self.needs_privilege_escalation(scan_type) and not self.is_running_as_root():
            if self.confirm_scan(target, host_count, scan_type, report_format, auto_open):
                # Need to escalate privileges
                # Prepare arguments for re-execution
                args = [__file__, target, '-t', scan_type, '--format', report_format]
                if not auto_open:
                    args.append('--no-open')
                
                self.escalate_privileges(args)
        else:
            # Either doesn't need root or already running as root
            if self.confirm_scan(target, host_count, scan_type, report_format, auto_open):
                start_time = time.time()
                if self.run_pipeline(target, scan_type, report_format, auto_open):
                    elapsed = time.time() - start_time
                    print(f"\n{Fore.GREEN + Style.BRIGHT}🎉 All done! Your network analysis is complete.")
                    print(f"{Style.DIM}Total time: {elapsed/60:.1f} minutes")
                else:
                    print(f"\n{Fore.RED}❌ Pipeline failed. Please check the errors above.")
                    sys.exit(1)
            else:
                print(f"\n{Fore.YELLOW}Pipeline cancelled.")
                sys.exit(0)

def main():
    # Set up argument parser for non-interactive mode
    parser = argparse.ArgumentParser(
        description="Network Security Scanner Pipeline - Professional network mapping and analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Interactive mode (recommended):
    python3 pipeline.py
    
  Automated mode:
    python3 pipeline.py 192.168.1.0/24 -t comprehensive
    python3 pipeline.py 10.0.0.1 -t quick --format html
    python3 pipeline.py scanme.nmap.org -t vulnerability_scan --no-open
    python3 pipeline.py 192.168.1.0/24 -t everything_withvuln
    
  Process existing results:
    python3 pipeline.py --xml-file output/xml/raw/scan_20240115_120000.xml
    python3 pipeline.py --json-file output/processed/scan_parsed.json --format html
        """
    )
    
    # Create mutually exclusive group for input modes
    input_group = parser.add_mutually_exclusive_group()
    
    # Option 1: Scan targets (for new scans)
    input_group.add_argument("targets", nargs='?', 
                            help="Target IP, network range, or hostname (e.g., 192.168.1.0/24)")
    
    # Option 2: Process existing XML
    input_group.add_argument("--xml-file", 
                            help="Process existing nmap XML file")
    
    # Option 3: Process existing JSON
    input_group.add_argument("--json-file",
                            help="Generate reports from existing parsed JSON")
    
    # Scan options (only valid with targets)
    parser.add_argument("-t", "--type", 
                       choices=['quick', 'comprehensive', 'full_tcp', 'vulnerability_scan',
                               'web_discovery', 'database_discovery', 'discovery', 
                               'stealth_scan', 'everything_novuln', 'everything_withvuln',
                               'top_1000_intense', 'udp_scan'],
                       default='comprehensive',
                       help="Scan type (default: comprehensive)")
    
    parser.add_argument("-T", "--timing", type=int, choices=range(0, 6), default=3,
                       help="Timing template (0=slow, 5=fast, default=3)")
    
    # Output options
    parser.add_argument("-o", "--output", default="output",
                       help="Base output directory")
    
    parser.add_argument("--format", choices=["html", "text", "both"], default="both",
                       help="Report format (default: both)")
    
    parser.add_argument("--no-open", action="store_true",
                       help="Don't auto-open HTML reports")
    
    # Hidden flag to indicate we're already elevated
    parser.add_argument("--elevated", action="store_true", help=argparse.SUPPRESS)
    
    args = parser.parse_args()
    
    # Determine mode of operation
    pipeline = NetworkScannerPipeline()
    
    if not any([args.targets, args.xml_file, args.json_file]):
        # No arguments provided - run interactive mode
        pipeline.interactive_mode()
    else:
        # Arguments provided - run in automated mode
        if args.targets:
            # Check if we need privilege escalation
            if pipeline.needs_privilege_escalation(args.type) and not pipeline.is_running_as_root() and not args.elevated:
                # Need to escalate
                print(f"{Fore.YELLOW}🔒 The selected scan type requires administrator privileges.")
                args_list = sys.argv[:]
                pipeline.escalate_privileges(args_list)
            else:
                # New scan - either doesn't need root or already elevated
                print(f"{Fore.CYAN}Running automated scan...")
                pipeline.run_pipeline(args.targets, args.type, args.format, not args.no_open)
        
        elif args.xml_file:
            # Process existing XML
            print(f"{Fore.CYAN}Processing existing XML file...")
            parse_cmd = [sys.executable, "scripts/parsing/xml_parser.py", args.xml_file]
            subprocess.run(parse_cmd)
        
        elif args.json_file:
            # Generate report from JSON
            print(f"{Fore.CYAN}Generating report from JSON...")
            report_cmd = [
                sys.executable, 
                "scripts/reporting/report_generator.py",
                args.json_file,
                "--format", args.format
            ]
            subprocess.run(report_cmd)

if __name__ == "__main__":
    main()
