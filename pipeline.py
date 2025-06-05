#!/usr/bin/env python3
"""
Complete Network Mapping Pipeline
Orchestrates scanning, parsing, and reporting in one command
Now with interactive user interface!
"""

import argparse
import subprocess
import sys
import os
from pathlib import Path
import json
import time
from datetime import datetime

class NetworkMappingPipeline:
    def __init__(self, project_root="."):
        self.project_root = Path(project_root)
        self.scripts_dir = self.project_root / "scripts"
        self.output_dir = self.project_root / "output"
        
        # Ensure directories exist
        self.scripts_dir.mkdir(exist_ok=True)
        self.output_dir.mkdir(exist_ok=True)
        
        # Scan type configurations
        self.scan_types = {
            "1": {
                "name": "quick",
                "description": "Quick scan - Top 100 ports (fastest, ~30 seconds)",
                "details": "Scans most common ports, good for quick network overview"
            },
            "2": {
                "name": "discovery", 
                "description": "Discovery scan - Host discovery only (very fast)",
                "details": "Only finds which hosts are online, no port scanning"
            },
            "3": {
                "name": "comprehensive",
                "description": "Comprehensive scan - Full service + OS detection (recommended)",
                "details": "Balanced scan with service detection and OS fingerprinting"
            },
            "4": {
                "name": "full_tcp",
                "description": "Full TCP scan - All 65535 TCP ports (slowest, thorough)",
                "details": "Complete TCP port scan, can take 10+ minutes"
            },
            "5": {
                "name": "udp_top",
                "description": "UDP scan - Top 1000 UDP ports",
                "details": "Scans common UDP services like DNS, DHCP, SNMP"
            }
        }
    
    def interactive_mode(self):
        """Run the pipeline in interactive mode"""
        print("🌐 Network Mapping Pipeline - Interactive Mode")
        print("=" * 55)
        
        # Get scan type
        scan_type = self._get_scan_type()
        
        # Get target
        targets = self._get_targets()
        
        # Get timing (optional)
        timing = self._get_timing()
        
        # Get report format
        report_format = self._get_report_format()
        
        # Confirm and run
        if self._confirm_scan(targets, scan_type, timing, report_format):
            return self.run_full_pipeline(targets, scan_type, timing, report_format)
        else:
            print("❌ Scan cancelled by user")
            return False
    
    def _get_scan_type(self):
        """Interactive scan type selection"""
        print("\n🔍 Select Scan Type:")
        print("-" * 25)
        
        for key, scan in self.scan_types.items():
            print(f"{key}. {scan['description']}")
            print(f"   {scan['details']}")
            print()
        
        while True:
            choice = input("Enter your choice (1-5): ").strip()
            
            if choice in self.scan_types:
                selected = self.scan_types[choice]
                print(f"✅ Selected: {selected['description']}")
                return selected['name']
            else:
                print("❌ Invalid choice. Please enter 1-5.")
    
    def _get_targets(self):
        """Interactive target selection with examples"""
        print("\n🎯 Enter Target(s):")
        print("-" * 20)
        print("Examples:")
        print("  • Single IP:     192.168.1.1")
        print("  • IP range:      192.168.1.1-50")
        print("  • Subnet:        192.168.1.0/24")
        print("  • Multiple:      192.168.1.1,192.168.1.5,192.168.1.10")
        print()
        
        while True:
            targets = input("Enter target IP(s) or subnet: ").strip()
            
            if targets:
                # Basic validation
                if self._validate_targets(targets):
                    print(f"✅ Target set: {targets}")
                    return targets
                else:
                    print("❌ Invalid target format. Please check your input.")
            else:
                print("❌ Please enter a target.")
    
    def _validate_targets(self, targets):
        """Basic target validation"""
        # Simple validation - check for basic IP patterns
        import re
        
        # Remove spaces and check for basic patterns
        targets = targets.replace(" ", "")
        
        # Allow IPs, ranges, subnets, and comma-separated lists
        pattern = r'^[\d\.\-,/]+$'
        return bool(re.match(pattern, targets))
    
    def _get_timing(self):
        """Interactive timing selection"""
        print("\n⏱️  Scan Timing (Optional):")
        print("-" * 30)
        print("0. Paranoid (very slow, stealthy)")
        print("1. Sneaky (slow, stealthy)")  
        print("2. Polite (slow)")
        print("3. Normal (default) ⭐")
        print("4. Aggressive (fast)")
        print("5. Insane (very fast, may miss results)")
        print()
        
        choice = input("Enter timing (0-5) or press Enter for default (3): ").strip()
        
        if choice == "":
            print("✅ Using default timing (T3)")
            return 3
        elif choice in "012345":
            timing = int(choice)
            timing_names = ["Paranoid", "Sneaky", "Polite", "Normal", "Aggressive", "Insane"]
            print(f"✅ Selected: T{timing} ({timing_names[timing]})")
            return timing
        else:
            print("❌ Invalid choice, using default (T3)")
            return 3
    
    def _get_report_format(self):
        """Interactive report format selection"""
        print("\n📊 Report Format:")
        print("-" * 17)
        print("1. HTML only (web dashboard)")
        print("2. Text only (terminal friendly)")
        print("3. Both formats (recommended) ⭐")
        print()
        
        choice = input("Enter choice (1-3) or press Enter for both (3): ").strip()
        
        format_map = {"1": "html", "2": "text", "3": "both", "": "both"}
        
        if choice in format_map:
            selected_format = format_map[choice]
            format_names = {"html": "HTML only", "text": "Text only", "both": "Both formats"}
            print(f"✅ Selected: {format_names[selected_format]}")
            return selected_format
        else:
            print("❌ Invalid choice, using both formats")
            return "both"
    
    def _confirm_scan(self, targets, scan_type, timing, report_format):
        """Confirm scan parameters before running"""
        print("\n" + "=" * 55)
        print("📋 Scan Summary:")
        print("-" * 15)
        print(f"Target(s):     {targets}")
        print(f"Scan Type:     {scan_type}")
        print(f"Timing:        T{timing}")
        print(f"Report Format: {report_format}")
        
        # Estimate time
        time_estimates = {
            "discovery": "< 1 minute",
            "quick": "1-2 minutes", 
            "comprehensive": "3-10 minutes",
            "full_tcp": "10+ minutes",
            "udp_top": "5-15 minutes"
        }
        
        estimated_time = time_estimates.get(scan_type, "Unknown")
        print(f"Estimated Time: {estimated_time}")
        
        # Security warning for certain scans
        if scan_type in ["comprehensive", "full_tcp"] and os.geteuid() != 0:
            print("\n⚠️  Warning: Not running as root")
            print("   Some features (OS detection, SYN scans) may not work optimally")
            print("   Consider running with 'sudo' for best results")
        
        print("\n" + "=" * 55)
        
        while True:
            confirm = input("Start scan? (y/n): ").strip().lower()
            if confirm in ['y', 'yes']:
                return True
            elif confirm in ['n', 'no']:
                return False
            else:
                print("Please enter 'y' or 'n'")

    def run_scan(self, targets, scan_type="comprehensive", timing=3):
        """Execute nmap scan"""
        print(f"\n🔍 Starting {scan_type} scan of {targets}...")
        
        scanner_script = self.scripts_dir / "scanning" / "nmap_scanner.py"
        if not scanner_script.exists():
            print(f"Error: Scanner script not found at {scanner_script}")
            return None
        
        cmd = [
            sys.executable, str(scanner_script),
            targets,
            "-t", scan_type,
            "-T", str(timing),
            "-o", str(self.output_dir / "xml" / "raw")
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            print("✅ Scan completed successfully")
            
            # Extract XML file path from output
            for line in result.stdout.split('\n'):
                if 'Results saved to:' in line:
                    xml_file = line.split('Results saved to:')[1].strip()
                    return Path(xml_file)
            
            return None
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Scan failed: {e}")
            print(f"Error output: {e.stderr}")
            return None
    
    def parse_results(self, xml_file):
        """Parse XML results to JSON"""
        if not xml_file or not xml_file.exists():
            print(f"❌ XML file not found: {xml_file}")
            return None
        
        print(f"\n📊 Parsing scan results from {xml_file.name}...")
        
        parser_script = self.scripts_dir / "parsing" / "xml_parser.py"
        if not parser_script.exists():
            print(f"Error: Parser script not found at {parser_script}")
            return None
        
        output_dir = self.output_dir / "processed"
        
        cmd = [
            sys.executable, str(parser_script),
            str(xml_file),
            "-o", str(output_dir),
            "--format", "json"
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            print("✅ Parsing completed successfully")
            
            # Find the generated JSON file
            base_name = xml_file.stem
            json_file = output_dir / f"{base_name}_parsed.json"
            
            if json_file.exists():
                return json_file
            else:
                print(f"❌ Expected JSON file not found: {json_file}")
                return None
                
        except subprocess.CalledProcessError as e:
            print(f"❌ Parsing failed: {e}")
            print(f"Error output: {e.stderr}")
            return None
    
    def generate_report(self, json_file, report_format="both"):
        """Generate reports from parsed data"""
        if not json_file or not json_file.exists():
            print(f"❌ JSON file not found: {json_file}")
            return False
        
        print(f"\n📋 Generating {report_format} report(s)...")
        
        reporter_script = self.scripts_dir / "reporting" / "report_generator.py"
        if not reporter_script.exists():
            print(f"Error: Reporter script not found at {reporter_script}")
            return False
        
        output_dir = self.output_dir / "reports"
        
        cmd = [
            sys.executable, str(reporter_script),
            str(json_file),
            "-o", str(output_dir),
            "--format", report_format
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            print("✅ Report generation completed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Report generation failed: {e}")
            print(f"Error output: {e.stderr}")
            return False
    
    def run_full_pipeline(self, targets, scan_type="comprehensive", timing=3, report_format="both"):
        """Run the complete pipeline"""
        start_time = time.time()
        
        print("\n🚀 Starting Network Mapping Pipeline")
        print("=" * 40)
        
        # Step 1: Run scan
        xml_file = self.run_scan(targets, scan_type, timing)
        if not xml_file:
            print("❌ Pipeline failed at scanning stage")
            return False
        
        # Step 2: Parse results
        json_file = self.parse_results(xml_file)
        if not json_file:
            print("❌ Pipeline failed at parsing stage")
            return False
        
        # Step 3: Generate report
        if not self.generate_report(json_file, report_format):
            print("❌ Pipeline failed at reporting stage")
            return False
        
        # Success summary
        end_time = time.time()
        duration = end_time - start_time
        
        print("\n" + "=" * 50)
        print("🎉 Pipeline completed successfully!")
        print(f"⏱️  Total time: {duration:.2f} seconds")
        print(f"📁 XML results: {xml_file}")
        print(f"📄 JSON data: {json_file}")
        print(f"📊 Reports: {self.output_dir / 'reports'}")
        
        # Find and display HTML report with clickable link
        html_files = list((self.output_dir / 'reports').glob("*report*.html"))
        if html_files:
            html_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
            html_file = html_files[0]
            print(f"🌐 HTML Report: file://{html_file.absolute()}")
            print(f"   Click to open: \033]8;;file://{html_file.absolute()}\033\\{html_file.name}\033]8;;\033\\")
        else:
            print("⚠️ No HTML reports found")
        
        # Show quick summary
        self._show_quick_summary(json_file)
        
        return True
    
    def _show_quick_summary(self, json_file):
        """Display a quick summary of results"""
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            insights = data.get('insights', {})
            
            print("\n📈 Quick Summary:")
            print(f"   Hosts scanned: {insights.get('total_hosts', 0)}")
            print(f"   Hosts online: {insights.get('hosts_up', 0)}")
            print(f"   Open ports: {insights.get('total_open_ports', 0)}")
            print(f"   Services found: {len(insights.get('unique_services', []))}")
            print(f"   Security issues: {len(insights.get('potential_issues', []))}")
            
            if insights.get('potential_issues'):
                print("\n⚠️  Top Security Concerns:")
                for issue in insights['potential_issues'][:3]:
                    print(f"   • {issue['host']}:{issue['port']} - {issue['issue']}")
                
                if len(insights['potential_issues']) > 3:
                    print(f"   ... and {len(insights['potential_issues']) - 3} more issues")
            
        except Exception as e:
            print(f"Could not load summary: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Complete Network Mapping Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode (recommended for new users)
  python3 pipeline.py
  
  # Command line mode (for automation)
  python3 pipeline.py 192.168.1.0/24
  python3 pipeline.py 10.0.0.0/8 -t quick --report text
  python3 pipeline.py 172.16.0.0/12 -t comprehensive -T 4
        """
    )
    
    parser.add_argument("targets", nargs='?', help="Target IP range or single IP (optional - will prompt if not provided)")
    parser.add_argument("-t", "--type", default="comprehensive",
                       choices=["quick", "comprehensive", "full_tcp", "udp_top", "discovery"],
                       help="Scan type (default: comprehensive)")
    parser.add_argument("-T", "--timing", type=int, default=3, choices=range(0, 6),
                       help="Timing template 0-5 (default: 3)")
    parser.add_argument("--report", choices=["html", "text", "both"], default="both",
                       help="Report format (default: both)")
    parser.add_argument("--scan-only", action="store_true",
                       help="Only run scan, skip parsing and reporting")
    parser.add_argument("--project-root", default=".",
                       help="Project root directory (default: current directory)")
    
    args = parser.parse_args()
    
    # Initialize pipeline
    pipeline = NetworkMappingPipeline(args.project_root)
    
    # Check if we should run in interactive mode
    if not args.targets:
        # No targets provided - run interactive mode
        success = pipeline.interactive_mode()
        sys.exit(0 if success else 1)
    
    # Command line mode (original functionality)
    if args.type in ["comprehensive", "full_tcp"] and os.geteuid() != 0:
        print("⚠️  Warning: Running without root privileges")
        print("   Some features (OS detection, SYN scans) may not work optimally")
        print("   Consider running with 'sudo' for best results")
        print()
    
    if args.scan_only:
        xml_file = pipeline.run_scan(args.targets, args.type, args.timing)
        if xml_file:
            print(f"✅ Scan completed. XML file: {xml_file}")
        else:
            sys.exit(1)
    else:
        success = pipeline.run_full_pipeline(
            args.targets, args.type, args.timing, args.report
        )
        
        if not success:
            sys.exit(1)

if __name__ == "__main__":
    main()
