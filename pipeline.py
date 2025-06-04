#!/usr/bin/env python3
"""
Complete Network Mapping Pipeline
Orchestrates scanning, parsing, and reporting in one command
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
        
    def run_scan(self, targets, scan_type="comprehensive", timing=3):
        """Execute nmap scan"""
        print(f"🔍 Starting {scan_type} scan of {targets}...")
        
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
        
        print(f"📊 Parsing scan results from {xml_file.name}...")
        
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
        
        print(f"📋 Generating {report_format} report(s)...")
        
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
        
        print("🚀 Starting Network Mapping Pipeline")
        print(f"Target: {targets}")
        print(f"Scan Type: {scan_type}")
        print(f"Timing: T{timing}")
        print(f"Report Format: {report_format}")
        print("-" * 50)
        
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
        
        # Find and display HTML report with clickable link - FIXED VERSION
        html_files = list((self.output_dir / 'reports').glob("*report*.html"))
        if html_files:
            # Sort by modification time, newest first
            html_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
            html_file = html_files[0]  # Get the newest by modification time
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
  # Basic scan of local network
  python3 pipeline.py 192.168.1.0/24
  
  # Quick scan with text report only
  python3 pipeline.py 10.0.0.0/8 -t quick --report text
  
  # Comprehensive scan with custom timing
  python3 pipeline.py 172.16.0.0/12 -t comprehensive -T 4
  
  # Discovery scan only
  python3 pipeline.py 192.168.1.1-254 -t discovery
        """
    )
    
    parser.add_argument("targets", help="Target IP range or single IP")
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
    
    # Check if running as root for certain scan types
    if args.type in ["comprehensive", "full_tcp"] and os.geteuid() != 0:
        print("⚠️  Warning: Running without root privileges")
        print("   Some features (OS detection, SYN scans) may not work optimally")
        print("   Consider running with 'sudo' for best results")
        print()
    
    if args.scan_only:
        # Run scan only
        xml_file = pipeline.run_scan(args.targets, args.type, args.timing)
        if xml_file:
            print(f"✅ Scan completed. XML file: {xml_file}")
            print(f"To continue processing: python3 {sys.argv[0]} --continue {xml_file}")
        else:
            sys.exit(1)
    else:
        # Run full pipeline
        success = pipeline.run_full_pipeline(
            args.targets, args.type, args.timing, args.report
        )
        
        if not success:
            sys.exit(1)

if __name__ == "__main__":
    main()
