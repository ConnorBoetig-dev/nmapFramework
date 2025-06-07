#!/usr/bin/env python3
"""
Network Mapper Framework - Main Pipeline
Interactive/CLI orchestrator for network scanning and analysis
"""

import sys
import os
import argparse
import webbrowser
import subprocess
import platform
from pathlib import Path
from datetime import datetime
import json
import importlib.util

# Color output support
try:
    from colorama import init, Fore, Back, Style

    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False

    # Fallback color classes
    class MockColor:
        def __getattr__(self, name):
            return ""

    Fore = Back = Style = MockColor()


def print_banner():
    """Display the tool banner"""
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════════╗{Style.RESET_ALL}
{Fore.CYAN}║{Style.RESET_ALL}     {Fore.YELLOW}🛡️  Network Security Scanner - Ultimate Pipeline  🛡️{Style.RESET_ALL}         {Fore.CYAN}║{Style.RESET_ALL}
{Fore.CYAN}╚═══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)


def print_section(title):
    """Print a formatted section header"""
    print(
        f"\n{Fore.BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Style.RESET_ALL}"
    )
    print(f"{Fore.BLUE}  {Fore.WHITE}{title}{Style.RESET_ALL}")
    print(
        f"{Fore.BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Style.RESET_ALL}"
    )


def get_scan_types():
    """Define available scan types with metadata"""
    return {
        "1": {
            "id": "quick",
            "name": "Quick Scan",
            "desc": "⚡ Fast scan of top 100 ports",
            "nmap_args": "-T3 -F --version-intensity 0",
            "time_per_host": 0.5,
            "base_time": 1,
            "requires_root": False,
        },
        "2": {
            "id": "comprehensive",
            "name": "Comprehensive Scan",
            "desc": "🔍 Detailed service detection with OS fingerprinting",
            "nmap_args": "-T3 -sT -sV -A --version-intensity 5",
            "time_per_host": 2,
            "base_time": 5,
            "requires_root": False,
        },
        "3": {
            "id": "full_tcp",
            "name": "Full TCP Scan",
            "desc": "🌐 All 65535 TCP ports",
            "nmap_args": "-T3 -sT -sV -p- --version-intensity 3",
            "time_per_host": 15,
            "base_time": 10,
            "requires_root": False,
        },
        "4": {
            "id": "vulnerability_scan",
            "name": "Vulnerability Scan",
            "desc": "🚨 NSE vulnerability scripts",
            "nmap_args": "-T3 -sT -sV --script=vuln --top-ports 2000",
            "time_per_host": 5,
            "base_time": 10,
            "requires_root": False,
        },
        "5": {
            "id": "web_discovery",
            "name": "Web Discovery",
            "desc": "🌐 Web services enumeration",
            "nmap_args": "-T3 -sT -sV --script=http-*,ssl-* -p 80,443,8080",
            "time_per_host": 2,
            "base_time": 3,
            "requires_root": False,
        },
        "6": {
            "id": "database_discovery",
            "name": "Database Discovery",
            "desc": "🗄️ Database services detection",
            "nmap_args": "-T3 -sT -sV --script=*sql*,*db* -p 1433,3306,5432",
            "time_per_host": 1,
            "base_time": 2,
            "requires_root": False,
        },
        "7": {
            "id": "stealth_scan",
            "name": "Stealth Scan",
            "desc": "🥷 SYN stealth scan",
            "nmap_args": "-T2 -sS -sV -f --randomize-hosts",
            "time_per_host": 3,
            "base_time": 5,
            "requires_root": True,
        },
        "8": {
            "id": "udp_scan",
            "name": "UDP Scan",
            "desc": "📡 UDP top 100 ports",
            "nmap_args": "-T3 -sU --top-ports 100 -sV",
            "time_per_host": 10,
            "base_time": 5,
            "requires_root": True,
        },
        "9": {
            "id": "everything_with_vuln",
            "name": "Ultimate Scan",
            "desc": "💥 Everything + vulnerabilities",
            "nmap_args": "-T3 -sT -sV -A -p- --script=default,vuln,http-*",
            "time_per_host": 30,
            "base_time": 15,
            "requires_root": False,
        },
    }


def estimate_scan_time(target, scan_type):
    """Estimate scan time based on target and scan type"""
    scan_types = get_scan_types()

    if scan_type not in scan_types:
        return "Unknown"

    config = scan_types[scan_type]

    # Simple host count estimation
    if "/" in target:
        # CIDR notation
        if "/24" in target:
            host_count = 254
        elif "/16" in target:
            host_count = 65534
        else:
            host_count = 50  # Conservative estimate
    elif "," in target:
        # Multiple hosts
        host_count = len(target.split(","))
    else:
        # Single host
        host_count = 1

    # Calculate time
    total_time = config["base_time"] + (host_count * config["time_per_host"])

    if total_time < 1:
        return "< 1 minute"
    elif total_time < 60:
        return f"{int(total_time)} minutes"
    else:
        hours = int(total_time // 60)
        minutes = int(total_time % 60)
        return f"{hours}h {minutes}m"


def validate_target(target):
    """Basic target validation"""
    if not target.strip():
        return False, "Target cannot be empty"

    # Add more validation as needed
    return True, "Valid target"


def check_previous_scans(target):
    """Check for previous scans of the same target"""
    previous_scans = []
    processed_dir = Path("output/processed")

    if not processed_dir.exists():
        return previous_scans

    # Normalize target for comparison
    target_normalized = target.strip().lower()

    # Look for JSON files in processed directory
    for json_file in sorted(
        processed_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True
    ):
        try:
            with open(json_file, "r") as f:
                data = json.load(f)

            # Get scan target from metadata
            scan_target = data.get("scan_metadata", {}).get("target", "")

            # Check if targets match (simple comparison, could be enhanced)
            if scan_target.strip().lower() == target_normalized:
                previous_scans.append(
                    {
                        "file": json_file,
                        "path": str(json_file),
                        "date": data["scan_info"].get("scan_date", "Unknown"),
                        "type": data["scan_metadata"].get("scan_type", "unknown"),
                        "hosts_up": data["insights"].get("hosts_up", 0),
                        "open_ports": data["insights"].get("total_open_ports", 0),
                    }
                )
        except Exception:
            # Skip files that can't be read or parsed
            continue

    return previous_scans


def interactive_mode():
    """Run interactive mode for target and scan selection"""
    print_banner()

    # Target selection
    print_section("🎯 Target Selection")
    print("\nEnter the target to scan:")
    print("  • Single IP: 192.168.1.100")
    print("  • Network range: 192.168.1.0/24")
    print("  • Multiple IPs: 192.168.1.1,192.168.1.2")
    print("  • Hostname: example.com")

    while True:
        target = input(f"\n{Fore.GREEN}Target ▸{Style.RESET_ALL} ").strip()
        is_valid, message = validate_target(target)
        if is_valid:
            print(f"{Fore.GREEN}✓{Style.RESET_ALL} {message}")
            break
        else:
            print(f"{Fore.RED}✗{Style.RESET_ALL} {message}")

    # Check for previous scans of this target
    compare_with_previous = None
    previous_scans = check_previous_scans(target)

    if previous_scans:
        print_section("📊 Previous Scan Detection")
        print(
            f"\n{Fore.CYAN}🔍 Found {len(previous_scans)} previous scan(s) of this target:{Style.RESET_ALL}"
        )

        # Show up to 5 most recent scans
        for i, scan in enumerate(previous_scans[:5], 1):
            print(
                f"\n  {Fore.YELLOW}{i}.{Style.RESET_ALL} {scan['date']} - {scan['type']} scan"
            )
            print(f"     • Hosts up: {scan['hosts_up']}")
            print(f"     • Open ports: {scan['open_ports']}")

        if len(previous_scans) > 5:
            print(
                f"\n  {Fore.BLUE}... and {len(previous_scans) - 5} more older scan(s){Style.RESET_ALL}"
            )

        compare_choice = (
            input(
                f"\n{Fore.GREEN}Compare with a previous scan? [y/N] ▸{Style.RESET_ALL} "
            )
            .strip()
            .lower()
        )

        if compare_choice == "y":
            if len(previous_scans) == 1:
                compare_with_previous = previous_scans[0]["path"]
                print(
                    f"{Fore.GREEN}✓{Style.RESET_ALL} Will compare with scan from {previous_scans[0]['date']}"
                )
            else:
                # Let user select which scan
                while True:
                    scan_num = input(
                        f"\n{Fore.GREEN}Select scan to compare with [1-{min(5, len(previous_scans))}] ▸{Style.RESET_ALL} "
                    ).strip()
                    try:
                        idx = int(scan_num) - 1
                        if 0 <= idx < min(5, len(previous_scans)):
                            compare_with_previous = previous_scans[idx]["path"]
                            print(
                                f"{Fore.GREEN}✓{Style.RESET_ALL} Will compare with scan from {previous_scans[idx]['date']}"
                            )
                            break
                        else:
                            print(
                                f"{Fore.RED}✗{Style.RESET_ALL} Please select a number between 1 and {min(5, len(previous_scans))}"
                            )
                    except ValueError:
                        print(
                            f"{Fore.RED}✗{Style.RESET_ALL} Please enter a valid number"
                        )
    else:
        print(
            f"\n{Fore.BLUE}ℹ️  No previous scans found for target: {target}{Style.RESET_ALL}"
        )

    # Scan type selection
    print_section("🔍 Scan Type Selection")
    scan_types = get_scan_types()

    for key, config in scan_types.items():
        time_est = estimate_scan_time(target, key)
        root_req = (
            f" {Fore.RED}(requires root){Style.RESET_ALL}"
            if config["requires_root"]
            else ""
        )

        print(
            f"\n  {Fore.YELLOW}{key}.{Style.RESET_ALL} {Fore.WHITE}{config['name']}{Style.RESET_ALL}"
        )
        print(f"     {config['desc']}")
        print(f"     {Fore.BLUE}Time estimate:{Style.RESET_ALL} {time_est}{root_req}")
        print(
            f"     {Fore.BLUE}Nmap command:{Style.RESET_ALL} nmap {config['nmap_args']} <target>"
        )

    while True:
        choice = input(
            f"\n{Fore.GREEN}Select scan type [1-{len(scan_types)}] ▸{Style.RESET_ALL} "
        ).strip()
        if choice in scan_types:
            selected_scan = scan_types[choice]
            time_est = estimate_scan_time(target, choice)
            print(
                f"{Fore.GREEN}✓{Style.RESET_ALL} Selected: {selected_scan['name']} (estimated {time_est})"
            )
            break
        else:
            print(
                f"{Fore.RED}✗{Style.RESET_ALL} Invalid choice. Please select 1-{len(scan_types)}"
            )

    # Report format selection
    print_section("📊 Report Format")
    print("  1. HTML (interactive report)")
    print("  2. Text (terminal-friendly)")
    print("  3. CSV (spreadsheet-friendly)")
    print("  4. All formats")

    while True:
        format_choice = input(
            f"\n{Fore.GREEN}Select format [1-4] ▸{Style.RESET_ALL} "
        ).strip()
        if format_choice == "1":
            report_format = "html"
            break
        elif format_choice == "2":
            report_format = "text"
            break
        elif format_choice == "3":
            report_format = "csv"
            break
        elif format_choice == "4":
            report_format = "all"
            break
        else:
            print(f"{Fore.RED}✗{Style.RESET_ALL} Invalid choice. Please select 1-4")

    return target, selected_scan["id"], report_format, compare_with_previous


def check_root_required(scan_type):
    """Check if scan type requires root privileges"""
    scan_types = get_scan_types()
    for key, config in scan_types.items():
        if config["id"] == scan_type:
            return config["requires_root"]
    return False


def elevate_privileges():
    """Re-run script with sudo if needed"""
    if os.geteuid() != 0:
        print(
            f"{Fore.YELLOW}⚠️  This scan type requires root privileges.{Style.RESET_ALL}"
        )
        print("Re-running with sudo...")

        # Preserve virtual environment
        venv_python = sys.executable
        args = ["/usr/bin/sudo", venv_python] + sys.argv

        try:
            os.execv("/usr/bin/sudo", args)
        except OSError as e:
            print(f"{Fore.RED}Error elevating privileges: {e}{Style.RESET_ALL}")
            sys.exit(1)


def run_scan_pipeline(
    target, scan_type, report_format, xml_file=None, no_open=False, compare_with=None
):
    """Execute the complete scanning pipeline"""

    # Check root requirements
    if check_root_required(scan_type) and os.geteuid() != 0:
        elevate_privileges()

    # Import scanning modules with better error handling
    current_dir = Path(__file__).parent
    scripts_dir = current_dir / "scripts"
    
    # Ensure we're working with absolute paths
    scripts_dir = scripts_dir.resolve()
    
    # Add all necessary paths to Python's import path
    # Using insert(0, ...) to prioritize our modules
    sys.path.insert(0, str(current_dir))
    sys.path.insert(0, str(scripts_dir))
    
    # Add each subdirectory
    for subdir in ['scanning', 'parsing', 'reporting', 'analysis', 'visualization']:
        subdir_path = scripts_dir / subdir
        if subdir_path.exists():
            sys.path.insert(0, str(subdir_path))
    
    # Now try to import
    try:
        # Try absolute import first
        try:
            from scripts.scanning.nmap_scanner import NetworkScanner
            from scripts.parsing.xml_parser import NmapXMLParser
            from scripts.reporting.report_generator import ReportGenerator
        except ImportError as e:
            # Fall back to direct import
            try:
                from nmap_scanner import NetworkScanner
                from xml_parser import NmapXMLParser
                from report_generator import ReportGenerator
            except ImportError as e2:
                # Both imports failed, show detailed error
                raise ImportError(f"Absolute import failed: {e}\nDirect import failed: {e2}")
            
    except ImportError as e:
        print(f"{Fore.RED}Error importing modules: {e}{Style.RESET_ALL}")
        
        # Detailed debugging information
        print(f"\n{Fore.YELLOW}Debug Information:{Style.RESET_ALL}")
        print(f"Current directory: {os.getcwd()}")
        print(f"Script location: {Path(__file__).resolve()}")
        print(f"Looking for modules in: {scripts_dir}")
        print(f"Python path: {sys.path}")
        
        # Check if files exist
        files_to_check = [
            scripts_dir / "scanning" / "nmap_scanner.py",
            scripts_dir / "parsing" / "xml_parser.py",
            scripts_dir / "reporting" / "report_generator.py"
        ]
        
        for file_path in files_to_check:
            if file_path.exists():
                print(f"{Fore.GREEN}✓{Style.RESET_ALL} Found: {file_path}")
                # Try to import the file directly to see what error we get
                try:
                    import importlib.util
                    spec = importlib.util.spec_from_file_location("test_module", file_path)
                    test_module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(test_module)
                    print(f"  {Fore.GREEN}✓{Style.RESET_ALL} File can be loaded")
                except Exception as file_error:
                    print(f"  {Fore.RED}✗{Style.RESET_ALL} Error loading file: {file_error}")
            else:
                print(f"{Fore.RED}✗{Style.RESET_ALL} Missing: {file_path}")
        
        # Check for common dependencies
        print(f"\n{Fore.YELLOW}Checking dependencies:{Style.RESET_ALL}")
        try:
            import nmap
            print(f"{Fore.GREEN}✓{Style.RESET_ALL} python-nmap is installed")
        except ImportError:
            print(f"{Fore.RED}✗{Style.RESET_ALL} python-nmap is NOT installed - run: pip install python-nmap")
        
        try:
            import jinja2
            print(f"{Fore.GREEN}✓{Style.RESET_ALL} jinja2 is installed")
        except ImportError:
            print(f"{Fore.RED}✗{Style.RESET_ALL} jinja2 is NOT installed - run: pip install jinja2")
        
        try:
            import lxml
            print(f"{Fore.GREEN}✓{Style.RESET_ALL} lxml is installed")
        except ImportError:
            print(f"{Fore.RED}✗{Style.RESET_ALL} lxml is NOT installed - run: pip install lxml")
        
        sys.exit(1)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Step 1: Scanning (or use existing XML)
    if xml_file:
        print(f"{Fore.BLUE}📄 Using existing XML file: {xml_file}{Style.RESET_ALL}")
        scan_file = xml_file
    else:
        print(
            f"{Fore.BLUE}🚀 Starting {scan_type} scan of {target}...{Style.RESET_ALL}"
        )

        scanner = NetworkScanner()

        # Map scan_type to timing if needed
        timing_map = {
            "quick": 3,
            "comprehensive": 3,
            "full_tcp": 3,
            "vulnerability_scan": 3,
            "web_discovery": 3,
            "database_discovery": 3,
            "stealth_scan": 2,
            "udp_scan": 3,
            "everything_with_vuln": 3,
        }
        timing = timing_map.get(scan_type, 3)

        scan_file = scanner.scan_network(target, scan_type, timing=timing)

        if not scan_file or not Path(scan_file).exists():
            print(f"{Fore.RED}❌ Scan failed or no output generated{Style.RESET_ALL}")
            sys.exit(1)

        print(f"{Fore.GREEN}✅ Scan completed: {scan_file}{Style.RESET_ALL}")

    # Step 2: Parsing
    print(f"{Fore.BLUE}🔄 Parsing scan results...{Style.RESET_ALL}")

    parser = NmapXMLParser()

    # Parse the XML file
    if not parser.parse_xml(scan_file):
        print(f"{Fore.RED}❌ Parsing failed{Style.RESET_ALL}")
        sys.exit(1)

    # Generate parsed JSON file with timestamp
    output_dir = Path("output/processed")
    output_dir.mkdir(parents=True, exist_ok=True)
    parsed_file = output_dir / f"scan_{scan_type}_{timestamp}_parsed.json"
    parser.export_to_json(parsed_file)

    print(f"{Fore.GREEN}✅ Parsing completed: {parsed_file}{Style.RESET_ALL}")

    # Step 2.5: Device Classification and Hardware Inventory
    if not no_open:  # Only run interactively if not in batch mode
        print_section("🔧 Asset Inventory & Classification")

        # Device Classification
        print(f"{Fore.BLUE}🤖 Running device classification...{Style.RESET_ALL}")
        try:
            from device_classifier import DeviceClassifier

            classifier = DeviceClassifier()

            # Load parsed data
            with open(parsed_file, "r") as f:
                scan_data = json.load(f)

            # Classify each host
            for host in scan_data["hosts"]:
                classification = classifier.classify_device(host)
                host["device_classification"] = classification

                ip = host["addresses"].get("ipv4", "unknown")
                print(
                    f"  {ip}: {classification['device_type']} (confidence: {classification['confidence']})"
                )

            # Ask about hardware inventory
            inventory_choice = (
                input(
                    f"\n{Fore.GREEN}Run hardware & certificate inventory for discovered hosts? [Y/n] ▸{Style.RESET_ALL} "
                )
                .strip()
                .lower()
            )

            if inventory_choice != "n":
                from hardware_inventory import HardwareInventory

                # Check for config file
                config_file = Path("config/config.yml")
                if not config_file.exists():
                    config_file = None
                    print(
                        f"{Fore.YELLOW}ℹ️  No config file found. Will prompt for credentials.{Style.RESET_ALL}"
                    )

                inventory = HardwareInventory(config_file)

                # Enrich hosts with hardware data
                print(
                    f"\n{Fore.CYAN}⏱️  This may take several minutes depending on network size and response times...{Style.RESET_ALL}"
                )
                enriched_hosts = inventory.enrich_hosts(scan_data["hosts"])
                scan_data["hosts"] = enriched_hosts

                # Count enriched hosts
                enriched_count = sum(
                    1 for h in enriched_hosts if h.get("hardware_info")
                )
                print(
                    f"\n{Fore.GREEN}📊 Enriched {enriched_count}/{len(enriched_hosts)} hosts with hardware data{Style.RESET_ALL}"
                )

            # Save enriched data back
            with open(parsed_file, "w") as f:
                json.dump(scan_data, f, indent=2)

        except ImportError as e:
            print(
                f"{Fore.YELLOW}⚠️  Asset inventory modules not available: {e}{Style.RESET_ALL}"
            )
            print("Continuing with basic parsing only...")
        except Exception as e:
            print(f"{Fore.RED}❌ Error during asset inventory: {e}{Style.RESET_ALL}")
            print("Continuing with report generation...")

    # Step 2.6: Network Topology Mapping
    if not no_open:  # Only run interactively if not in batch mode
        print_section("🗺️ Network Topology Mapping")

        topology_choice = (
            input(
                f"\n{Fore.GREEN}Generate network topology visualization? [Y/n] ▸{Style.RESET_ALL} "
            )
            .strip()
            .lower()
        )

        if topology_choice != "n":
            print(f"{Fore.BLUE}🔍 Analyzing network topology...{Style.RESET_ALL}")

            try:
                from network_mapper import NetworkTopologyMapper
                from subnet_analyzer import SubnetAnalyzer

                # Create topology mapper
                mapper = NetworkTopologyMapper()

                # Analyze topology
                topology_data = mapper.analyze_topology(scan_data)

                # Save topology data to the scan
                scan_data["network_topology"] = topology_data

                # Generate visualizations
                topo_dir = Path("output/topology")
                topo_dir.mkdir(parents=True, exist_ok=True)

                # Interactive Plotly visualization
                plotly_file = topo_dir / f"topology_{timestamp}.html"
                fig = mapper.generate_plotly_visualization(
                    str(plotly_file), title=f"Network Topology - {target}"
                )

                print(
                    f"{Fore.GREEN}✅ Interactive topology map generated{Style.RESET_ALL}"
                )

                # Also generate static PNG
                png_file = topo_dir / f"topology_{timestamp}.png"
                mapper.generate_matplotlib_visualization(str(png_file))

                # Subnet analysis
                subnet_analyzer = SubnetAnalyzer()
                subnet_analysis = subnet_analyzer.analyze_network_segments(scan_data)
                scan_data["subnet_analysis"] = subnet_analysis

                # Print summary
                print(f"\n{Fore.CYAN}📊 Topology Summary:{Style.RESET_ALL}")
                print(
                    f"  • Network Segments: {len(topology_data['stats']['segments'])}"
                )
                print(
                    f"  • Subnets Detected: {topology_data['stats']['total_subnets']}"
                )
                print(
                    f"  • Gateway Devices: {topology_data['stats']['gateway_devices']}"
                )

                if subnet_analysis["vlan_hints"].get("potential_vlans"):
                    print(
                        f"  • Potential VLANs: {len(subnet_analysis['vlan_hints']['potential_vlans'])}"
                    )

                # Save enriched data back
                with open(parsed_file, "w") as f:
                    json.dump(scan_data, f, indent=2)

            except ImportError as e:
                print(
                    f"{Fore.YELLOW}⚠️ Topology mapping modules not available: {e}{Style.RESET_ALL}"
                )
                print("Install requirements: pip install networkx plotly matplotlib")
            except Exception as e:
                print(
                    f"{Fore.RED}❌ Error during topology mapping: {e}{Style.RESET_ALL}"
                )
                print("Continuing with report generation...")

    # Step 3: Report Generation
    print(f"{Fore.BLUE}📊 Generating reports...{Style.RESET_ALL}")

    generator = ReportGenerator(parsed_file)
    reports = generator.generate_reports(report_format, timestamp, no_open)

    if reports:
        print(f"{Fore.GREEN}✅ Reports generated:{Style.RESET_ALL}")
        for report in reports:
            print(f"   📄 {report}")

        # Auto-open HTML report if generated
        if not no_open and report_format in ["html", "all"]:
            html_report = next((r for r in reports if r.endswith(".html")), None)
            if html_report:
                try:
                    webbrowser.open(f"file://{Path(html_report).absolute()}")
                    print(
                        f"{Fore.BLUE}🌐 Opening report in browser...{Style.RESET_ALL}"
                    )
                except Exception as e:
                    print(
                        f"{Fore.YELLOW}⚠️  Could not auto-open browser: {e}{Style.RESET_ALL}"
                    )
                    print(f"   Manual open: file://{Path(html_report).absolute()}")
    else:
        print(f"{Fore.RED}❌ Report generation failed{Style.RESET_ALL}")
        sys.exit(1)

    # Step 4: Run comparison if requested
    if compare_with:
        print(f"\n{Fore.BLUE}🔄 Running comparison analysis...{Style.RESET_ALL}")
        print(
            f"{Fore.BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Style.RESET_ALL}"
        )

        # First, let's make sure the scan report opened (give it a moment)
        import time

        time.sleep(1)

        # Run diff analysis
        run_diff_analysis(
            base_file=compare_with,
            compare_file=str(parsed_file),
            output_format="html",
            output_dir="output/reports/diffs",
        )

    return parsed_file


def run_diff_analysis(
    base_file,
    compare_file,
    output_format,
    output_dir="output/reports/diffs",
    suppress_browser_errors=True,
):
    """Execute scan comparison analysis"""

    # Import diff module
    scripts_dir = Path(__file__).parent / "scripts"
    sys.path.append(str(scripts_dir / "analysis"))

    try:
        from diff_scanner import ScanDiffer
    except ImportError as e:
        print(f"{Fore.RED}Error importing diff module: {e}{Style.RESET_ALL}")
        print("Make sure diff_scanner.py is in scripts/analysis/")
        sys.exit(1)

    print(f"{Fore.BLUE}🔄 Loading scan files for comparison...{Style.RESET_ALL}")

    # Validate input files
    if not Path(base_file).exists():
        print(f"{Fore.RED}❌ Base file not found: {base_file}{Style.RESET_ALL}")
        sys.exit(1)

    if not Path(compare_file).exists():
        print(f"{Fore.RED}❌ Compare file not found: {compare_file}{Style.RESET_ALL}")
        sys.exit(1)

    # Create diff analyzer
    differ = ScanDiffer()

    if not differ.load_scans(base_file, compare_file):
        print(f"{Fore.RED}❌ Failed to load scan files{Style.RESET_ALL}")
        sys.exit(1)

    print(f"{Fore.BLUE}📊 Analyzing differences...{Style.RESET_ALL}")
    differ.analyze_diff()

    # Create output directory
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Generate reports
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    generated_files = []

    if output_format in ["html", "both"]:
        html_file = output_path / f"diff_report_{timestamp}.html"
        differ.export_to_html(html_file)
        generated_files.append(str(html_file))

        # Auto-open HTML report with error suppression
        try:
            # Add small delay to ensure previous report had time to open
            import time

            time.sleep(0.5)

            # Create subprocess kwargs to suppress stderr
            kwargs = {}
            if suppress_browser_errors and platform.system() != "Windows":
                kwargs["stderr"] = subprocess.DEVNULL
                kwargs["stdout"] = subprocess.DEVNULL

            if platform.system() == "Darwin":  # macOS
                subprocess.call(["open", str(html_file.absolute())], **kwargs)
            elif platform.system() == "Windows":  # Windows
                os.startfile(str(html_file))
            else:  # Linux/Unix
                try:
                    subprocess.call(
                        ["xdg-open", f"file://{html_file.absolute()}"], **kwargs
                    )
                except:
                    # Fallback to webbrowser
                    webbrowser.open(f"file://{html_file.absolute()}")

            print(f"{Fore.BLUE}🌐 Opening diff report in browser...{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}⚠️  Could not auto-open browser{Style.RESET_ALL}")

    if output_format in ["csv", "both"]:
        csv_file = output_path / f"diff_report_{timestamp}.csv"
        differ.export_to_csv(csv_file)
        generated_files.append(str(csv_file))

    # Print summary
    summary = differ.diff_results["summary"]
    print(f"\n{Fore.GREEN}✅ Diff Analysis Complete:{Style.RESET_ALL}")
    print(
        f"  📊 Hosts: {Fore.GREEN}+{summary['hosts_added']}{Style.RESET_ALL} / {Fore.RED}-{summary['hosts_removed']}{Style.RESET_ALL}"
    )
    print(
        f"  📊 Ports: {Fore.GREEN}+{summary['ports_added']}{Style.RESET_ALL} / {Fore.RED}-{summary['ports_removed']}{Style.RESET_ALL}"
    )
    print(
        f"  📊 Services Changed: {Fore.YELLOW}{summary['services_changed']}{Style.RESET_ALL}"
    )

    print(f"\n{Fore.GREEN}📄 Generated Reports:{Style.RESET_ALL}")
    for file_path in generated_files:
        print(f"   {file_path}")


def main():
    """Main entry point with argument parsing"""

    # Create main parser
    parser = argparse.ArgumentParser(
        description="Network Security Scanner Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Interactive mode:
    python3 pipeline.py

  Quick scan:
    python3 pipeline.py 192.168.1.1 -t quick --format html

  Compare scans:
    python3 pipeline.py diff --base old_scan.json --compare new_scan.json

  Process existing XML:
    python3 pipeline.py --xml-file scan_results.xml
        """,
    )

    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command (default)
    scan_parser = subparsers.add_parser("scan", help="Perform network scan")
    scan_parser.add_argument(
        "target", nargs="?", help="Target to scan (IP, hostname, or CIDR)"
    )
    scan_parser.add_argument(
        "-t",
        "--type",
        dest="scan_type",
        choices=[config["id"] for config in get_scan_types().values()],
        help="Scan type",
    )
    scan_parser.add_argument(
        "--format",
        choices=["html", "text", "csv", "all"],
        default="html",
        help="Report format",
    )
    scan_parser.add_argument(
        "--xml-file", help="Process existing XML file instead of scanning"
    )
    scan_parser.add_argument(
        "--no-open", action="store_true", help="Don't auto-open HTML reports"
    )

    # Diff command
    diff_parser = subparsers.add_parser("diff", help="Compare two scan results")
    diff_parser.add_argument("--base", required=True, help="Base scan JSON file")
    diff_parser.add_argument("--compare", required=True, help="Compare scan JSON file")
    diff_parser.add_argument(
        "--format",
        choices=["html", "csv", "both"],
        default="html",
        help="Output format for diff report",
    )
    diff_parser.add_argument(
        "-o",
        "--output",
        default="output/reports/diffs",
        help="Output directory for diff reports",
    )

    # For backward compatibility, also support direct arguments (no subcommand)
    parser.add_argument(
        "target", nargs="?", help="Target to scan (IP, hostname, or CIDR)"
    )
    parser.add_argument(
        "-t",
        "--type",
        dest="scan_type",
        choices=[config["id"] for config in get_scan_types().values()],
        help="Scan type",
    )
    parser.add_argument(
        "--format",
        choices=["html", "text", "csv", "all"],
        default="html",
        help="Report format",
    )
    parser.add_argument(
        "--xml-file", help="Process existing XML file instead of scanning"
    )
    parser.add_argument(
        "--no-open", action="store_true", help="Don't auto-open HTML reports"
    )

    args = parser.parse_args()

    # Handle diff command
    if args.command == "diff":
        run_diff_analysis(args.base, args.compare, args.format, args.output)
        return

    # Handle scan command or direct arguments (backward compatibility)
    if args.command == "scan" or args.command is None:
        # Interactive mode if no target specified
        if not args.target and not args.xml_file:
            result = interactive_mode()
            if len(result) == 4:
                target, scan_type, report_format, compare_with = result
            else:
                # Backward compatibility if interactive_mode returns 3 values
                target, scan_type, report_format = result
                compare_with = None
            no_open = False
            
            # Run the scan pipeline
            run_scan_pipeline(target, scan_type, report_format, compare_with=compare_with, no_open=no_open)
        else:
            # CLI mode
            if args.xml_file:
                target = None
                scan_type = "existing"
                report_format = args.format
            else:
                target = args.target
                scan_type = args.scan_type
                report_format = args.format

                if not target:
                    print(
                        f"{Fore.RED}Error: Target required for scanning{Style.RESET_ALL}"
                    )
                    parser.print_help()
                    sys.exit(1)

                if not scan_type:
                    print(
                        f"{Fore.RED}Error: Scan type required. Use -t/--type{Style.RESET_ALL}"
                    )
                    parser.print_help()
                    sys.exit(1)

            no_open = args.no_open
            compare_with = None
            
            # Run the scan pipeline
            run_scan_pipeline(target, scan_type, report_format, xml_file=args.xml_file, 
                            no_open=no_open, compare_with=compare_with)

    else:
        parser.print_help()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⚠️  Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}❌ Unexpected error: {e}{Style.RESET_ALL}")
        sys.exit(1)