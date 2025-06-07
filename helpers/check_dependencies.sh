#!/usr/bin/env python3
"""
Quick dependency checker for Network Mapper Framework
"""

import sys
import subprocess
from pathlib import Path

# Color support
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORS = True
except ImportError:
    COLORS = False
    class MockColor:
        def __getattr__(self, name):
            return ""
    Fore = Style = MockColor()

def check_system_command(command):
    """Check if a system command is available"""
    try:
        result = subprocess.run([command, "--version"], capture_output=True, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False

def check_python_package(package_name, import_name=None):
    """Check if a Python package is installed"""
    if import_name is None:
        import_name = package_name
    
    try:
        __import__(import_name)
        return True
    except ImportError:
        return False

def main():
    print(f"\n{Fore.CYAN}🔍 Network Mapper Framework - Dependency Check{Style.RESET_ALL}")
    print("=" * 60)
    
    # Check Python version
    python_version = sys.version_info
    print(f"\n{Fore.YELLOW}Python Version:{Style.RESET_ALL}")
    if python_version >= (3, 7):
        print(f"{Fore.GREEN}✓{Style.RESET_ALL} Python {python_version.major}.{python_version.minor}.{python_version.micro}")
    else:
        print(f"{Fore.RED}✗{Style.RESET_ALL} Python {python_version.major}.{python_version.minor}.{python_version.micro} (3.7+ required)")
    
    # Check system dependencies
    print(f"\n{Fore.YELLOW}System Dependencies:{Style.RESET_ALL}")
    
    if check_system_command("nmap"):
        print(f"{Fore.GREEN}✓{Style.RESET_ALL} nmap is installed")
    else:
        print(f"{Fore.RED}✗{Style.RESET_ALL} nmap is NOT installed - Install with: sudo apt install nmap")
    
    # Check Python packages
    print(f"\n{Fore.YELLOW}Python Packages:{Style.RESET_ALL}")
    
    packages = [
        ("colorama", None, "Terminal colors"),
        ("python-nmap", "nmap", "Nmap Python wrapper"),
        ("lxml", None, "XML parsing"),
        ("jinja2", None, "HTML templating"),
        ("pandas", None, "Data analysis (optional)"),
        ("beautifulsoup4", "bs4", "HTML parsing (optional)"),
        ("tqdm", None, "Progress bars (optional)"),
        ("networkx", None, "Network topology (optional)"),
        ("plotly", None, "Interactive visualizations (optional)"),
        ("matplotlib", None, "Static visualizations (optional)"),
    ]
    
    required_missing = []
    optional_missing = []
    
    for package, import_name, description in packages:
        is_optional = "(optional)" in description
        if check_python_package(package, import_name):
            print(f"{Fore.GREEN}✓{Style.RESET_ALL} {package:20s} - {description}")
        else:
            print(f"{Fore.RED}✗{Style.RESET_ALL} {package:20s} - {description}")
            if is_optional:
                optional_missing.append(package)
            else:
                required_missing.append(package)
    
    # Check project structure
    print(f"\n{Fore.YELLOW}Project Structure:{Style.RESET_ALL}")
    
    project_root = Path(__file__).resolve().parent.parent
    scripts_dir = project_root / "scripts"
    
    required_files = [
        project_root / "pipeline.py",
        scripts_dir / "scanning" / "nmap_scanner.py",
        scripts_dir / "parsing" / "xml_parser.py",
        scripts_dir / "reporting" / "report_generator.py",
        project_root / "requirements.txt",
    ]
    
    for file_path in required_files:
        if file_path.exists():
            print(f"{Fore.GREEN}✓{Style.RESET_ALL} {file_path.relative_to(project_root)}")
        else:
            print(f"{Fore.RED}✗{Style.RESET_ALL} {file_path.relative_to(project_root)} - MISSING!")
    
    # Summary and recommendations
    print(f"\n{Fore.CYAN}Summary:{Style.RESET_ALL}")
    print("=" * 60)
    
    if required_missing:
        print(f"\n{Fore.RED}❌ Missing REQUIRED packages:{Style.RESET_ALL}")
        print(f"   Run: pip install {' '.join(required_missing)}")
    else:
        print(f"\n{Fore.GREEN}✅ All required dependencies are installed!{Style.RESET_ALL}")
    
    if optional_missing:
        print(f"\n{Fore.YELLOW}⚠️  Missing optional packages:{Style.RESET_ALL}")
        print(f"   For full functionality, run: pip install {' '.join(optional_missing)}")
    
    # Quick install command
    print(f"\n{Fore.CYAN}Quick install all dependencies:{Style.RESET_ALL}")
    print(f"   pip install -r requirements.txt")
    
    # Test imports
    print(f"\n{Fore.YELLOW}Testing module imports:{Style.RESET_ALL}")
    
    # Add script subfolders to path
    sys.path.insert(0, str(scripts_dir / "scanning"))
    sys.path.insert(0, str(scripts_dir / "parsing"))
    sys.path.insert(0, str(scripts_dir / "reporting"))
    
    try:
        from nmap_scanner import NetworkScanner
        print(f"{Fore.GREEN}✓{Style.RESET_ALL} Can import NetworkScanner")
    except Exception as e:
        print(f"{Fore.RED}✗{Style.RESET_ALL} Cannot import NetworkScanner: {e}")
    
    try:
        from xml_parser import NmapXMLParser
        print(f"{Fore.GREEN}✓{Style.RESET_ALL} Can import NmapXMLParser")
    except Exception as e:
        print(f"{Fore.RED}✗{Style.RESET_ALL} Cannot import NmapXMLParser: {e}")
    
    try:
        from report_generator import ReportGenerator
        print(f"{Fore.GREEN}✓{Style.RESET_ALL} Can import ReportGenerator")
    except Exception as e:
        print(f"{Fore.RED}✗{Style.RESET_ALL} Cannot import ReportGenerator: {e}")
    
    print("\n" + "=" * 60)
    print(f"{Fore.CYAN}Check complete!{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()
