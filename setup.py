#!/usr/bin/env python3
"""
Network Scanner - Automated Dependency Setup
Handles both system packages and Python dependencies
"""

import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    """Display setup banner"""
    banner = f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║     🔧  Network Scanner - Dependency Setup  🔧                    ║
║                                                                   ║
║     This script will install all required dependencies            ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝{Colors.RESET}
    """
    print(banner)

def check_os():
    """Check if running on supported OS"""
    system = platform.system()
    if system == 'Linux':
        # Check for specific distributions
        if os.path.exists('/etc/debian_version'):
            return 'debian'
        elif os.path.exists('/etc/redhat-release'):
            return 'redhat'
        else:
            return 'linux'
    elif system == 'Darwin':
        return 'macos'
    else:
        return 'unsupported'

def check_command(command):
    """Check if a command is available"""
    return shutil.which(command) is not None

def run_command(cmd, description, require_sudo=False):
    """Run a command with nice output"""
    print(f"\n{Colors.CYAN}▶ {description}{Colors.RESET}")
    
    if require_sudo and os.geteuid() != 0:
        cmd = ['sudo'] + cmd
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"{Colors.GREEN}✓ {description} completed successfully{Colors.RESET}")
            return True, result.stdout
        else:
            print(f"{Colors.RED}✗ {description} failed{Colors.RESET}")
            if result.stderr:
                print(f"{Colors.YELLOW}  Error: {result.stderr}{Colors.RESET}")
            return False, result.stderr
    except Exception as e:
        print(f"{Colors.RED}✗ Error running command: {e}{Colors.RESET}")
        return False, str(e)

def install_system_packages(os_type):
    """Install system packages based on OS"""
    print(f"\n{Colors.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
    print(f"{Colors.YELLOW}  Installing System Dependencies{Colors.RESET}")
    print(f"{Colors.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
    
    packages_installed = []
    packages_failed = []
    
    if os_type == 'debian':
        # Update package list
        print(f"\n{Colors.BLUE}Updating package list...{Colors.RESET}")
        success, _ = run_command(['apt', 'update'], "Updating package list", require_sudo=True)
        
        # Define required packages
        packages = ['nmap', 'python3-pip', 'python3-venv', 'python3-dev']
        
        for package in packages:
            # Check if already installed
            check_cmd = ['dpkg', '-l', package]
            result = subprocess.run(check_cmd, capture_output=True, text=True)
            
            if result.returncode == 0 and 'ii' in result.stdout:
                print(f"{Colors.GREEN}✓ {package} is already installed{Colors.RESET}")
                packages_installed.append(package)
            else:
                # Install package
                success, _ = run_command(
                    ['apt', 'install', '-y', package],
                    f"Installing {package}",
                    require_sudo=True
                )
                if success:
                    packages_installed.append(package)
                else:
                    packages_failed.append(package)
    
    elif os_type == 'redhat':
        # For Red Hat based systems
        packages = ['nmap', 'python3-pip', 'python3-devel']
        
        for package in packages:
            success, _ = run_command(
                ['yum', 'install', '-y', package],
                f"Installing {package}",
                require_sudo=True
            )
            if success:
                packages_installed.append(package)
            else:
                packages_failed.append(package)
    
    elif os_type == 'macos':
        # Check for Homebrew
        if not check_command('brew'):
            print(f"{Colors.RED}✗ Homebrew is not installed!{Colors.RESET}")
            print(f"{Colors.YELLOW}Please install Homebrew first: https://brew.sh{Colors.RESET}")
            return False
        
        packages = ['nmap', 'python3']
        
        for package in packages:
            # Check if already installed
            check_result = subprocess.run(['brew', 'list', package], capture_output=True)
            
            if check_result.returncode == 0:
                print(f"{Colors.GREEN}✓ {package} is already installed{Colors.RESET}")
                packages_installed.append(package)
            else:
                success, _ = run_command(
                    ['brew', 'install', package],
                    f"Installing {package}"
                )
                if success:
                    packages_installed.append(package)
                else:
                    packages_failed.append(package)
    
    # Summary
    print(f"\n{Colors.CYAN}System packages summary:{Colors.RESET}")
    if packages_installed:
        print(f"{Colors.GREEN}✓ Installed/verified: {', '.join(packages_installed)}{Colors.RESET}")
    if packages_failed:
        print(f"{Colors.RED}✗ Failed: {', '.join(packages_failed)}{Colors.RESET}")
        return False
    
    return True

def setup_python_environment():
    """Set up Python virtual environment and install dependencies"""
    print(f"\n{Colors.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
    print(f"{Colors.YELLOW}  Setting Up Python Environment{Colors.RESET}")
    print(f"{Colors.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
    
    # Check if venv exists
    venv_path = Path('venv')
    
    if venv_path.exists():
        print(f"{Colors.GREEN}✓ Virtual environment already exists{Colors.RESET}")
    else:
        # Create virtual environment
        print(f"\n{Colors.BLUE}Creating virtual environment...{Colors.RESET}")
        success, _ = run_command(
            [sys.executable, '-m', 'venv', 'venv'],
            "Creating virtual environment"
        )
        if not success:
            return False
    
    # Determine pip path in venv
    if platform.system() == 'Windows':
        pip_path = venv_path / 'Scripts' / 'pip'
        python_path = venv_path / 'Scripts' / 'python'
    else:
        pip_path = venv_path / 'bin' / 'pip'
        python_path = venv_path / 'bin' / 'python'
    
    # Upgrade pip
    print(f"\n{Colors.BLUE}Upgrading pip...{Colors.RESET}")
    run_command(
        [str(python_path), '-m', 'pip', 'install', '--upgrade', 'pip'],
        "Upgrading pip"
    )
    
    # Install requirements
    requirements_file = Path('requirements.txt')
    
    if not requirements_file.exists():
        # Create requirements.txt if it doesn't exist
        print(f"\n{Colors.YELLOW}Creating requirements.txt...{Colors.RESET}")
        requirements_content = """# Network Scanner Dependencies
colorama>=0.4.6
python-nmap>=0.7.1
lxml>=4.9.0
jinja2>=3.1.0
pandas>=2.0.0
beautifulsoup4>=4.12.0
"""
        requirements_file.write_text(requirements_content)
        print(f"{Colors.GREEN}✓ Created requirements.txt{Colors.RESET}")
    
    print(f"\n{Colors.BLUE}Installing Python dependencies...{Colors.RESET}")
    success, output = run_command(
        [str(pip_path), 'install', '-r', 'requirements.txt'],
        "Installing Python packages"
    )
    
    if not success:
        print(f"{Colors.RED}Failed to install Python dependencies{Colors.RESET}")
        return False
    
    # Verify installation
    print(f"\n{Colors.BLUE}Verifying Python packages...{Colors.RESET}")
    required_packages = ['colorama', 'nmap', 'lxml', 'jinja2', 'pandas', 'bs4']
    
    all_installed = True
    for package in required_packages:
        try:
            result = subprocess.run(
                [str(python_path), '-c', f'import {package}'],
                capture_output=True
            )
            if result.returncode == 0:
                print(f"{Colors.GREEN}✓ {package} is installed{Colors.RESET}")
            else:
                print(f"{Colors.RED}✗ {package} is not installed{Colors.RESET}")
                all_installed = False
        except Exception:
            print(f"{Colors.RED}✗ {package} check failed{Colors.RESET}")
            all_installed = False
    
    return all_installed

def create_activation_script():
    """Create a convenience activation script"""
    print(f"\n{Colors.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
    print(f"{Colors.YELLOW}  Creating Convenience Scripts{Colors.RESET}")
    print(f"{Colors.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
    
    # Create run.sh for Unix-like systems
    if platform.system() != 'Windows':
        run_script = """#!/bin/bash
# Network Scanner Launch Script

# Colors
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m' # No Color

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${RED}Virtual environment not found!${NC}"
    echo -e "${YELLOW}Please run: python3 setup_dependencies.py${NC}"
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Run the pipeline
echo -e "${GREEN}Starting Network Scanner...${NC}"
python3 pipeline.py "$@"
"""
        
        run_path = Path('run.sh')
        run_path.write_text(run_script)
        run_path.chmod(0o755)
        print(f"{Colors.GREEN}✓ Created run.sh launcher script{Colors.RESET}")
    
    # Create run.bat for Windows
    else:
        run_script = """@echo off
REM Network Scanner Launch Script

REM Check if virtual environment exists
IF NOT EXIST "venv" (
    echo Virtual environment not found!
    echo Please run: python setup_dependencies.py
    exit /b 1
)

REM Activate virtual environment
call venv\\Scripts\\activate.bat

REM Run the pipeline
echo Starting Network Scanner...
python pipeline.py %*
"""
        
        run_path = Path('run.bat')
        run_path.write_text(run_script)
        print(f"{Colors.GREEN}✓ Created run.bat launcher script{Colors.RESET}")

def print_next_steps():
    """Print instructions for next steps"""
    print(f"\n{Colors.GREEN}{'=' * 70}{Colors.RESET}")
    print(f"{Colors.GREEN + Colors.BOLD}✅ Setup Complete!{Colors.RESET}")
    print(f"{Colors.GREEN}{'=' * 70}{Colors.RESET}")
    
    print(f"\n{Colors.CYAN}🎉 All dependencies have been installed successfully!{Colors.RESET}")
    
    print(f"\n{Colors.YELLOW}To use the Network Scanner:{Colors.RESET}")
    
    if platform.system() != 'Windows':
        print(f"\n  {Colors.WHITE}Option 1 - Using the launcher script (recommended):{Colors.RESET}")
        print(f"    {Colors.GREEN}./run.sh{Colors.RESET}")
        
        print(f"\n  {Colors.WHITE}Option 2 - Manual activation:{Colors.RESET}")
        print(f"    {Colors.GREEN}source venv/bin/activate{Colors.RESET}")
        print(f"    {Colors.GREEN}python3 pipeline.py{Colors.RESET}")
    else:
        print(f"\n  {Colors.WHITE}Option 1 - Using the launcher script (recommended):{Colors.RESET}")
        print(f"    {Colors.GREEN}run.bat{Colors.RESET}")
        
        print(f"\n  {Colors.WHITE}Option 2 - Manual activation:{Colors.RESET}")
        print(f"    {Colors.GREEN}venv\\Scripts\\activate.bat{Colors.RESET}")
        print(f"    {Colors.GREEN}python pipeline.py{Colors.RESET}")
    
    print(f"\n{Colors.MAGENTA}The scanner will automatically handle privilege escalation when needed!{Colors.RESET}")
    print(f"{Colors.MAGENTA}Just run it normally - it will prompt for your password if required.{Colors.RESET}")
    
    print(f"\n{Colors.CYAN}Example commands:{Colors.RESET}")
    print(f"  {Colors.WHITE}Interactive mode:{Colors.RESET} ./run.sh")
    print(f"  {Colors.WHITE}Quick scan:{Colors.RESET} ./run.sh 192.168.1.0/24 -t quick")
    print(f"  {Colors.WHITE}Stealth scan:{Colors.RESET} ./run.sh 10.0.0.1 -t stealth_scan")
    print(f"    {Colors.YELLOW}(Will automatically prompt for sudo password){Colors.RESET}")

def main():
    """Main setup function"""
    print_banner()
    
    # Check OS
    os_type = check_os()
    if os_type == 'unsupported':
        print(f"{Colors.RED}✗ Unsupported operating system!{Colors.RESET}")
        print(f"{Colors.YELLOW}This script supports Linux (Debian/Ubuntu/RedHat) and macOS.{Colors.RESET}")
        sys.exit(1)
    
    print(f"{Colors.CYAN}Detected OS: {os_type}{Colors.RESET}")
    
    # Check if running with appropriate privileges for system packages
    if os_type in ['debian', 'redhat'] and os.geteuid() != 0:
        print(f"\n{Colors.YELLOW}⚠️  System package installation requires administrator privileges.{Colors.RESET}")
        print(f"{Colors.WHITE}You can either:{Colors.RESET}")
        print(f"  1. Run this script with sudo: {Colors.GREEN}sudo python3 setup_dependencies.py{Colors.RESET}")
        print(f"  2. Continue without sudo (you'll be prompted for password when needed){Colors.RESET}")
        
        response = input(f"\n{Colors.CYAN}Continue without sudo? [Y/n] ▸ {Colors.RESET}").strip().lower()
        if response in ['n', 'no']:
            print(f"{Colors.YELLOW}Please run with: sudo python3 setup_dependencies.py{Colors.RESET}")
            sys.exit(0)
    
    # Install system packages
    if not install_system_packages(os_type):
        print(f"\n{Colors.RED}✗ Failed to install system packages!{Colors.RESET}")
        print(f"{Colors.YELLOW}Please install them manually and run this script again.{Colors.RESET}")
        sys.exit(1)
    
    # Set up Python environment
    if not setup_python_environment():
        print(f"\n{Colors.RED}✗ Failed to set up Python environment!{Colors.RESET}")
        sys.exit(1)
    
    # Create convenience scripts
    create_activation_script()
    
    # Print next steps
    print_next_steps()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Setup interrupted by user.{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}✗ Setup failed with error: {e}{Colors.RESET}")
        sys.exit(1)
