#!/usr/bin/env python3
"""
Hardware Inventory Scanner
Enriches discovered hosts with hardware details via SNMP, SSH, WMI, and certificates
"""

import ssl
import socket
import sys
import json
import yaml
import concurrent.futures
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
import ipaddress
import re

# Try to import optional dependencies
try:
    from pysnmp.hlapi import *
    SNMP_AVAILABLE = True
except ImportError:
    SNMP_AVAILABLE = False
    print("Warning: pysnmp not available. SNMP inventory disabled.")

try:
    import paramiko
    SSH_AVAILABLE = True
except ImportError:
    SSH_AVAILABLE = False
    print("Warning: paramiko not available. SSH inventory disabled.")

try:
    if sys.platform == "win32":
        import wmi
        WMI_AVAILABLE = True
    else:
        WMI_AVAILABLE = False
except ImportError:
    WMI_AVAILABLE = False
    if sys.platform == "win32":
        print("Warning: wmi not available. WMI inventory disabled.")

try:
    from mac_vendor_lookup import MacLookup
    MAC_LOOKUP_AVAILABLE = True
except ImportError:
    MAC_LOOKUP_AVAILABLE = False
    print("Warning: mac-vendor-lookup not available. MAC vendor lookup disabled.")

# Try to import colorama for colored output
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    class MockColor:
        def __getattr__(self, name):
            return ""
    Fore = Style = MockColor()

class HardwareInventory:
    """Orchestrates hardware inventory collection from multiple sources"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config = self._load_config(config_file)
        self.mac_lookup = MacLookup() if MAC_LOOKUP_AVAILABLE else None
        
        # Common SNMP OIDs
        self.snmp_oids = {
            'sysDescr': '1.3.6.1.2.1.1.1.0',
            'sysName': '1.3.6.1.2.1.1.5.0',
            'sysLocation': '1.3.6.1.2.1.1.6.0',
            'sysContact': '1.3.6.1.2.1.1.4.0',
            'sysUpTime': '1.3.6.1.2.1.1.3.0',
            # Hardware-specific OIDs
            'entPhysicalSerialNum': '1.3.6.1.2.1.47.1.1.1.1.11.1',
            'entPhysicalModelName': '1.3.6.1.2.1.47.1.1.1.1.13.1',
            'hrDeviceDescr': '1.3.6.1.2.1.25.3.2.1.3.1',
            # Printer OIDs
            'prtGeneralSerialNumber': '1.3.6.1.2.1.43.5.1.1.17.1',
            'prtGeneralModelName': '1.3.6.1.2.1.43.5.1.1.8.1',
            # Interface OIDs for MAC addresses
            'ifPhysAddress': '1.3.6.1.2.1.2.2.1.6'
        }
    
    def _load_config(self, config_file: Optional[str]) -> Dict:
        """Load configuration from file or use defaults"""
        default_config = {
            'snmp': {
                'community': 'public',
                'timeout': 5,
                'retries': 2
            },
            'ssh': {
                'username': 'admin',
                'password': None,
                'key_file': None,
                'timeout': 10
            },
            'wmi': {
                'username': None,
                'password': None,
                'domain': '.'
            },
            'ssl': {
                'timeout': 5
            },
            'max_workers': 10
        }
        
        if config_file and Path(config_file).exists():
            try:
                with open(config_file, 'r') as f:
                    loaded_config = yaml.safe_load(f)
                    # Merge with defaults
                    for key in default_config:
                        if key in loaded_config:
                            default_config[key].update(loaded_config[key])
                        else:
                            default_config[key] = loaded_config.get(key, default_config[key])
                    return default_config
            except Exception as e:
                print(f"{Fore.YELLOW}Warning: Could not load config file: {e}{Style.RESET_ALL}")
        
        return default_config
    
    def enrich_hosts(self, hosts: List[Dict], interactive: bool = True) -> List[Dict]:
        """
        Enrich a list of hosts with hardware inventory data
        
        Args:
            hosts: List of host dictionaries from nmap scan
            interactive: Whether to prompt for credentials
            
        Returns:
            Enriched host list
        """
        if interactive:
            self._prompt_for_credentials()
        
        print(f"\n{Fore.CYAN}🔍 Starting hardware inventory collection...{Style.RESET_ALL}")
        print(f"   Processing {len(hosts)} hosts with {self.config['max_workers']} workers")
        
        # Process hosts in parallel
        enriched_hosts = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['max_workers']) as executor:
            # Submit all jobs
            future_to_host = {
                executor.submit(self._enrich_single_host, host): host 
                for host in hosts
            }
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    enriched_host = future.result()
                    enriched_hosts.append(enriched_host)
                    
                    # Show progress
                    ip = host['addresses'].get('ipv4', 'unknown')
                    if enriched_host.get('hardware_info'):
                        print(f"{Fore.GREEN}✓{Style.RESET_ALL} {ip} - Inventory collected")
                    else:
                        print(f"{Fore.YELLOW}⚠{Style.RESET_ALL} {ip} - No inventory data")
                        
                except Exception as e:
                    print(f"{Fore.RED}✗{Style.RESET_ALL} {ip} - Error: {str(e)}")
                    enriched_hosts.append(host)
        
        print(f"\n{Fore.GREEN}✅ Hardware inventory complete{Style.RESET_ALL}")
        return enriched_hosts
    
    def _prompt_for_credentials(self):
        """Interactively prompt for missing credentials"""
        print(f"\n{Fore.BLUE}🔐 Credential Configuration{Style.RESET_ALL}")
        
        # SNMP Community
        if SNMP_AVAILABLE:
            current = self.config['snmp']['community']
            community = input(f"SNMP Community [{current}]: ").strip()
            if community:
                self.config['snmp']['community'] = community
        
        # SSH Credentials
        if SSH_AVAILABLE:
            print("\n📡 SSH Credentials (press Enter to skip)")
            username = input(f"SSH Username [{self.config['ssh']['username']}]: ").strip()
            if username:
                self.config['ssh']['username'] = username
            
            password = input("SSH Password (hidden): ").strip()
            if password:
                self.config['ssh']['password'] = password
        
        # WMI Credentials (Windows only)
        if WMI_AVAILABLE:
            print("\n💻 WMI Credentials (for Windows hosts)")
            username = input("WMI Username: ").strip()
            if username:
                self.config['wmi']['username'] = username
                password = input("WMI Password (hidden): ").strip()
                if password:
                    self.config['wmi']['password'] = password
    
    def _enrich_single_host(self, host: Dict) -> Dict:
        """Enrich a single host with hardware inventory"""
        ip = host['addresses'].get('ipv4', host['addresses'].get('ipv6', ''))
        if not ip:
            return host
        
        # Initialize hardware_info
        host['hardware_info'] = {}
        
        # 1. MAC Vendor Lookup
        if 'mac' in host['addresses'] and self.mac_lookup:
            try:
                mac = host['addresses']['mac']
                vendor = self.mac_lookup.lookup(mac)
                host['hardware_info']['mac_vendor'] = vendor
            except:
                pass
        
        # 2. SNMP Inventory
        if SNMP_AVAILABLE:
            snmp_data = self._collect_snmp_data(ip)
            if snmp_data:
                host['hardware_info'].update(snmp_data)
        
        # 3. Certificate Analysis
        cert_data = self._analyze_certificates(host)
        if cert_data:
            host['hardware_info']['certificates'] = cert_data
        
        # 4. SSH Inventory (if Linux/Unix detected)
        if SSH_AVAILABLE and self._is_ssh_candidate(host):
            ssh_data = self._collect_ssh_data(ip)
            if ssh_data:
                host['hardware_info'].update(ssh_data)
        
        # 5. WMI Inventory (if Windows detected)
        if WMI_AVAILABLE and self._is_windows_host(host):
            wmi_data = self._collect_wmi_data(ip)
            if wmi_data:
                host['hardware_info'].update(wmi_data)
        
        # 6. Extract firmware version from service banners
        firmware = self._extract_firmware_from_services(host)
        if firmware:
            host['hardware_info']['firmware'] = firmware
        
        return host
    
    def _collect_snmp_data(self, ip: str) -> Dict:
        """Collect hardware data via SNMP"""
        if not SNMP_AVAILABLE:
            return {}
        
        data = {}
        community = self.config['snmp']['community']
        timeout = self.config['snmp']['timeout']
        retries = self.config['snmp']['retries']
        
        # Try SNMP v2c
        for oid_name, oid in self.snmp_oids.items():
            try:
                iterator = getCmd(
                    SnmpEngine(),
                    CommunityData(community),
                    UdpTransportTarget((ip, 161), timeout=timeout, retries=retries),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid))
                )
                
                errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
                
                if not errorIndication and not errorStatus:
                    for varBind in varBinds:
                        value = str(varBind[1])
                        if value and value != 'No Such Object' and value != 'No Such Instance':
                            # Map OID names to inventory fields
                            if oid_name == 'sysDescr':
                                data['system_description'] = value
                            elif oid_name == 'entPhysicalSerialNum':
                                data['serial_number'] = value
                            elif oid_name == 'entPhysicalModelName':
                                data['model'] = value
                            elif oid_name == 'prtGeneralSerialNumber':
                                data['printer_serial'] = value
                            elif oid_name == 'prtGeneralModelName':
                                data['printer_model'] = value
                            elif oid_name == 'sysUpTime':
                                # Convert timeticks to readable format
                                ticks = int(value)
                                days = ticks // 8640000
                                hours = (ticks % 8640000) // 360000
                                data['uptime'] = f"{days}d {hours}h"
            except Exception:
                # SNMP timeout or error - continue with other OIDs
                continue
        
        # Try to extract model/vendor from sysDescr if not found
        if 'system_description' in data and 'model' not in data:
            model, vendor = self._parse_sysdescr(data['system_description'])
            if model:
                data['model'] = model
            if vendor:
                data['vendor'] = vendor
        
        return data
    
    def _parse_sysdescr(self, sysdescr: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract model and vendor from SNMP sysDescr"""
        sysdescr_lower = sysdescr.lower()
        
        # Common patterns
        patterns = {
            'cisco': [
                r'cisco\s+(\S+)\s+software',
                r'cisco\s+(\S+)\s+\(',
            ],
            'hp': [
                r'hp\s+(\S+)\s+switch',
                r'procurve\s+(\S+)',
            ],
            'dell': [
                r'dell\s+(\S+)',
                r'powerconnect\s+(\S+)',
            ],
            'juniper': [
                r'juniper.*model:\s*(\S+)',
            ]
        }
        
        vendor = None
        model = None
        
        for v, pats in patterns.items():
            if v in sysdescr_lower:
                vendor = v.upper()
                for pat in pats:
                    match = re.search(pat, sysdescr, re.IGNORECASE)
                    if match:
                        model = match.group(1)
                        break
                if model:
                    break
        
        return model, vendor
    
    def _analyze_certificates(self, host: Dict) -> List[Dict]:
        """Analyze SSL/TLS certificates from HTTPS services"""
        cert_data = []
        
        for port_info in host.get('ports', []):
            if port_info['state'] != 'open':
                continue
                
            port = port_info['port']
            # Check for HTTPS services
            if port in [443, 8443] or 'https' in port_info.get('service', {}).get('name', ''):
                cert_info = self._get_certificate_info(
                    host['addresses'].get('ipv4', ''), 
                    port
                )
                if cert_info:
                    cert_data.append(cert_info)
        
        return cert_data
    
    def _get_certificate_info(self, hostname: str, port: int) -> Optional[Dict]:
        """Retrieve SSL certificate information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=self.config['ssl']['timeout']) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert_bin()
                    x509 = ssl.DER_cert_to_PEM_cert(cert)
                    
                    # Parse certificate
                    cert_dict = ssock.getpeercert()
                    
                    if cert_dict:
                        # Extract relevant information
                        subject = dict(x[0] for x in cert_dict.get('subject', []))
                        issuer = dict(x[0] for x in cert_dict.get('issuer', []))
                        
                        # Parse dates
                        not_before = datetime.strptime(cert_dict['notBefore'], '%b %d %H:%M:%S %Y %Z')
                        not_after = datetime.strptime(cert_dict['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_remaining = (not_after - datetime.now()).days
                        
                        return {
                            'port': port,
                            'common_name': subject.get('commonName', ''),
                            'issuer': issuer.get('organizationName', issuer.get('commonName', '')),
                            'serial_number': cert_dict.get('serialNumber', ''),
                            'not_before': not_before.isoformat(),
                            'not_after': not_after.isoformat(),
                            'days_remaining': days_remaining,
                            'expired': days_remaining < 0,
                            'expiring_soon': 0 < days_remaining < 30,
                            'subject_alt_names': [x[1] for x in cert_dict.get('subjectAltName', [])]
                        }
        except Exception:
            return None
        
        return None
    
    def _collect_ssh_data(self, ip: str) -> Dict:
        """Collect hardware data via SSH"""
        if not SSH_AVAILABLE or not self.config['ssh']['password']:
            return {}
        
        data = {}
        
        try:
            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect
            ssh.connect(
                ip,
                username=self.config['ssh']['username'],
                password=self.config['ssh']['password'],
                timeout=self.config['ssh']['timeout']
            )
            
            # Commands to run
            commands = {
                'uname': 'uname -a',
                'lsb_release': 'lsb_release -a 2>/dev/null',
                'dmidecode_system': 'sudo dmidecode -t system 2>/dev/null | grep -E "Manufacturer|Product Name|Serial Number"',
                'dmidecode_bios': 'sudo dmidecode -t bios 2>/dev/null | grep -E "Vendor|Version|Release Date"',
                'hostnamectl': 'hostnamectl 2>/dev/null',
                'cpu_info': 'cat /proc/cpuinfo | grep -E "model name|cpu cores" | head -2',
                'mem_info': 'free -h | grep Mem'
            }
            
            for cmd_name, command in commands.items():
                try:
                    stdin, stdout, stderr = ssh.exec_command(command, timeout=5)
                    output = stdout.read().decode().strip()
                    
                    if output:
                        if cmd_name == 'dmidecode_system':
                            # Parse dmidecode output
                            for line in output.split('\n'):
                                if 'Manufacturer:' in line:
                                    data['manufacturer'] = line.split(':', 1)[1].strip()
                                elif 'Product Name:' in line:
                                    data['model'] = line.split(':', 1)[1].strip()
                                elif 'Serial Number:' in line:
                                    data['serial_number'] = line.split(':', 1)[1].strip()
                        
                        elif cmd_name == 'dmidecode_bios':
                            for line in output.split('\n'):
                                if 'Version:' in line:
                                    data['bios_version'] = line.split(':', 1)[1].strip()
                                elif 'Release Date:' in line:
                                    data['bios_date'] = line.split(':', 1)[1].strip()
                        
                        elif cmd_name == 'hostnamectl':
                            for line in output.split('\n'):
                                if 'Operating System:' in line:
                                    data['os_details'] = line.split(':', 1)[1].strip()
                                elif 'Kernel:' in line:
                                    data['kernel'] = line.split(':', 1)[1].strip()
                        
                        elif cmd_name == 'cpu_info':
                            lines = output.split('\n')
                            for line in lines:
                                if 'model name' in line:
                                    data['cpu_model'] = line.split(':', 1)[1].strip()
                                elif 'cpu cores' in line:
                                    data['cpu_cores'] = line.split(':', 1)[1].strip()
                        
                        elif cmd_name == 'mem_info':
                            parts = output.split()
                            if len(parts) > 1:
                                data['memory_total'] = parts[1]
                        
                        else:
                            data[cmd_name] = output
                            
                except Exception:
                    continue
            
            ssh.close()
            
        except Exception as e:
            # SSH connection failed
            pass
        
        return data
    
    def _collect_wmi_data(self, ip: str) -> Dict:
        """Collect hardware data via WMI (Windows)"""
        if not WMI_AVAILABLE or not self.config['wmi']['username']:
            return {}
        
        data = {}
        
        try:
            # Connect to remote WMI
            connection = wmi.WMI(
                computer=ip,
                user=self.config['wmi']['username'],
                password=self.config['wmi']['password']
            )
            
            # Get computer system info
            for computer in connection.Win32_ComputerSystem():
                data['manufacturer'] = computer.Manufacturer
                data['model'] = computer.Model
                data['total_memory'] = f"{int(computer.TotalPhysicalMemory) // (1024**3)}GB"
            
            # Get BIOS info
            for bios in connection.Win32_BIOS():
                data['serial_number'] = bios.SerialNumber
                data['bios_version'] = bios.Version
                data['bios_manufacturer'] = bios.Manufacturer
            
            # Get OS info
            for os in connection.Win32_OperatingSystem():
                data['os_details'] = f"{os.Caption} {os.Version}"
                data['os_architecture'] = os.OSArchitecture
                data['install_date'] = os.InstallDate
            
            # Get processor info
            for cpu in connection.Win32_Processor():
                data['cpu_model'] = cpu.Name
                data['cpu_cores'] = cpu.NumberOfCores
                data['cpu_threads'] = cpu.NumberOfLogicalProcessors
                break  # Just get first CPU
                
        except Exception:
            # WMI connection failed
            pass
        
        return data
    
    def _is_ssh_candidate(self, host: Dict) -> bool:
        """Check if host is a candidate for SSH inventory"""
        # Check if SSH port is open
        for port in host.get('ports', []):
            if port['state'] == 'open' and port['port'] == 22:
                return True
        return False
    
    def _is_windows_host(self, host: Dict) -> bool:
        """Check if host appears to be Windows"""
        # Check OS detection
        os_info = host.get('os', {})
        if os_info.get('matches'):
            os_name = os_info['matches'][0].get('name', '').lower()
            if 'windows' in os_name:
                return True
        
        # Check for Windows-specific ports
        windows_ports = {135, 139, 445, 3389}
        open_ports = {p['port'] for p in host.get('ports', []) if p['state'] == 'open'}
        
        return bool(windows_ports & open_ports)
    
    def _extract_firmware_from_services(self, host: Dict) -> Optional[str]:
        """Extract firmware version from service banners"""
        for port in host.get('ports', []):
            if port['state'] != 'open':
                continue
                
            service = port.get('service', {})
            # Look for firmware patterns in version/extrainfo
            version = service.get('version', '')
            extrainfo = service.get('extrainfo', '')
            product = service.get('product', '')
            
            # Common firmware patterns
            patterns = [
                r'firmware[:\s]+v?([\d\.]+)',
                r'fw[:\s]+v?([\d\.]+)',
                r'version[:\s]+v?([\d\.]+)',
                r'v([\d\.]+\s+build\s+\d+)'
            ]
            
            combined = f"{version} {extrainfo} {product}".lower()
            
            for pattern in patterns:
                match = re.search(pattern, combined, re.IGNORECASE)
                if match:
                    return match.group(1)
        
        return None

def main():
    """Test the hardware inventory scanner"""
    # Example host data
    test_hosts = [
        {
            'addresses': {
                'ipv4': '192.168.1.1',
                'mac': '00:11:22:33:44:55'
            },
            'os': {
                'matches': [
                    {'name': 'Linux 3.2 - 4.9', 'accuracy': 95}
                ]
            },
            'ports': [
                {
                    'port': 22,
                    'state': 'open',
                    'service': {'name': 'ssh'}
                },
                {
                    'port': 443,
                    'state': 'open',
                    'service': {'name': 'https'}
                }
            ]
        }
    ]
    
    inventory = HardwareInventory()
    enriched = inventory.enrich_hosts(test_hosts, interactive=False)
    
    print(json.dumps(enriched, indent=2))

if __name__ == "__main__":
    main()
